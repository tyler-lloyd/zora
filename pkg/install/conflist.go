// Package install chains zora into the node's existing CNI configuration and
// keeps it there.
//
// zora is a guest in another CNI's config file, so the rules are strict:
//
//   - Never write a config of our own. If we did, the runtime could pick it
//     as the primary. With no primary config yet we wait: the node is
//     NotReady until the primary CNI writes one, so only hostNetwork pods
//     (zora's agent among them) run in the meantime.
//   - Edit only the file the runtime will use: the lexically first *.conf,
//     *.conflist or *.json in the directory, as containerd's go-cni and
//     libcni select it. If that file doesn't parse, touch nothing and wait;
//     containerd refuses to use it too.
//   - Preserve everything else: unknown fields, key order, every other
//     plugin and its position. zora appends itself when absent and otherwise
//     updates its entry where it is, so it never fights another chained
//     plugin (Istio's CNI, say) for the last slot.
//   - Write atomically (temp file, then rename), with a temp name the
//     runtime ignores.
//   - Re-apply on every change: primary CNIs rewrite their config (Cilium
//     on every agent start), and Cilium's exclusive mode renames others'.
//
// The decisions here are pure functions over file names and bytes, tested
// against fixtures shaped after real CNIs' configs; Reconciler applies them
// through a small FS interface.
package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containernetworking/cni/libcni"
)

// PluginType is zora's "type" in a conflist (its binary's name).
const PluginType = "zora"

// tempPrefix and tempSuffix name our in-flight writes. The suffix is not a
// CNI config extension, so runtimes never read a half-written file.
const (
	tempPrefix = ".zora-"
	tempSuffix = ".tmp"
)

// IsConfigFile reports whether the runtime would consider name.
func IsConfigFile(name string) bool {
	switch filepath.Ext(name) {
	case ".conf", ".conflist", ".json":
		return true
	}
	return false
}

// Primary returns the config file the runtime uses: the lexically first
// config file.
func Primary(names []string) (string, bool) {
	var cfgs []string
	for _, n := range names {
		if IsConfigFile(n) {
			cfgs = append(cfgs, n)
		}
	}
	if len(cfgs) == 0 {
		return "", false
	}
	slices.Sort(cfgs)
	return cfgs[0], true
}

// InvalidConfigError means a config file would be rejected by the runtime.
type InvalidConfigError struct {
	Name string
	Err  error
}

func (e *InvalidConfigError) Error() string { return fmt.Sprintf("%s: %v", e.Name, e.Err) }
func (e *InvalidConfigError) Unwrap() error { return e.Err }

// Chain returns the config file content with entry chained in, and the name
// it must be written under. A single-plugin .conf/.json is converted into a
// .conflist of the same base name (the caller writes it, then removes the
// original). The output is canonically indented, so Chain is idempotent:
// chaining its own output returns identical bytes.
func Chain(name string, data, entry []byte) (string, []byte, error) {
	if err := checkEntry(entry); err != nil {
		return "", nil, err
	}
	if filepath.Ext(name) != ".conflist" {
		return chainSingle(name, data, entry)
	}
	if _, err := libcni.ConfListFromBytes(data); err != nil {
		return "", nil, &InvalidConfigError{name, err}
	}
	obj, err := parseObject(data)
	if err != nil {
		return "", nil, &InvalidConfigError{name, err}
	}
	plugins, err := pluginsOf(obj)
	if err != nil {
		return "", nil, &InvalidConfigError{name, err}
	}
	if isZora(plugins[0]) {
		return "", nil, &InvalidConfigError{name, errors.New("zora is the first plugin, so there is no primary to chain after")}
	}
	var out []json.RawMessage
	placed := false
	for _, p := range plugins {
		switch {
		case !isZora(p):
			out = append(out, p)
		case !placed: // update in place: keep our position
			out = append(out, entry)
			placed = true
		}
		// further zora entries are duplicates: drop them
	}
	if !placed {
		out = append(out, entry)
	}
	if err := obj.setPlugins(out); err != nil {
		return "", nil, err
	}
	b, err := format(obj)
	return name, b, err
}

func chainSingle(name string, data, entry []byte) (string, []byte, error) {
	conf, err := libcni.NetworkPluginConfFromBytes(data)
	if err != nil {
		return "", nil, &InvalidConfigError{name, err}
	}
	if conf.Network.Type == "" {
		return "", nil, &InvalidConfigError{name, errors.New(`missing "type"`)}
	}
	if conf.Network.Type == PluginType {
		return "", nil, &InvalidConfigError{name, errors.New("the only plugin is zora, so there is no primary to chain after")}
	}
	orig, err := parseObject(data)
	if err != nil {
		return "", nil, &InvalidConfigError{name, err}
	}
	// libcni's ConfListFromConf builds the same list: version and name
	// from the plugin, which stays intact as the first element.
	list := object{}
	for _, k := range []string{"cniVersion", "name"} {
		if v, ok := orig.get(k); ok {
			list = append(list, member{k, v})
		}
	}
	if err := list.setPlugins([]json.RawMessage{data, entry}); err != nil {
		return "", nil, err
	}
	b, err := format(list)
	return strings.TrimSuffix(name, filepath.Ext(name)) + ".conflist", b, err
}

// Unchain removes zora's entries from a conflist. Other files are returned
// unchanged. changed reports whether anything was removed.
func Unchain(name string, data []byte) ([]byte, bool, error) {
	if filepath.Ext(name) != ".conflist" {
		return data, false, nil
	}
	obj, err := parseObject(data)
	if err != nil {
		return nil, false, &InvalidConfigError{name, err}
	}
	plugins, err := pluginsOf(obj)
	if err != nil {
		return nil, false, &InvalidConfigError{name, err}
	}
	kept := slices.DeleteFunc(slices.Clone(plugins), isZora)
	if len(kept) == len(plugins) {
		return data, false, nil
	}
	if err := obj.setPlugins(kept); err != nil {
		return nil, false, err
	}
	b, err := format(obj)
	return b, true, err
}

// HasEntry reports whether a config file chains zora.
func HasEntry(name string, data []byte) bool {
	if filepath.Ext(name) != ".conflist" {
		return false
	}
	obj, err := parseObject(data)
	if err != nil {
		return false
	}
	plugins, err := pluginsOf(obj)
	return err == nil && slices.ContainsFunc(plugins, isZora)
}

func checkEntry(entry []byte) error {
	var e struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(entry, &e); err != nil {
		return fmt.Errorf("zora entry: %w", err)
	}
	if e.Type != PluginType {
		return fmt.Errorf("zora entry has type %q, want %q", e.Type, PluginType)
	}
	return nil
}

func isZora(plugin json.RawMessage) bool {
	var p struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(plugin, &p) == nil && p.Type == PluginType
}

func pluginsOf(obj object) ([]json.RawMessage, error) {
	raw, ok := obj.get("plugins")
	if !ok {
		return nil, errors.New(`missing "plugins"`)
	}
	var plugins []json.RawMessage
	if err := json.Unmarshal(raw, &plugins); err != nil {
		return nil, fmt.Errorf(`"plugins": %w`, err)
	}
	if len(plugins) == 0 {
		return nil, errors.New(`"plugins" is empty`)
	}
	return plugins, nil
}

func (o *object) setPlugins(plugins []json.RawMessage) error {
	b, err := json.Marshal(plugins)
	if err != nil {
		return err
	}
	o.set("plugins", b)
	return nil
}

func format(o object) ([]byte, error) {
	compact, err := o.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := json.Indent(&b, compact, "", "  "); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}
