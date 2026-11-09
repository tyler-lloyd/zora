package cniplugin

import (
	"os"
	"time"

	"github.com/containernetworking/cni/pkg/skel"

	"github.com/tyler-lloyd/zora/pkg/agentapi"
	"github.com/tyler-lloyd/zora/pkg/netapply"
	"github.com/tyler-lloyd/zora/pkg/plan"
)

// Version is set at build time with -ldflags "-X ...cniplugin.Version=...".
var Version = "dev"

// kernel is the real Netlink implementation.
type kernel struct{}

func (kernel) Apply(ns string, p *plan.Plan, o netapply.Options) error {
	return netapply.Apply(ns, p, o)
}
func (kernel) Remove(ns string, p *plan.Plan, o netapply.Options) error {
	return netapply.Remove(ns, p, o)
}
func (kernel) Verify(ns string, p *plan.Plan) error   { return netapply.Verify(ns, p) }
func (kernel) UplinkMTU(ns, name string) (int, error) { return netapply.UplinkMTU(ns, name) }
func (kernel) DeleteHostOrphans(o netapply.Options, keep func(string) bool) ([]string, error) {
	return netapply.DeleteHostOrphans(o, keep)
}

// New returns the plugin wired to the real agent client and kernel.
func New() *Plugin {
	return &Plugin{
		NewAgent: func(socket string, timeout time.Duration) Agent { return agentapi.NewClient(socket, timeout) },
		Net:      kernel{},
		Log:      os.Stderr,
	}
}

// Main is the zora-cni binary's main function.
func Main() {
	skel.PluginMainFuncs(New().Funcs(), SupportedVersions, "zora WireGuard CNI plugin "+Version)
}
