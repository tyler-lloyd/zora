package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// object is a JSON object that keeps its keys in order, so rewriting a
// primary CNI's config doesn't reshuffle it. Values stay raw: we never
// reinterpret fields we don't own.
type object []member

type member struct {
	Key   string
	Value json.RawMessage
}

func parseObject(data []byte) (object, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	var o object
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected token %v", tok)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		o = append(o, member{key, v})
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON object")
	}
	return o, nil
}

// get returns the last value for key, as encoding/json would use.
func (o object) get(key string) (json.RawMessage, bool) {
	for i := len(o) - 1; i >= 0; i-- {
		if o[i].Key == key {
			return o[i].Value, true
		}
	}
	return nil, false
}

// set replaces the last value for key, or appends it.
func (o *object) set(key string, v json.RawMessage) {
	for i := len(*o) - 1; i >= 0; i-- {
		if (*o)[i].Key == key {
			(*o)[i].Value = v
			return
		}
	}
	*o = append(*o, member{key, v})
}

func (o object) keys() []string {
	k := make([]string, len(o))
	for i, m := range o {
		k[i] = m.Key
	}
	return k
}

func (o object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(m.Key)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		if err := json.Compact(&b, m.Value); err != nil {
			return nil, err
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
