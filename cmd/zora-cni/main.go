// Command zora-cni is the zora CNI plugin binary, installed into the CNI bin
// directory by zora-agent and exec'd by the container runtime.
package main

import "github.com/tyler-lloyd/zora/pkg/cniplugin"

func main() { cniplugin.Main() }
