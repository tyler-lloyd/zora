module github.com/tyler-lloyd/zora

go 1.26.0

require (
	github.com/containernetworking/cni v1.3.1
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
)

require (
	github.com/alexflint/go-filemutex v1.3.0 // indirect
	github.com/containernetworking/plugins v1.9.1 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/networkplumbing/go-nft v0.4.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/safchain/ethtool v0.6.2 // indirect
	go.opentelemetry.io/otel v1.29.0 // indirect
	go.opentelemetry.io/otel/trace v1.29.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	sigs.k8s.io/knftables v0.0.18 // indirect
)

tool (
	github.com/containernetworking/plugins/plugins/ipam/host-local
	github.com/containernetworking/plugins/plugins/main/bridge
	github.com/containernetworking/plugins/plugins/main/loopback
	github.com/containernetworking/plugins/plugins/main/ptp
)
