# zora

zora gives a Kubernetes pod its own WireGuard tunnel.

You put a WireGuard config in a Secret, point a pod at it with an annotation,
and the pod starts with a `wg0` interface already up. No sidecar, no
privileged container, no changes to your image.

zora is a *secondary* CNI plugin. It runs alongside whatever CNI your cluster
already uses (flannel, Cilium, kindnet, Calico) and leaves pods that don't ask
for a tunnel completely alone.

> **Status: early.** The core is built and well tested, but there is no
> container image or Helm chart yet, so you can't install it on a cluster
> today. That is the next piece of work.

## What it looks like

Store a normal wg-quick config in a Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-vpn
stringData:
  wg0.conf: |
    [Interface]
    PrivateKey = <your private key>
    Address = 10.64.0.2/32

    [Peer]
    PublicKey = <the peer's public key>
    AllowedIPs = 0.0.0.0/0
    Endpoint = vpn.example.com:51820
```

Then annotate the pod with the Secret's name:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  annotations:
    zora.io/wireguard-secret: my-vpn
spec:
  containers:
    - name: app
      image: my-app:latest
```

The Secret has to be in the same namespace as the pod.

## What to expect

**Cluster traffic stays out of the tunnel.** Even with `AllowedIPs = 0.0.0.0/0`,
traffic to other pods, to Services (including cluster DNS) and to the node
keeps using the pod's normal interface. Everything else goes through WireGuard.

**If the tunnel goes away, traffic stops.** zora installs a kill switch, so
traffic meant for the tunnel is dropped rather than quietly leaving through
the pod's normal interface.

**If something is wrong, the pod doesn't start.** A missing Secret or a typo in
the config keeps the pod in `ContainerCreating`, and `kubectl describe pod`
shows an event saying what to fix. A pod that asked for a tunnel never runs
without one.

**The config is applied when the pod starts.** To pick up a changed Secret,
restart the pod.

A few wg-quick features are deliberately not supported:

- `PreUp`, `PostUp`, `PreDown` and `PostDown` are rejected. They would run
  commands as root on the node.
- `DNS =` is ignored. Use the pod's `dnsConfig` instead.
- `Table =` only accepts `auto` and `off`.

## Annotations

| Annotation | What it does | Default |
| --- | --- | --- |
| `zora.io/wireguard-secret` | Name of the Secret. This is what opts a pod in. | |
| `zora.io/wireguard-key` | Which key in the Secret holds the config. | `wg0.conf` |
| `zora.io/wireguard-ifname` | Name of the interface inside the pod. | `wg0` |
| `zora.io/wireguard-mode` | Set to `host` to send encrypted traffic from the node instead of the pod. See below. | `pod` |

Once the tunnel is set up, zora marks the pod with a
`zora.io/wireguard-ready` condition. Add it to the pod's `readinessGates` if
you want the pod kept out of Services until then.

### Host mode

By default the encrypted WireGuard packets leave through the pod's normal
interface, so your NetworkPolicies still apply to them.

In host mode they leave from the node instead. That skips NetworkPolicy, so a
pod can't turn it on by itself: a cluster admin has to allow the namespace
first.

## How it works

There are two parts:

- **`zora-cni`** is a small CNI plugin. The container runtime calls it for
  each new pod, after the cluster's main CNI has finished. It sets up the
  interface, routes and kill switch inside the pod.
- **`zora-agent`** runs on every node. It installs the plugin, adds it to the
  node's existing CNI config (and puts it back if the main CNI rewrites that
  file), and reads Secrets on the plugin's behalf.

If the agent is down, annotated pods wait until it's back. Pods in
`kube-system` never depend on it.

## Development

You need Go and, for the network tests, Linux with the WireGuard kernel module
loaded (`sudo modprobe wireguard`).

```sh
make test   # everything; needs no root
make lint
make fuzz
```

The network tests create real WireGuard tunnels, but inside throwaway
namespaces, so they don't touch your machine's network.

[CONTRIBUTING.md](CONTRIBUTING.md) explains how the tests are organised and
how to add a case, which is often just dropping in a file.

## License

zora is licensed under the [Apache License 2.0](LICENSE).
