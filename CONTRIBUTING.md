# Contributing to zora

zora runs as root on every node and sits in the pod-creation path of
someone else's CNI, so we hold changes to a high bar of evidence. **Every
behaviour change ships with a test at the lowest tier that can observe it**,
and every bug fix ships with a regression test that fails without the fix.

## Test tiers

| Tier | Command | Needs | Covers |
|---|---|---|---|
| 0 | `make lint` | Go | gofmt, `go vet`, `go mod tidy`, golangci-lint if installed |
| 1 | `make test` | Go | unit, golden-file and property tests (with `-race`) |
| 2 | `make fuzz` | Go | parser contracts on arbitrary input |
| 3 | `make test-netns` | Linux + `wireguard` module + unprivileged user namespaces (or root) | plans applied to real network namespaces, real tunnel traffic |
| 4 | `make test-integration` | as tier 3 | the real `zora-cni` binary, run by `libcni` after the reference `bridge`/`ptp` + `host-local` plugins |
| 5 | `make e2e-smoke` | Docker, kind, kubectl, helm | the image and Helm chart in a kind cluster: install, a pod gets its interface, a plain pod doesn't, a bad annotation is explained, restart, uninstall |

Tiers 0-2 need no root and no cluster, and they cover most of the logic: the
packages that make decisions (`wgconfig`, `plan`) are pure functions on
purpose.

Tier 3 needs no sudo either on most distributions: `internal/testns`
re-executes the test binary inside a fresh user + network namespace, so the
tests can never touch your machine's real network. `make test` runs tier 3
when it can and skips it with a reason when it can't; `make test-netns` (and
CI) set `ZORA_REQUIRE_NETNS=1`, which turns those skips into failures. You
need the module loaded (`sudo modprobe wireguard`). On Ubuntu 23.10+, AppArmor
blocks unprivileged user namespaces: run
`sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`, or run the
tests as root.

## Adding test cases without writing Go

- **A WireGuard config the parser should accept:** add
  `pkg/wgconfig/testdata/valid/<name>.conf` and run `make update-golden`.
  Review the generated `.json`. Valid fixtures are also round-tripped and seed
  the fuzzer.
- **A config the parser should reject:** add
  `pkg/wgconfig/testdata/invalid/<name>.conf` and run `make update-golden`.
  Check that the `.err` file says what a user needs to fix.
- **A routing scenario:** add `pkg/plan/testdata/<name>/wg.conf` and
  `input.json` (cluster CIDRs, mode, MTU, ...) and run `make update-golden`.
  Every golden plan is also checked against the routing properties below.

- **Another primary CNI's config:** add it to
  `pkg/install/testdata/primaries/` and run `make update-golden`. Every
  fixture is chained, compared with `testdata/chained/`, checked against the
  installer's contract (below) and seeds `FuzzChain`.

Golden files are part of the review: a diff in `plan.json` *is* the change in
kernel state your PR causes.

## Invariants the tests enforce

`pkg/wgconfig`
- Errors never contain key material, even when a key is pasted into the
  wrong field (checked by a fixed list of cases and by the fuzzer).
- `SecretKey` redacts itself in fmt, slog and JSON. `Base64()` is the only
  way to reveal a key, so every disclosure is explicit and greppable.
- `Parse(Encode(c)) == c`, and `Encode` is a fixed point.
- Hook directives (`PreUp`, `PostUp`, ...) and `SaveConfig` are always rejected.

`pkg/resolver`, `pkg/repair`, `pkg/agent` (the agent; tested against
client-go's fake API server, and `pkg/agent` against real temp directories and
a real socket)
- Unannotated pods are skipped without reading any Secret.
- A sandbox is matched to its pod by UID: a stale cache entry or a replaced
  pod is never answered for.
- Every config error reaches the runtime and a pod Event, with the Secret's
  name and line number and never key material.
- Host mode is refused, not downgraded, outside the admin's namespace list.
- Repair never deletes a pod unless zora is installed, the pod is past its
  grace period, a controller owns it, and no successful ADD was reported.
- A restart leaves the plugin installed; only deleting the DaemonSet
  uninstalls, config first and binary second.

`test/integration` also runs the real plugin against the real resolver (a
Pod and Secret in a fake API server), so the annotation-to-tunnel path is
covered without a cluster.

`pkg/install` (the CNI config installer)
- zora never writes a config of its own, and never edits a primary config the
  runtime would reject (mid-write, or invalid).
- It edits only the runtime's file (lexically first), follows a new primary
  (e.g. Cilium taking over) and removes itself from configs no longer read.
- Chaining preserves every plugin, its position, unknown fields and key order;
  zora updates its entry in place rather than fighting other chained plugins
  for the last slot; chaining is idempotent and steady state writes nothing;
  uninstall restores the original.
- Converting a single `.conf` writes the `.conflist` before removing the
  `.conf`, so the runtime never sees a gap.

`pkg/plan` (`sim_test.go` models Linux policy routing and checks these on
every golden case and on 5000 random configs):
1. Cluster carve-outs (pod/service CIDRs, node IPs) always leave via the uplink.
2. In pod mode, WireGuard's own encrypted packets never loop into the tunnel.
3. AllowedIPs destinations outside the carve-outs enter the tunnel.
4. Kill switch: with the WireGuard link gone, tunnel traffic is dropped, never
   leaked out of the uplink.
5. Destinations the config doesn't claim are left alone.
6. Specific routes the primary CNI installed (link-local, gateways) win.
7. In pod mode, replies to the WireGuard socket pass strict IPv4 rp_filter.

These properties are proven on a model (`internal/routesim`).
`pkg/netapply`'s `TestKernelAgreesWithModel` applies every golden plan to a
real namespace and checks the kernel's routing decisions (`ip route get`)
match the model's, so the properties hold in the kernel too.

`pkg/netapply` (tier 3) additionally checks, with real traffic:
- tunnelled traffic arrives from the tunnel address; Service and node-probe
  traffic does not; the kill switch drops traffic when the link is deleted,
  even though a plaintext path exists; for pod and host mode, and for each
  `rp_filter` mode a node might impose (0, 1, 2);
- Apply rolls back completely when any step fails, is retry-safe, and never
  touches an interface it didn't create; Remove restores the namespace
  exactly; Verify detects each kind of drift.

`test/integration` (tier 4) runs the real binary the way a container runtime
does, across CNI 0.4.0, 1.0.0 and 1.1.0, with a fake agent on a unix socket:
ADD/CHECK/DEL (twice) with real traffic through the tunnel; unannotated pods
untouched; ADD failing closed with the agent down while DEL still succeeds and
the primary's IP is released; excluded namespaces and runtime-supplied pod
annotations working without the agent; a failed apply leaving nothing
behind; host mode; GC of orphaned host-side links; STATUS. The reference
plugins are pinned as Go `tool` dependencies in `go.mod` and built by the
test.

When a tier-3 assertion fails, the message includes `ip`/`wg` dumps of the
namespace (if those tools are installed).

If you change routing, make sure each of these still bites. Break the
behaviour on purpose, confirm a property test fails, then restore it.
