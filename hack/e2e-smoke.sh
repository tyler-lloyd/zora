#!/usr/bin/env bash
# Installs the chart into a kind cluster and checks the basics end to end:
# the agent chains in, an annotated pod gets a WireGuard interface, a plain
# pod doesn't, a bad annotation is explained, and uninstalling restores the
# node. The tunnel has no live peer; traffic through tunnels is covered by
# the netns and integration tests.
#
# Needs docker, kind, kubectl and helm, and the wireguard kernel module.
set -euo pipefail

CLUSTER=${CLUSTER:-zora-e2e}
IMAGE=${IMAGE:-zora:e2e}
NODE=$CLUSTER-control-plane
cd "$(dirname "$0")/.."

step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

diagnose() {
  set +e
  step "diagnostics"
  kubectl get pods -A -o wide
  kubectl -n zora-system describe pods | tail -40
  kubectl -n zora-system logs -l app.kubernetes.io/component=agent --tail=50
  kubectl get events -A --sort-by=.lastTimestamp | tail -30
  docker exec "$NODE" sh -c 'ls -la /etc/cni/net.d /opt/cni/bin; cat /etc/cni/net.d/*.conflist'
}
trap 'diagnose' ERR

step "cluster"
kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 120s
kubectl config use-context "kind-$CLUSTER" >/dev/null
docker exec "$NODE" sh -c 'cat /etc/cni/net.d/*.conflist' > /tmp/zora-e2e-conflist.before

step "image"
docker build -q -t "$IMAGE" .
kind load docker-image --name "$CLUSTER" "$IMAGE"

step "install"
helm upgrade --install zora deploy/helm/zora -n zora-system --create-namespace \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE#*:}" --set image.pullPolicy=Never \
  --set 'cluster.podCIDRs={10.244.0.0/16}' --set 'cluster.serviceCIDRs={10.96.0.0/16}' \
  --set 'secrets.namespaces={default}' --wait --timeout 180s
kubectl -n zora-system rollout status ds/zora-agent --timeout=120s
docker exec "$NODE" sh -c 'grep -q "\"zora\"" /etc/cni/net.d/*.conflist && test -x /opt/cni/bin/zora' \
  || fail "zora is not chained into the node's CNI config"

step "pods"
# Any 32 random bytes are a valid WireGuard key.
kubectl create secret generic wg --dry-run=client -o yaml --from-literal=wg0.conf="[Interface]
PrivateKey = $(openssl rand -base64 32)
Address = 10.99.0.2/32

[Peer]
PublicKey = $(openssl rand -base64 32)
AllowedIPs = 10.99.0.0/24
Endpoint = 192.0.2.1:51820
" | kubectl apply -f -
pod() { # name, annotation value (may be empty)
  local ann="{}"
  if [ -n "$2" ]; then ann="{\"zora.io/wireguard-secret\":\"$2\"}"; fi
  kubectl run "$1" --image=busybox:1.36 --restart=Never \
    --overrides="{\"metadata\":{\"annotations\":$ann}}" -- sleep 3600
}
pod vpn wg; pod plain ""; pod typo no-such-secret
kubectl wait --for=condition=Ready pod/vpn pod/plain --timeout=120s

step "the annotated pod has its tunnel"
kubectl exec vpn -- ip addr show wg0 | grep -q 10.99.0.2 || fail "vpn pod has no wg0 with its address"
kubectl exec vpn -- ip route get 10.99.0.7 | grep -q 'dev wg0' || fail "tunnel traffic is not routed to wg0"
kubectl exec vpn -- ip route get 10.96.0.1 | grep -q 'dev eth0' || fail "Service traffic is not kept on eth0"
kubectl exec vpn -- nslookup kubernetes.default.svc.cluster.local >/dev/null || fail "cluster DNS fails in the vpn pod"
[ "$(kubectl get pod vpn -o jsonpath='{.status.conditions[?(@.type=="zora.io/wireguard-ready")].status}')" = True ] \
  || fail "the zora.io/wireguard-ready condition is not True"

step "the plain pod is untouched"
kubectl exec plain -- ip link show wg0 >/dev/null 2>&1 && fail "plain pod has a wg0"
[ "$(kubectl exec plain -- ip rule | wc -l)" = 3 ] || fail "plain pod has extra routing rules"

step "a bad annotation is explained and blocks the pod"
for _ in $(seq 30); do
  kubectl get events --field-selector involvedObject.name=typo,reason=WireGuardConfigError -o jsonpath='{.items[*].message}' \
    | grep -q 'secret "no-such-secret"' && explained=1 && break
  sleep 2
done
[ "${explained:-}" = 1 ] || fail "no WireGuardConfigError event for the typo pod"
[ "$(kubectl get pod typo -o jsonpath='{.status.phase}')" = Pending ] || fail "the typo pod started without its tunnel"
kubectl delete pod typo --wait=true

step "an agent restart leaves zora installed"
kubectl -n zora-system rollout restart ds/zora-agent
kubectl -n zora-system rollout status ds/zora-agent --timeout=120s
docker exec "$NODE" sh -c 'grep -q "\"zora\"" /etc/cni/net.d/*.conflist && test -x /opt/cni/bin/zora' \
  || fail "the agent restart uninstalled zora"
kubectl exec vpn -- ip addr show wg0 >/dev/null || fail "the vpn pod lost its tunnel"

step "uninstall restores the node"
helm uninstall zora -n zora-system --wait --timeout 180s
docker exec "$NODE" sh -c '! grep -q "\"zora\"" /etc/cni/net.d/*.conflist' || fail "zora is still in the CNI config"
docker exec "$NODE" sh -c '! test -e /opt/cni/bin/zora' || fail "the plugin binary is still on the node"
docker exec "$NODE" sh -c 'cat /etc/cni/net.d/*.conflist' > /tmp/zora-e2e-conflist.after
python3 - <<'PY' || fail "the CNI config differs from the original"
import json
a, b = (json.load(open(f"/tmp/zora-e2e-conflist.{x}")) for x in ("before", "after"))
assert a == b, (a, b)
PY
pod after-uninstall ""
kubectl wait --for=condition=Ready pod/after-uninstall --timeout=120s

trap - ERR
printf '\nPASS\n'
