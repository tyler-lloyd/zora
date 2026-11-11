#!/usr/bin/env bash
# Installs the chart into a kind cluster and checks the basics end to end:
# the agent chains in, an annotated pod gets a WireGuard interface, a plain
# pod doesn't, a bad annotation is explained, and uninstalling restores the
# node. The tunnel has no live peer; traffic through tunnels is covered by
# the netns and integration tests.
#
# CNI selects the cluster's primary CNI: kindnet (kind's default), flannel or
# cilium. For flannel and cilium, zora is installed *before* the primary, to
# check that it waits for the primary's config instead of writing its own.
#
# Needs docker, kind, kubectl and helm, and the wireguard kernel module
# (plus br_netfilter for flannel).
set -euo pipefail

CNI=${CNI:-kindnet}
FLANNEL_VERSION=v0.28.10
CNI_PLUGINS_VERSION=v1.10.0
CILIUM_VERSION=1.20.4
CLUSTER=${CLUSTER:-zora-e2e-$CNI}
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
  for sel in kube-flannel/app=flannel kube-system/k8s-app=cilium; do
    kubectl -n "${sel%%/*}" logs -l "${sel#*/}" --all-containers --tail=30 2>/dev/null
    kubectl -n "${sel%%/*}" logs -l "${sel#*/}" --all-containers --tail=30 --previous 2>/dev/null
  done
  kubectl get events -A --sort-by=.lastTimestamp | tail -30
  docker exec "$NODE" sh -c 'ls -la /etc/cni/net.d /opt/cni/bin; cat /etc/cni/net.d/*.conflist'
}

chained() {
  docker exec "$NODE" sh -c 'grep -q "\"zora\"" /etc/cni/net.d/*.conflist 2>/dev/null && test -x /opt/cni/bin/zora'
}

install_zora() { # extra helm args
  helm upgrade --install zora deploy/helm/zora -n zora-system --create-namespace \
    --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE#*:}" --set image.pullPolicy=Never \
    --set 'cluster.podCIDRs={10.244.0.0/16}' --set 'secrets.namespaces={default}' "$@"
}

install_primary() {
  case $CNI in
    flannel)
      # kind's node image lacks the bridge plugin that flannel delegates to.
      curl -fsSL "https://github.com/containernetworking/plugins/releases/download/$CNI_PLUGINS_VERSION/cni-plugins-linux-amd64-$CNI_PLUGINS_VERSION.tgz" \
        | docker exec -i "$NODE" tar -xz -C /opt/cni/bin ./bridge
      kubectl apply -f "https://github.com/flannel-io/flannel/releases/download/$FLANNEL_VERSION/kube-flannel.yml"
      ;;
    cilium)
      # cni.exclusive=false: otherwise Cilium reverts zora's entry.
      helm upgrade --install cilium cilium --repo https://helm.cilium.io --version "$CILIUM_VERSION" -n kube-system \
        --set ipam.mode=kubernetes --set cni.exclusive=false --set operator.replicas=1
      ;;
  esac
}
trap 'diagnose; exit 1' ERR

step "cluster ($CNI)"
if ! kind get clusters | grep -qx "$CLUSTER"; then
  if [ "$CNI" = kindnet ]; then
    kind create cluster --name "$CLUSTER" --wait 120s
  else
    kind create cluster --name "$CLUSTER" --config - <<KIND
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 10.244.0.0/16
KIND
  fi
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null

step "image"
docker build -q -t "$IMAGE" .
kind load docker-image --name "$CLUSTER" "$IMAGE"

if [ "$CNI" = kindnet ]; then
  step "install"
  install_zora --wait --timeout 180s
else
  step "install zora before the primary CNI"
  install_zora
  kubectl -n zora-system rollout status ds/zora-agent --timeout=20s 2>/dev/null && fail "zora is ready with no primary CNI"
  # Give the agent time to do the wrong thing, then check it didn't.
  for _ in $(seq 30); do
    kubectl -n zora-system get pods -o jsonpath='{.items[*].status.phase}' | grep -q Running && break
    sleep 2
  done
  sleep 5
  [ -z "$(docker exec "$NODE" sh -c 'ls /etc/cni/net.d 2>/dev/null')" ] || fail "something wrote a CNI config before the primary CNI was installed"

  step "install $CNI"
  install_primary
  kubectl wait --for=condition=Ready node --all --timeout=300s
fi
kubectl -n zora-system rollout status ds/zora-agent --timeout=180s
chained || fail "zora is not chained into the node's CNI config"
# What the node's config should be once zora is gone again.
docker exec "$NODE" sh -c 'cat /etc/cni/net.d/*.conflist' > /tmp/zora-e2e-conflist.chained
kubectl -n kube-system rollout status deploy/coredns --timeout=180s

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
chained || fail "the agent restart uninstalled zora"
kubectl exec vpn -- ip addr show wg0 >/dev/null || fail "the vpn pod lost its tunnel"

step "uninstall restores the node"
helm uninstall zora -n zora-system --wait --timeout 180s
docker exec "$NODE" sh -c '! grep -q "\"zora\"" /etc/cni/net.d/*.conflist' || fail "zora is still in the CNI config"
docker exec "$NODE" sh -c '! test -e /opt/cni/bin/zora' || fail "the plugin binary is still on the node"
docker exec "$NODE" sh -c 'cat /etc/cni/net.d/*.conflist' > /tmp/zora-e2e-conflist.after
python3 - <<'PY' || fail "the CNI config differs from the original"
import json
want, got = (json.load(open(f"/tmp/zora-e2e-conflist.{x}")) for x in ("chained", "after"))
want["plugins"] = [p for p in want["plugins"] if p["type"] != "zora"]
assert want == got, (want, got)
PY
pod after-uninstall ""
kubectl wait --for=condition=Ready pod/after-uninstall --timeout=120s

trap - ERR
printf '\nPASS\n'
