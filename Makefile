# Test tiers (see CONTRIBUTING.md). Tiers 0-2 need no root, no kernel
# features and no cluster. Tier 3 needs Linux with the wireguard module and
# unprivileged user namespaces (or root); `make test` runs it when possible
# and skips it otherwise, `make test-netns` insists.

GO       ?= go
PKGS     ?= ./...
FUZZTIME ?= 30s

.PHONY: all deps lint test test-netns test-integration cover fuzz update-golden

all: lint test

## Tier 0: static checks.
lint:
	@unformatted=$$(gofmt -l .); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	$(GO) vet $(PKGS)
	$(GO) mod tidy -diff
	@if command -v golangci-lint >/dev/null; then golangci-lint run; else echo "golangci-lint not installed; skipping"; fi

# The netns tiers build the reference CNI plugins inside a namespace with no
# network, so every module (including tool dependencies) must be cached.
deps:
	$(GO) mod download

## Tiers 1-4: unit, golden and property tests, plus netns and integration
## tests where the machine supports them.
test: deps
	$(GO) test -race -count=1 $(PKGS)

## Tier 3: real network namespaces and tunnels. Fails instead of skipping.
test-netns:
	ZORA_REQUIRE_NETNS=1 $(GO) test -race -count=1 ./pkg/netapply/...

## Tier 4: the real plugin binary in real CNI chains. Fails instead of skipping.
test-integration: deps
	ZORA_REQUIRE_NETNS=1 $(GO) test -race -count=1 ./test/integration/...

cover:
	$(GO) test -count=1 -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -1

## Tier 2: fuzzing. Each target runs for FUZZTIME.
fuzz:
	$(GO) test ./pkg/wgconfig -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME)

## Rewrite golden files after an intended change; review the diff.
update-golden:
	$(GO) test ./pkg/... -update
