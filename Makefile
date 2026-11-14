# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.DEFAULT_GOAL := help

.PHONY: help all build examples fmt fmt-check lint lint-ci vet cross vuln test e2e coverage coverage-check coverage-pkg-check cover bench bench-smoke fuzz check clean interop test-interop generate generate-check coverpkg-check upstream-watch conformance conformance-image print-conformance-image docs-check captures-verify captures-oracle captures-report captures-seeds
help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Parent otfabric/go.work does not list this module; isolate toolchain commands.
export GOWORK := off

# CI formats and lints with the Go version from go.mod, not with the toolchain installed here.
# gofmt's output changes between Go releases, so formatting is done with that version, and
# `fmt-check` also requires the local gofmt to agree.
GO_MOD_VERSION := $(shell sed -nE 's/^go ([0-9]+\.[0-9]+).*/\1/p' go.mod | head -n1)
GOFMT_CI = $(shell GOTOOLCHAIN=go$(GO_MOD_VERSION).0 go env GOROOT)/bin/gofmt

# docsync release of docs-check (DOC-008).
DOCSYNC_VERSION := v0.3.1

# Output directory for generated binaries
BIN_DIR := bin
# Library packages: tests and coverage (exclude examples)
TEST_PKGS := $(shell go list ./... | grep -v '/examples')
# Packages whose coverage counts, including what the e2e suite exercises.
# internal/capture is test infrastructure for the recorded traffic.
COVER_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/internal/cmd' | grep -v '/e2e' | grep -v '/internal/capture' | paste -sd, -)

# Build tag of the interop package (excluded from default ./... builds).
INTEROP_TAGS := interop

# Coverage floor: the coverage-min of .github/workflows/ci.yml.
COVER_MIN := 90
# Per-package floor (TEST-012): the lowest package measures 93.2 %. Needs the
# -coverpkg coverage.out of `make coverage`.
COVER_PKG_MIN := 90

# Reference implementations for 'make interop': otfabric/dnp3-interop
# INTEROP_RELEASE (opendnp3 3.1.2, DSC go-dnp3 v0.8.2, dnp3py 0.6.0,
# cB-Sigma dnp3 v0.3.1, nfm-dnp3 1.0.1). The
# images are pinned by multi-arch index digest; INTEROP_COMMIT is the
# release's commit, from which make conformance-image builds the dnp3c
# runner. Keep in step with interop/harness.go. Override to test
# other builds, e.g.
#   make interop DNP3_INTEROP_OPENDNP3_IMAGE=ghcr.io/otfabric/dnp3-interop-opendnp3:dev
INTEROP_RELEASE := v0.12.1
INTEROP_COMMIT  := 6b76b57e5f870f970220b7dcece3896883ab702f
DNP3_INTEROP_OPENDNP3_IMAGE   ?= ghcr.io/otfabric/dnp3-interop-opendnp3@sha256:22d5d0c03d7648af2b059898fb49d2e5dcd5a3e8a722935a5adfd6912bb21655
DNP3_INTEROP_DSCSYSTEMS_IMAGE ?= ghcr.io/otfabric/dnp3-interop-dscsystems@sha256:0e524995121752018db491c49bf08a5fde2098a2ce51541cdf1dff0a9b18f1bd
DNP3_INTEROP_DNP3PY_IMAGE     ?= ghcr.io/otfabric/dnp3-interop-dnp3py@sha256:6be83712526017b0247a90cfd1a36fd679b87abb01b54ff438a52332aaa26469
DNP3_INTEROP_CBSIGMA_IMAGE    ?= ghcr.io/otfabric/dnp3-interop-cbsigma@sha256:5469a14546b5bc3a5c75fdbffe4b4d8f9dd7113357cfb74daaba8db0c1d998ed
DNP3_INTEROP_NFMDNP3_IMAGE    ?= ghcr.io/otfabric/dnp3-interop-nfmdnp3@sha256:6e7f72f58cc9a59804c6e6fa3ff368593e40bf03596934d642724c96191a2ff2

# The dnp3c runner for 'make conformance': dnp3-interop's image of Step
# Function I/O's dnp3c (the DNP3 IED Certification Procedure), GPL-3.0-only
# and not published. make conformance-image builds it here from
# dnp3-interop's source at CONFORMANCE_COMMIT; the build fetches dnp3c from
# Maven Central. Nothing of it is in this repository. The same release as
# the interop images.
CONFORMANCE_RELEASE := $(INTEROP_RELEASE)
CONFORMANCE_COMMIT  ?= $(INTEROP_COMMIT)
DNP3_INTEROP_DNP3C_IMAGE ?= dnp3-interop-dnp3c:$(CONFORMANCE_RELEASE)

all: build ## Default target: build the examples

build: ## Build the examples into ./bin
	@echo "Building examples"
	@mkdir -p $(BIN_DIR)
	@for dir in examples/*/; do \
		name="$$(basename "$$dir")"; \
		go build -o "$(BIN_DIR)/example-$$name" "./$$dir"; \
	done

# The self-contained examples: each starts both sides and exits by itself.
RUN_EXAMPLES := quickstart commands events files secure observability dialout

examples: ## Run the self-contained examples (each must exit successfully)
	@for e in $(RUN_EXAMPLES); do \
		echo "Running example $$e"; \
		go run ./examples/$$e >/dev/null || { echo "example $$e failed"; exit 1; }; \
	done

fmt: ## Format Go code with the gofmt of the Go version in go.mod (what CI uses)
	@echo "Running gofmt (go$(GO_MOD_VERSION))"
	@$(GOFMT_CI) -w .

fmt-check: ## Fail if the go.mod-version gofmt or the local gofmt would change any file
	@echo "Checking formatting (gofmt go$(GO_MOD_VERSION) and local $$(go env GOVERSION))"
	@ci="$$($(GOFMT_CI) -l .)"; loc="$$(gofmt -l .)"; \
	if [ -n "$$ci$$loc" ]; then \
		[ -z "$$ci" ] || { echo "Not formatted for gofmt go$(GO_MOD_VERSION) (CI):"; echo "$$ci"; }; \
		[ -z "$$loc" ] || { echo "Not formatted for the local gofmt:"; echo "$$loc"; }; \
		echo "Files must be stable under both. Run 'make fmt'."; \
		exit 1; \
	fi

lint: ## Run staticcheck (includes -tags=interop for ./interop)
	@echo "Running staticcheck"
	@staticcheck -tags=$(INTEROP_TAGS) ./...

lint-ci: ## Run golangci-lint (build-tags include interop; see .golangci.yml)
	@echo "Running golangci-lint"
	@golangci-lint run ./...

vet: ## Run go vet (includes -tags=interop compile of ./interop)
	@echo "Running go vet"
	@go vet -tags=$(INTEROP_TAGS) ./...

cross: ## Cross-compile every package, and type-check the tests, without cgo for the supported platforms (32-bit included)
	@for p in linux/amd64 linux/arm64 linux/arm linux/386 darwin/arm64 windows/amd64; do \
		echo "Building $$p"; \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go build ./... || exit 1; \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go vet -tags=$(INTEROP_TAGS) ./... || exit 1; \
	done

vuln: ## Run govulncheck
	@echo "Running govulncheck"
	@govulncheck ./...

test: ## Run the tests with the race detector
	@echo "Running tests"
	@go test -count=1 -race $(TEST_PKGS)

e2e: ## Run the end-to-end suite (master against outstation over loopback) with the race detector
	@echo "Running the e2e suite"
	@go test -count=1 -race ./e2e/...

coverage: ## Run tests with coverage across the library packages (writes coverage.out)
	@echo "Running coverage"
	@go test -count=1 -race -covermode=atomic -coverpkg=$(COVER_PKGS) -coverprofile=coverage.out $(TEST_PKGS)
	@go tool cover -func=coverage.out | tail -1

coverage-check: coverage ## Fail when coverage.out is below COVER_MIN
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if (t+0 < m+0) { printf "coverage %.1f%% < %s%%\n", t, m; exit 1 } else printf "coverage %.1f%% >= %s%%\n", t, m }'

coverage-pkg-check: coverage ## Fail when a package is below COVER_PKG_MIN
	@awk -v m="$(COVER_PKG_MIN)" 'NR > 1 { n[$$1] = $$2; if ($$3 > 0) h[$$1] = 1 } \
	END { for (k in n) { p = k; sub(/\/[^\/]*$$/, "", p); s[p] += n[k]; if (k in h) c[p] += n[k] } \
	for (p in s) { v = 100 * c[p] / s[p]; if (v < m) { printf "%s: %.1f%% < %s%%\n", p, v, m; bad = 1 } } exit bad }' coverage.out

cover: coverage ## Open coverage report in browser
	@echo "Opening coverage report"
	@go tool cover -html=coverage.out

bench: ## Run the benchmarks of the codecs, the outstation's READ and the master's Measurements
	@echo "Running benchmarks"
	@go test -count=1 -run='^$$' -bench=. -benchmem ./link ./transport ./app ./server ./client

bench-smoke: ## Run every benchmark once, so that one that fails or no longer builds is seen
	@echo "Running every benchmark once"
	@go test -count=1 -run='^$$' -bench=. -benchtime=1x $(TEST_PKGS)

# Duration each fuzz target runs. Override with FUZZTIME=... (e.g. FUZZTIME=5m).
FUZZTIME ?= 30s
# The targets are discovered (go test -list) in every package of TEST_PKGS,
# so a new one runs without being listed here.
fuzz: ## Run every fuzz target of the library packages for FUZZTIME each (default 30s)
	@echo "Fuzzing (FUZZTIME=$(FUZZTIME))"
	@for pkg in $(TEST_PKGS); do \
		for target in $$(go test -list='^Fuzz' "$$pkg" | grep '^Fuzz'); do \
			echo "$$target ($$pkg)"; \
			go test -run='^$$' -fuzz="^$$target\$$" -fuzztime=$(FUZZTIME) "$$pkg" || exit 1; \
		done; \
	done

test-interop: ## Run the interop suite against the opendnp3, dscsystems, dnp3py, cbsigma and nfmdnp3 reference images (needs Docker)
	@echo "Running interop tests against dnp3-interop $(INTEROP_RELEASE): opendnp3, dscsystems, dnp3py, cbsigma, nfmdnp3"
	@DNP3_REQUIRE_INTEROP=1 \
		DNP3_INTEROP_OPENDNP3_IMAGE="$(DNP3_INTEROP_OPENDNP3_IMAGE)" \
		DNP3_INTEROP_DSCSYSTEMS_IMAGE="$(DNP3_INTEROP_DSCSYSTEMS_IMAGE)" \
		DNP3_INTEROP_DNP3PY_IMAGE="$(DNP3_INTEROP_DNP3PY_IMAGE)" \
		DNP3_INTEROP_CBSIGMA_IMAGE="$(DNP3_INTEROP_CBSIGMA_IMAGE)" \
		DNP3_INTEROP_NFMDNP3_IMAGE="$(DNP3_INTEROP_NFMDNP3_IMAGE)" \
		go test -tags=$(INTEROP_TAGS) -count=1 -timeout=30m ./interop/...

interop: test-interop ## Alias for test-interop

conformance-image: ## Build dnp3-interop's dnp3c runner image from its source (it is not published; needs Docker)
	@if docker image inspect "$(DNP3_INTEROP_DNP3C_IMAGE)" >/dev/null 2>&1; then \
		echo "Using $(DNP3_INTEROP_DNP3C_IMAGE)"; \
	else \
		echo "Building $(DNP3_INTEROP_DNP3C_IMAGE) from otfabric/dnp3-interop $(CONFORMANCE_RELEASE) ($(CONFORMANCE_COMMIT))"; \
		docker build --build-arg ADAPTER_VERSION=$(CONFORMANCE_RELEASE) -t "$(DNP3_INTEROP_DNP3C_IMAGE)" -f conformance/dnp3c/Dockerfile \
			"https://github.com/otfabric/dnp3-interop.git#$(CONFORMANCE_COMMIT)"; \
	fi

print-conformance-image: ## Print the dnp3c runner image make conformance uses
	@echo "$(DNP3_INTEROP_DNP3C_IMAGE)"

conformance: conformance-image ## Run the DNP3 IED certification procedures (dnp3c: 3.1r1 levels 2 and 3, 2.7) against the conformance outstation (needs Docker)
	@DNP3_INTEROP_DNP3C_IMAGE="$(DNP3_INTEROP_DNP3C_IMAGE)" internal/cmd/conformance/run.sh

generate: ## Generate the object table, Measurements' points and OBJECTS.md from app/catalog.json
	@echo "Generating from app/catalog.json"
	@go generate ./...

generate-check: ## Fail when the generated files differ from what app/catalog.json generates
	@echo "Checking the generated files against app/catalog.json"
	@go run ./internal/cmd/gencatalog -check

upstream-watch: ## Compare app/catalog.json with the upstream object definitions (DSC go-dnp3)
	@go run ./internal/cmd/upstreamwatch

coverpkg-check: ## Fail when CI's coverpkg (.github/workflows/ci.yml) is not COVER_PKGS
	@grep -qF -- "$(COVER_PKGS)" .github/workflows/ci.yml || { echo "coverpkg in .github/workflows/ci.yml must be: $(COVER_PKGS)"; exit 1; }

check: generate-check coverpkg-check captures-verify fmt fmt-check lint lint-ci vet cross vuln test coverage-pkg-check bench-smoke examples docs-check ## Run generate-check + coverpkg-check + captures-verify + format + lint + vet + cross + vuln + test + per-package coverage + bench-smoke + docs-check

# The documents against the code (DOC-008): docsync, as docs.yml runs it.
docs-check: ## Check that the documents agree with the code (docsync)
	@go run github.com/otfabric/docsync@$(DOCSYNC_VERSION) check .

# Recorded traffic (testdata/captures/README.md): committed byte-identical,
# every file under 50 MB, so the suites run offline in make test.
captures-verify: ## Verify the SHA256 of every committed capture and conformance log
	@cd testdata/captures && shasum -a 256 -c --quiet SHA256SUMS && echo "testdata/captures: SHA256SUMS verified"

captures-oracle: ## Regenerate testdata/captures/tshark/ (Wireshark's decoding of every capture; needs tshark)
	@./scripts/captures-oracle.sh

captures-report: ## Rewrite testdata/captures/coverage.json from what the codecs find (review the difference)
	@DNP3_CAPTURE_UPDATE=1 go test -count=1 -run '^TestCoverage$$' ./internal/capture/

captures-seeds: ## Rewrite the fuzz seeds taken from the captures (testdata/fuzz of link, app, server, client)
	@DNP3_CAPTURE_SEEDS=1 go test -count=1 -run '^TestFuzzSeeds$$' ./internal/capture/

clean: ## Remove generated binaries and coverage artifacts
	@echo "Cleaning up"
	@rm -rf $(BIN_DIR) coverage.out coverage.html
