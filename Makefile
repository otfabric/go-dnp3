# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.DEFAULT_GOAL := help

.PHONY: help all build examples fmt fmt-check lint lint-ci vet vuln test coverage cover bench fuzz check clean interop test-interop generate generate-check coverpkg-check upstream-watch interop-stepfunc conformance conformance-image print-conformance-image
help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Parent otfabric/go.work does not list this module; isolate toolchain commands.
export GOWORK := off

# CI formats and lints with the Go version from go.mod, not with the toolchain installed here.
# gofmt's output changes between Go releases, so formatting is done with that version, and
# `fmt-check` also requires the local gofmt to agree.
GO_MOD_VERSION := $(shell sed -nE 's/^go ([0-9]+\.[0-9]+).*/\1/p' go.mod | head -n1)
GOFMT_CI = $(shell GOTOOLCHAIN=go$(GO_MOD_VERSION).0 go env GOROOT)/bin/gofmt

# Output directory for generated binaries
BIN_DIR := bin
# Library packages: tests and coverage (exclude examples)
TEST_PKGS := $(shell go list ./... | grep -v '/examples')
# Packages whose coverage counts, including what the e2e suite exercises.
COVER_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/internal/cmd' | grep -v '/e2e' | paste -sd, -)

# Build tag of the interop package (excluded from default ./... builds).
INTEROP_TAGS := interop

# Reference implementations for 'make interop': otfabric/dnp3-interop
# INTEROP_RELEASE (stepfunc dnp3 1.8.0, opendnp3 3.1.2, DSC go-dnp3 v0.8.2,
# dnp3py 0.6.0). The published images are pinned by multi-arch index
# digest. The stepfunc image is not published (Step Function I/O's licence
# does not allow redistributing its library, dnp3-interop#19): make
# interop-stepfunc builds it here from dnp3-interop's source at
# INTEROP_COMMIT, and you receive the crate from crates.io under that
# licence yourself. Keep in step with interop/harness.go. Override to test
# other builds, e.g.
#   make interop DNP3_INTEROP_OPENDNP3_IMAGE=ghcr.io/otfabric/dnp3-interop-opendnp3:dev
INTEROP_RELEASE := v0.6.0
INTEROP_COMMIT  := 944476262140ce0ca19f7c718d553e320adffc70
DNP3_INTEROP_STEPFUNC_IMAGE   ?= dnp3-interop-stepfunc:$(INTEROP_RELEASE)
DNP3_INTEROP_OPENDNP3_IMAGE   ?= ghcr.io/otfabric/dnp3-interop-opendnp3@sha256:a637998c28c60e6dcaaab51572fdf77e4290ce4e2939483a753a6ac0acd68cd2
DNP3_INTEROP_DSCSYSTEMS_IMAGE ?= ghcr.io/otfabric/dnp3-interop-dscsystems@sha256:ec0f25dfdcdbda12de259b6481d66e248da29ea817874f5f727b8a052fba8624
DNP3_INTEROP_DNP3PY_IMAGE     ?= ghcr.io/otfabric/dnp3-interop-dnp3py@sha256:68bdf9637da43d16e1e76603fbf0fa32adb71c2d8b078c35ef7f29f2288455dc

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

vuln: ## Run govulncheck
	@echo "Running govulncheck"
	@govulncheck ./...

test: ## Run the tests with the race detector
	@echo "Running tests"
	@go test -count=1 -race $(TEST_PKGS)

coverage: ## Run tests with coverage across the library packages (writes coverage.out)
	@echo "Running coverage"
	@go test -count=1 -race -covermode=atomic -coverpkg=$(COVER_PKGS) -coverprofile=coverage.out $(TEST_PKGS)
	@go tool cover -func=coverage.out | tail -1

cover: coverage ## Open coverage report in browser
	@echo "Opening coverage report"
	@go tool cover -html=coverage.out

bench: ## Run the codec benchmarks
	@echo "Running benchmarks"
	@go test -count=1 -run='^$$' -bench=. -benchmem ./link ./transport ./app

# Duration each fuzz target runs. Override with FUZZTIME=... (e.g. FUZZTIME=5m).
FUZZTIME ?= 30s
fuzz: ## Run the codec and outstation fuzz targets for FUZZTIME each (default 30s)
	@echo "Fuzzing (FUZZTIME=$(FUZZTIME))"
	@go test -run='^$$' -fuzz='^FuzzDecode$$' -fuzztime=$(FUZZTIME) ./link
	@go test -run='^$$' -fuzz='^FuzzReader$$' -fuzztime=$(FUZZTIME) ./link
	@go test -run='^$$' -fuzz='^FuzzReassembler$$' -fuzztime=$(FUZZTIME) ./transport
	@go test -run='^$$' -fuzz='^FuzzDecode$$' -fuzztime=$(FUZZTIME) ./app
	@go test -run='^$$' -fuzz='^FuzzOutstation$$' -fuzztime=$(FUZZTIME) ./server
	@go test -run='^$$' -fuzz='^FuzzPack$$' -fuzztime=$(FUZZTIME) ./server

interop-stepfunc: ## Build the stepfunc reference image from dnp3-interop's source (it is not published; needs Docker)
	@if docker image inspect "$(DNP3_INTEROP_STEPFUNC_IMAGE)" >/dev/null 2>&1; then \
		echo "Using $(DNP3_INTEROP_STEPFUNC_IMAGE)"; \
	else \
		echo "Building $(DNP3_INTEROP_STEPFUNC_IMAGE) from otfabric/dnp3-interop $(INTEROP_RELEASE) ($(INTEROP_COMMIT))"; \
		docker build --build-arg ADAPTER_VERSION=$(INTEROP_RELEASE) -t "$(DNP3_INTEROP_STEPFUNC_IMAGE)" -f adapters/stepfunc/Dockerfile \
			"https://github.com/otfabric/dnp3-interop.git#$(INTEROP_COMMIT)"; \
	fi

test-interop: interop-stepfunc ## Run the interop suite against the stepfunc, opendnp3, dscsystems and dnp3py reference images (needs Docker)
	@echo "Running interop tests against dnp3-interop $(INTEROP_RELEASE): stepfunc, opendnp3, dscsystems, dnp3py"
	@DNP3_INTEROP_STEPFUNC_IMAGE="$(DNP3_INTEROP_STEPFUNC_IMAGE)" \
		DNP3_INTEROP_OPENDNP3_IMAGE="$(DNP3_INTEROP_OPENDNP3_IMAGE)" \
		DNP3_INTEROP_DSCSYSTEMS_IMAGE="$(DNP3_INTEROP_DSCSYSTEMS_IMAGE)" \
		DNP3_INTEROP_DNP3PY_IMAGE="$(DNP3_INTEROP_DNP3PY_IMAGE)" \
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

upstream-watch: ## Compare app/catalog.json with the upstream object definitions (stepfunc dnp3, DSC go-dnp3)
	@go run ./internal/cmd/upstreamwatch

coverpkg-check: ## Fail when CI's coverpkg (.github/workflows/ci.yml) is not COVER_PKGS
	@grep -qF -- "$(COVER_PKGS)" .github/workflows/ci.yml || { echo "coverpkg in .github/workflows/ci.yml must be: $(COVER_PKGS)"; exit 1; }

check: generate-check coverpkg-check fmt fmt-check lint lint-ci vet vuln test coverage examples ## Run generate-check + coverpkg-check + format + lint + vet + vuln + test

clean: ## Remove generated binaries and coverage artifacts
	@echo "Cleaning up"
	@rm -rf $(BIN_DIR) coverage.out coverage.html
