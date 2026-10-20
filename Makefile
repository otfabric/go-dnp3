# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.DEFAULT_GOAL := help

.PHONY: help all build examples fmt fmt-check lint lint-ci vet vuln test coverage cover bench fuzz check clean interop test-interop
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
COVER_PKGS := $(shell go list ./... | grep -v '/examples' | grep -v '/e2e' | paste -sd, -)

# Build tag of the interop package (excluded from default ./... builds).
INTEROP_TAGS := interop

# Reference implementations for 'make interop': otfabric/dnp3-interop v0.2.0
# (stepfunc dnp3 1.7.0, opendnp3 3.1.2, DSC Systems go-dnp3 v0.8.1, dnp3py
# 0.6.0), pinned by multi-arch index digest. Keep in step with
# interop/harness.go. Override to test other builds, e.g.
#   make interop DNP3_INTEROP_OPENDNP3_IMAGE=ghcr.io/otfabric/dnp3-interop-opendnp3:dev
DNP3_INTEROP_STEPFUNC_IMAGE   ?= ghcr.io/otfabric/dnp3-interop-stepfunc@sha256:ead1ea3c9a0f48ea363f745846ff2d5df8f077f50b6bb7f20914c3207ba5667e
DNP3_INTEROP_OPENDNP3_IMAGE   ?= ghcr.io/otfabric/dnp3-interop-opendnp3@sha256:a69ebb5962b334ff9813a1efbb871ccd5d296fad71bd13feb94bec52ef7ff19a
DNP3_INTEROP_DSCSYSTEMS_IMAGE ?= ghcr.io/otfabric/dnp3-interop-dscsystems@sha256:d0576cceabf24cbd072b672069226c30486aa84046dc98d813a5427a32dbae3a
DNP3_INTEROP_DNP3PY_IMAGE     ?= ghcr.io/otfabric/dnp3-interop-dnp3py@sha256:14598aebcd5698d8f342d6d9beaa98b8618d724c57fbbe34222737678ceff0ef

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

test-interop: ## Run the interop suite against the stepfunc, opendnp3, dscsystems and dnp3py reference images (needs Docker)
	@echo "Running interop tests against dnp3-interop v0.2.0: stepfunc, opendnp3, dscsystems, dnp3py"
	@DNP3_INTEROP_STEPFUNC_IMAGE="$(DNP3_INTEROP_STEPFUNC_IMAGE)" \
		DNP3_INTEROP_OPENDNP3_IMAGE="$(DNP3_INTEROP_OPENDNP3_IMAGE)" \
		DNP3_INTEROP_DSCSYSTEMS_IMAGE="$(DNP3_INTEROP_DSCSYSTEMS_IMAGE)" \
		DNP3_INTEROP_DNP3PY_IMAGE="$(DNP3_INTEROP_DNP3PY_IMAGE)" \
		go test -tags=$(INTEROP_TAGS) -count=1 -timeout=30m ./interop/...

interop: test-interop ## Alias for test-interop

check: fmt fmt-check lint lint-ci vet vuln test coverage examples ## Run format + lint + vet + vuln + test

clean: ## Remove generated binaries and coverage artifacts
	@echo "Cleaning up"
	@rm -rf $(BIN_DIR) coverage.out coverage.html
