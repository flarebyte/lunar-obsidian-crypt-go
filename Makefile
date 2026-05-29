.DEFAULT_GOAL := help

FLYB := flyb
GO := go
GOFMT := gofmt
THOTH ?= thoth
DESIGN_META_DIR := doc/design-meta
GO_SOURCES := $(shell find . -name '*.go' -not -path './.gocache/*' -not -path './.gomodcache/*')
GO_ENV := GOCACHE=$(CURDIR)/.gocache

.PHONY: help check-tools install-tools-help \
	format format-go \
	test test-go \
	lint lint-go \
	cov cov-go \
	doc-design doc-design-validate \
	thoth-meta thoth-meta-go thoth-meta-go-test

## Public targets
help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "Available targets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

format: format-go doc-design ## Format Go sources and regenerate design docs.

test: test-go ## Run all tests.

lint: lint-go ## Run Go static checks.

cov: cov-go ## Run Go tests with coverage.

doc-design: doc-design-validate ## Validate and generate design markdown from flyb metadata.
	$(FLYB) generate markdown --config $(DESIGN_META_DIR)

doc-design-validate: ## Validate flyb design metadata.
	$(FLYB) validate --config $(DESIGN_META_DIR)

## Go targets
format-go: ## Format Go sources.
	$(GOFMT) -w $(GO_SOURCES)

test-go: ## Run Go tests.
	$(GO_ENV) $(GO) test ./...

lint-go: ## Run Go vet.
	$(GO_ENV) $(GO) vet ./...

cov-go: ## Run Go tests with coverage output.
	$(GO_ENV) $(GO) test -coverprofile=coverage.out ./...
	$(GO_ENV) $(GO) tool cover -func=coverage.out

## Diagnostics
check-tools: ## Report required tool availability.
	@command -v $(FLYB) >/dev/null 2>&1 && echo "flyb=true" || echo "flyb=false"
	@command -v $(GO) >/dev/null 2>&1 && echo "go=true" || echo "go=false"
	@command -v $(GOFMT) >/dev/null 2>&1 && echo "gofmt=true" || echo "gofmt=false"

install-tools-help: ## Show how to install required tools.
	@printf '%s\n' "flyb: install the baldrick-flying-buttress CLI and ensure the flyb executable is on PATH"
	@printf '%s\n' "go: install Go 1.24 or newer and ensure go is on PATH"

thoth-meta: thoth-meta-go thoth-meta-go-test

thoth-meta-go:
	$(THOTH) run --config ./pipeline-go-maat.thoth.cue

thoth-meta-go-test:
	$(THOTH) run --config ./pipeline-go-test-maat.thoth.cue

sec:
	semgrep scan --config auto

dup:
	npx jscpd --format go --min-lines 10 --ignore "**/.gomodcache/**,**/.gocache/**,**/.e2e-bin/**,**/node_modules/**,**/dist/**,doc/design-meta/examples/go-api.go" --gitignore .
	npx jscpd --format typescript --min-lines 10 --gitignore .

complexity:
	scc --sort complexity --by-file -i go . | head -n 15
	scc --sort complexity --by-file -i ts . | head -n 15
