.DEFAULT_GOAL := help

FLYB := flyb
DESIGN_META_DIR := doc/design-meta

.PHONY: help check-tools install-tools-help doc-design doc-design-validate

## Public targets
help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "Available targets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

doc-design: doc-design-validate ## Validate and generate design markdown from flyb metadata.
	$(FLYB) generate markdown --config $(DESIGN_META_DIR)

doc-design-validate: ## Validate flyb design metadata.
	$(FLYB) validate --config $(DESIGN_META_DIR)

## Diagnostics
check-tools: ## Report required tool availability.
	@command -v $(FLYB) >/dev/null 2>&1 && echo "flyb=true" || echo "flyb=false"

install-tools-help: ## Show how to install required tools.
	@printf '%s\n' "flyb: install the baldrick-flying-buttress CLI and ensure the flyb executable is on PATH"

thoth-meta: thoth-meta-go thoth-meta-go-test

thoth-meta-go:
        $(THOTH) run --config ./pipeline-go-maat.thoth.cue

thoth-meta-go-test:
        $(THOTH) run --config ./pipeline-go-test-maat.thoth.cue