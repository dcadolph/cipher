# cipher Makefile.
#
# Targets are intentionally short. Run `make help` for the full list.

GO              ?= go
GOLANGCI_LINT   ?= golangci-lint
GOBIN           ?= $(shell $(GO) env GOPATH)/bin
BINARY_NAME     ?= cipher
CMD_PATH        ?= ./cmd/cipher
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT          ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS         ?= -s -w \
                   -X main.version=$(VERSION) \
                   -X main.commit=$(COMMIT) \
                   -X main.buildDate=$(BUILD_DATE)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN{FS=":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the cipher binary into ./bin.
	@mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) $(CMD_PATH)

.PHONY: install
install: ## Install the cipher binary into $GOBIN.
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" $(CMD_PATH)
	@echo "installed $(BINARY_NAME) -> $(GOBIN)/$(BINARY_NAME)"

.PHONY: test
test: ## Run unit tests with race detector.
	$(GO) test -race -count=1 ./...

.PHONY: test-cover
test-cover: ## Run tests with coverage profile.
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: bench
bench: ## Run benchmarks.
	$(GO) test -run=^$$ -bench=. -benchmem ./...

.PHONY: lint
lint: ## Run golangci-lint.
	$(GOLANGCI_LINT) run

.PHONY: tidy
tidy: ## Run go mod tidy.
	$(GO) mod tidy

.PHONY: vet
vet: ## Run go vet.
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Run gofmt on all sources.
	gofmt -w .

.PHONY: clean
clean: ## Remove build artifacts.
	rm -rf bin coverage.out

.PHONY: demo
demo: build ## Build and launch the cipher demo in the default browser.
	./bin/$(BINARY_NAME) demo

.PHONY: ci
ci: tidy vet lint test ## Run the local CI sequence.
