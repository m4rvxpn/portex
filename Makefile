.PHONY: build clean test lint docker help

BINARY  := portex
VERSION := $(shell git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"
GOFLAGS := CGO_ENABLED=1

build: ## Build the portex binary
	$(GOFLAGS) go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/portex/

build-static: ## Build a static binary (Alpine-friendly)
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY)-static ./cmd/portex/

test: ## Run unit tests (no root required)
	go test -short ./...

test-integration: ## Run integration tests (requires root for raw sockets)
	sudo go test ./test/integration/... -v -timeout 120s

lint: ## Run linter
	golangci-lint run ./...

clean: ## Remove build artifacts
	rm -rf bin/

docker: ## Build Docker image
	docker build -t portex:$(VERSION) .

docker-run: ## Run a quick scan via Docker (requires NET_RAW capability)
	docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --network host \
		portex:$(VERSION) scan -t 127.0.0.1 -p 22,80,443 --mode syn

vet: ## Run go vet
	go vet ./...

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
