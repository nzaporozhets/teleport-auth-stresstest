GO ?= go
BUILD_DIR := bin

.PHONY: build
build:
	$(GO) build -o $(BUILD_DIR)/authload ./cmd/authload
	$(GO) build -o $(BUILD_DIR)/authseed ./cmd/authseed

.PHONY: test
test:
	$(GO) test ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	gofmt -l -w .

.PHONY: vet
vet:
	$(GO) vet ./...

# Integration tests require a running kind-based Teleport cluster and are
# gated behind the "integration" build tag so `make test` never needs one.
# See docs/runbook.md for the Teleport Helm install step that follows kind-up.
.PHONY: kind-up
kind-up:
	kind create cluster --name auth-stress

.PHONY: kind-down
kind-down:
	kind delete cluster --name auth-stress

.PHONY: integration-test
integration-test:
	$(GO) test -tags=integration ./... -run Integration -v

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
