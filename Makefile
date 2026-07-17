.PHONY: build binaries test lint check-imports ci lab-up lab-down lab-logs lab-seed lab-test-real-target

build:
	go build ./...

# Cross-compilable, statically-linked release binaries for every command.
BINARIES := omni-sag omnisag-ctl omni-verify omnisag-operator
GOOS   ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
EXT :=
ifeq ($(GOOS),windows)
EXT := .exe
endif

binaries:
	@mkdir -p bin
	@for b in $(BINARIES); do \
	  echo "building $$b ($(GOOS)/$(GOARCH), $(VERSION))"; \
	  CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	    go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" \
	    -o bin/$${b}_$(GOOS)_$(GOARCH)$(EXT) ./cmd/$$b || exit 1; \
	done

test:
	go test ./...

lint:
	@fmtout=$$(gofmt -l . | grep -v -e '^\.claude/' -e '^vendor/' || true); \
	if [ -n "$$fmtout" ]; then echo "gofmt needed:"; echo "$$fmtout"; exit 1; fi
	go vet ./...

check-imports:
	bash scripts/check-imports.sh

ci: build lint check-imports test

lab-up:
	docker compose -f deploy/compose/docker-compose.yml up -d

lab-seed:
	bash scripts/lab-seed.sh

lab-test-real-target:
	bash scripts/lab-test-real-target.sh

lab-down:
	docker compose -f deploy/compose/docker-compose.yml down

lab-logs:
	docker compose -f deploy/compose/docker-compose.yml logs -f
