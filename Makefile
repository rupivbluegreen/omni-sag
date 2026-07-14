.PHONY: build test lint check-imports ci lab-up lab-down lab-logs lab-seed

build:
	go build ./...

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

lab-down:
	docker compose -f deploy/compose/docker-compose.yml down

lab-logs:
	docker compose -f deploy/compose/docker-compose.yml logs -f
