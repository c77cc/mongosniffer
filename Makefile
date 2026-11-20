.PHONY: build test check e2e e2e-full

build:
	mkdir -p bin
	go build -trimpath -o bin/mongosniffer ./cmd/mongosniffer

test:
	go test ./...

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

e2e:
	MONGOSNIFFER_E2E_REQUIRED=1 go test -tags=e2e ./tests/e2e -run TestDockerEndToEnd -v -count=1

e2e-full:
	MONGOSNIFFER_E2E_REQUIRED=1 MONGOSNIFFER_E2E_REPLICA=1 MONGOSNIFFER_E2E_REAL_CLIENTS=1 \
		go test -tags=e2e ./tests/e2e -run TestDockerEndToEnd -v -count=1
