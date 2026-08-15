GO ?= go
PREFIX ?= /usr/local
VERSION_FILE := VERSION
VERSION ?= $(shell tr -d '[:space:]' < $(VERSION_FILE))
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := build

build:
	$(GO) build -trimpath -ldflags='$(LDFLAGS)' -o bin/punt ./cmd/punt

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o bin/punt-linux-amd64 ./cmd/punt

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o bin/punt-linux-arm64 ./cmd/punt

linux-armv7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o bin/punt-linux-armv7 ./cmd/punt

release:
	./scripts/build-release.sh

bump-version:
	./scripts/bump-version.sh

install: build
	install -Dm0755 bin/punt $(DESTDIR)$(PREFIX)/sbin/punt

clean:
	rm -rf bin dist

.PHONY: build test vet linux-amd64 linux-arm64 linux-armv7 release bump-version install clean
