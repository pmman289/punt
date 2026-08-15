GO ?= go
PREFIX ?= /usr/local
VERSION ?= dev
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

install: build
	install -Dm0755 bin/punt $(DESTDIR)$(PREFIX)/sbin/punt

clean:
	rm -rf bin

.PHONY: build test vet linux-amd64 install clean
