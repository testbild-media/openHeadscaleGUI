VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/testbild-media/openHeadscaleGUI/internal/app.Version=$(VERSION)

.PHONY: build linux test vet clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ohg ./cmd/ohg

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ohg-linux-amd64 ./cmd/ohg
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/ohg-linux-arm64 ./cmd/ohg

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -rf dist
