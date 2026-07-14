# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)
BUILDOS ?= $(shell uname -s | tr A-Z a-z)

# canonicalized names for host architecture
ifeq ($(BUILDARCH),aarch64)
BUILDARCH=arm64
endif
ifeq ($(BUILDARCH),x86_64)
BUILDARCH=amd64
endif

# unless otherwise set, I am building for my own architecture, i.e. not cross-compiling
# and for my OS
ARCH ?= $(BUILDARCH)
OS ?= $(BUILDOS)

# canonicalized names for target architecture
ifeq ($(ARCH),aarch64)
        override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
    override ARCH=amd64
endif

# The default build creates the pcap binary in the project root.
# Set BINDIR to place build artifacts elsewhere when needed.
BINDIR ?= .
BIN ?= pcap
# TARGET labels an artifact independently of the Go target tuple. Keep the
# supported 32-bit ARM baselines explicit so a v7 binary is never mislabeled
# as suitable for v6.
TARGETARCH := $(ARCH)
ifeq ($(ARCH),arm)
ifeq ($(filter 6 7,$(GOARM)),)
$(error GOARM must be 6 or 7 when ARCH=arm)
endif
TARGETARCH := armv$(GOARM)
endif
TARGET ?= $(OS)-$(TARGETARCH)
GOBINDIR ?= $(shell go env GOPATH)/bin
HOSTBIN := $(BINDIR)/$(BIN)
TARGETBIN := $(BINDIR)/$(BIN)-$(TARGET)
ifeq ($(OS),$(BUILDOS))
ifeq ($(ARCH),$(BUILDARCH))
LOCALBIN := $(HOSTBIN)
else
LOCALBIN := $(TARGETBIN)
endif
else
LOCALBIN := $(TARGETBIN)
endif
INSTALLBIN := $(GOBINDIR)/$(BIN)

.PHONY: build build-artifact clean fmt test integration bench fmt-check lint golangci-lint

export GO111MODULE=on

LINTER ?= $(GOBINDIR)/golangci-lint
LINTER_VERSION ?= v1.23.3
GOFILES := $(shell find . -name '*.go' | grep -v go/pkg/mod)

$(BINDIR):
	mkdir -p $@

build: $(LOCALBIN)

# build-artifact always includes the target suffix. Release builds use this
# target so a native build cannot overwrite the target-specific artifact name.
build-artifact: $(TARGETBIN)

$(HOSTBIN) $(TARGETBIN): $(BINDIR)
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) $(if $(filter arm,$(ARCH)),$(if $(GOARM),GOARM=$(GOARM))) go build -o $@ ./cmd

install: $(INSTALLBIN)
$(INSTALLBIN):
	CGO_ENABLED=0 go build -o $@

clean:
	@rm -f $(HOSTBIN) $(TARGETBIN)

fmt:
	gofmt -w -s $(GOFILES)

fmt-check:
	@FMTOUT=$$(gofmt -l $(GOFILES)); \
	if [ -n "$${FMTOUT}" ]; then echo $${FMTOUT}; exit 1; fi

vet:
	go vet ./...

golangci-lint: $(LINTER)
$(LINTER):
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBINDIR) $(LINTER_VERSION)

## Lint the files
lint: golangci-lint
	@$(LINTER) run ./...

test:
	go test ./...

integration: build
	@bash integration/run.sh

bench:
	go test ./filter -run '^$$' -bench . -benchmem -count=10
