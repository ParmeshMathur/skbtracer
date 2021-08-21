GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I./ebpf_prog

GO_SOURCE := ${PWD}/cmd/skbtracer/
GO_BINARY := bin/skbtracer

EBPF_SOURCE := ebpf_prog/skbtracer.c
EBPF_BINARY := cmd/skbtracer/skbtracer.elf

.PHONY: all rebuild build_ebpf build_go clean

all: build_ebpf build_go

rebuild: clean all

build_ebpf: $(EBPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@
	rm -f $(GO_BINARY)

$(GO_BINARY): $(GO_SOURCE)
	@-if ! test -e bin; then mkdir bin; fi
	$(GOBUILD) -v -o $@ $^
