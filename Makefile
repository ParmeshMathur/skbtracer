GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I./bpf_prog

GO_SOURCE := ${PWD}/cmd/skbtracer/
GO_BINARY := bin/skbtracer

BPF_SOURCE := bpf_prog/skbtracer.c
BPF_BINARY := cmd/skbtracer/skbtracer.elf

.PHONY: all rebuild build_bpf build_go clean

all: build_bpf build_go

rebuild: clean all

build_bpf: $(BPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(BPF_BINARY)

$(BPF_BINARY): $(BPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@
	rm -f $(GO_BINARY)

$(GO_BINARY): $(GO_SOURCE)
	@-if ! test -e bin; then mkdir bin; fi
	$(GOBUILD) -v -o $@ $^
