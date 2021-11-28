GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I./ebpf_prog

GO_SOURCE := ${PWD}/cmd/skbtracer/
GO_BINARY := skbtracer

EBPF_SOURCE := ebpf_prog/skbtracer.c
EBPF_BINARY := cmd/skbtracer/skbtracer.elf

.PHONY: all rebuild build_ebpf build_go clean pahole objdump

all: build_ebpf build_go

rebuild: clean all

build_ebpf: $(EBPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)

pahole:
	$(CLANG) $(CLANG_INCLUDE) -O2 -g -target bpf -c $(EBPF_SOURCE)  -o $(EBPF_BINARY)
	pahole $(EBPF_BINARY) > skbtracer_pahole.txt

objdump:
	$(CLANG) $(CLANG_INCLUDE) -O2 -g -target bpf -c $(EBPF_SOURCE)  -o $(EBPF_BINARY)
	llvm-objdump -S $(EBPF_BINARY) > skbtracer_objdump.txt

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@
	rm -f $(GO_BINARY)

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@ $^
