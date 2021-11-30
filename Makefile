GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOPS := /usr/local/bin/gops
GOPSSTACK := $(GOPS) stack
CLANG := clang
CLANG_INCLUDE := -I./ebpf

GO_SOURCE := ./*.go
GO_BINARY := skbtracer

EBPF_SOURCE := ebpf/skbtracer.c
EBPF_BINARY := skbtracer.elf

PID := $(shell pidof skbtracer)

.PHONY: all debug rebuild build_ebpf build_go clean pahole objdump gops kill

all: build_ebpf build_go

debug:
	$(CLANG) $(CLANG_INCLUDE) -O2 -g -target bpf -c $(EBPF_SOURCE)  -o $(EBPF_BINARY) -DDEBUG
	$(GOBUILD) -v -o $(GO_BINARY) $(GO_SOURCE)

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

gops:
	$(GOPSSTACK) $(PID) > skbtracer_gops.txt

kill:
	kill -9 $(PID)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@
	rm -f $(GO_BINARY)

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@ $^
