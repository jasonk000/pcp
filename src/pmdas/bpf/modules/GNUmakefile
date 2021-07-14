TOPDIR = ../../../..
include $(TOPDIR)/src/include/builddefs

# needs to match libbpf v0.4+
LIBBPF_HEADERS_PATH = /home/jkoch/code/libbpf/src

MODULES = biolatency.so runqlat.so
BPF_MODULES = biolatency.bpf.o runqlat.bpf.o 

default: $(MODULES) $(BPF_MODULES)

# Use the clang-11 pipeline to emit LLVM to LLD and emit BPF straight to an ELF .o.
# clang-10 also works. The GCC pipeline has parts of this but not completely
%.bpf.o: %.bpf.c
	clang-11 -I$(LIBBPF_HEADERS_PATH) -emit-llvm -O2 -g -c $^ -o - | llc-11 -march=bpf -filetype=obj -o $@

%.so: %.o module_helpers.o
	$(LINK.c) -lbpf -shared $^ -o $@
