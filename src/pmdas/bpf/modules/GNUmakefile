TOPDIR = ../../../..
include $(TOPDIR)/src/include/builddefs

LIBBPF_PATH = /home/jkoch/code/libbpf/src

default:	runqlat.so biolatency.so runqlat.bpf.o biolatency.bpf.o 

runqlat.bpf.o:
	clang-11 -I$(LIBBPF_PATH) -emit-llvm -O2 -g -c runqlat.bpf.c -o - | llc-11 -march=bpf -filetype=obj -o runqlat.bpf.o

biolatency.bpf.o:
	clang-11 -I$(LIBBPF_PATH) -emit-llvm -O2 -g -c biolatency.bpf.c -o - | llc-11 -march=bpf -filetype=obj -o biolatency.bpf.o

runqlat.so: runqlat.o module_helpers.o
	$(LINK.c) -lbpf -shared $^ -o $@

biolatency.so: biolatency.o module_helpers.o
	$(LINK.c) -lbpf -shared $^ -o $@
