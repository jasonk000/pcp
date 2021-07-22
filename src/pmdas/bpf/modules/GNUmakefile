TOPDIR = ../../../..
include $(TOPDIR)/src/include/builddefs

IAM	= bpf
MODULES	= biolatency.so runqlat.so
BPF_MODULES = biolatency.bpf.o runqlat.bpf.o 
MODULETMP = $(PCP_PMDAS_DIR)/$(IAM)/modules
MODULEDIR = $(PCP_PMDASADM_DIR)/$(IAM)/modules

default_pcp default:	$(MODULES) $(BPF_MODULES)

include $(BUILDRULES)

$(eval $(shell grep ^VERSION_ID= /etc/os-release))
$(eval $(shell grep ^ID= /etc/os-release))

install_pcp install:	default
	$(INSTALL) -m 755 -d $(MODULEDIR)
	$(INSTALL) -m 755 -d $(MODULETMP)
	$(INSTALL) -m 644 -t $(MODULETMP) $(MODULES) $(BPF_MODULES) $(MODULEDIR)

# Use the clang pipeline to emit LLVM to LLD and emit BPF straight to an ELF .o.
# The GCC pipeline has parts of this but not completely, and in any case, likely
# requires version/feature detection too.
#
# Some distributions place commands at different names (llvm-dis vs llvm-dis-12),
# so detect distro directly.
#
# clang-12 special notes: https://www.spinics.net/lists/netdev/msg689901.html
#     nb: opt and llvm-dis appear as opt-12 and llvm-dis-12 on some OSs

ifeq "$(ID)$(VERSION_ID)" "fedora34"
%.bpf.o: %.bpf.c
	clang-12 -emit-llvm -O2 -Wno-unknown-attributes -Xclang -disable-llvm-passes -g -c $< -o - | opt -O2 -mtriple=bpf-pc-linux | llvm-dis | llc -march=bpf -filetype=obj -o $@

else ifeq "$(ID)$(VERSION_ID)" "ubuntu20.10"
%.bpf.o: %.bpf.c
	clang-11 -emit-llvm -O2 -Wno-unknown-attributes -g -c $< -o - | llc-11 -march=bpf -filetype=obj -o $@

else
# hope for the best
%.bpf.o: %.bpf.c
	clang -emit-llvm -O2 -Wno-unknown-attributes -g -c $< -o - | llc -march=bpf -filetype=obj -o $@

endif

%.so: %.o module_helpers.o
	$(LINK.c) -lbpf -shared $^ -o $@

clean::
	rm -f $(MODULES) $(BPF_MODULES)

