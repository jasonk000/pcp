LIBBPF_PATH = /home/jkoch/code/libbpf/src

CFILES	= libbpf.c
CMDTARGET = pmdalibbpf$(EXECSUFFIX)
# LIBTARGET = pmda_libbpf.$(DSOSUFFIX)
LLDLIBS = $(PCP_PMDALIB) $(LIBBPF_PATH)/libbpf.a -lelf -lz -lm
LCFLAGS = -I.
CONFIG	= libbpf.conf
DFILES	= README help

IAM	= libbpf
DOMAIN	= LIBBPF

PMDATMPDIR = $(PCP_PMDAS_DIR)/$(IAM)
PMDACONFIG = $(PCP_SYSCONF_DIR)/$(IAM)
PMDAADMDIR = $(PCP_PMDASADM_DIR)/$(IAM)

LDIRT	= domain.h *.o $(IAM).log pmda$(IAM) pmda_$(IAM).$(DSOSUFFIX) runqlat.o

default:	runqlat.o biolatency.o $(_FORCE)

runqlat.o: $(_FORCE)
	clang-10 -I$(LIBBPF_PATH) -emit-llvm -O2 -g -c runqlat.bpf.c -o - | llc-10 -march=bpf -filetype=obj -o runqlat.o

biolatency.o: $(_FORCE)
	clang-10 -I$(LIBBPF_PATH) -emit-llvm -O2 -g -c biolatency.bpf.c -o - | llc-10 -march=bpf -filetype=obj -o biolatency.o
