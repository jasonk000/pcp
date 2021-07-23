TOPDIR = ../../..
include $(TOPDIR)/src/include/builddefs

CFILES	= bpf.c
CMDTARGET = pmdabpf$(EXECSUFFIX)
LIBTARGET = pmda_bpf.$(DSOSUFFIX)
LLDLIBS = $(PCP_PMDALIB) -lbpf -lelf -lz -lm -ldl
LCFLAGS = -I.
CONFIG	= bpf.conf
DFILES	= README help
SUBDIRS	= modules

IAM	= bpf
DOMAIN	= BPF

PMDATMPDIR = $(PCP_PMDAS_DIR)/$(IAM)
PMDACONFIG = $(PCP_SYSCONF_DIR)/$(IAM)
PMDAADMDIR = $(PCP_PMDASADM_DIR)/$(IAM)

LDIRT	= domain.h *.o $(IAM).log pmda$(IAM) pmda_$(IAM).$(DSOSUFFIX)

default_pcp default:	$(CMDTARGET) $(LIBTARGET) $(SUBDIRS)
	$(SUBDIRS_MAKERULE)

include $(BUILDRULES)

ifeq "$(PMDA_BPF)" "true"
install_pcp install:	default $(SUBDIRS)
	$(INSTALL) -m 755 -d $(PMDAADMDIR)
	$(INSTALL) -m 755 -d $(PMDATMPDIR)
	$(INSTALL) -m 755 -t $(PMDATMPDIR) Install Remove $(CMDTARGET) $(SCRIPTS) $(PMDAADMDIR)
	$(INSTALL) -m 644 -t $(PMDATMPDIR)/domain.h domain.h $(PMDAADMDIR)/domain.h
	$(INSTALL) -m 644 -t $(PMDATMPDIR)/root_bpf root_bpf $(PMDAADMDIR)/root_bpf
	$(INSTALL) -m 644 -t $(PCP_PMNS_DIR)/root_bpf root_bpf $(PCP_PMNSADM_DIR)/root_bpf
	$(INSTALL) -m 755 -d $(PMDACONFIG)
	$(INSTALL) -m 644 -t $(PMDATMPDIR)/$(CONFIG) $(CONFIG) $(PMDACONFIG)/$(CONFIG)
	$(SUBDIRS_MAKERULE)
else
install_pcp install:
	@$(INSTALL_MAN)
endif

$(OBJECTS): domain.h

domain.h: ../../pmns/stdpmid
	$(DOMAIN_MAKERULE)

pmns:
	$(LN_S) -f root_bpf pmns

check::	$(CFILES)
	$(CLINT) $^
