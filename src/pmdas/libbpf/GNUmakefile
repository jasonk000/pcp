TOPDIR = ../../..
include $(TOPDIR)/src/include/builddefs

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

default_pcp default:	$(CMDTARGET) $(LIBTARGET) $(_FORCE)

include $(BUILDRULES)

install_pcp install:	default 
	$(INSTALL) -m 755 -d $(PMDAADMDIR)
	$(INSTALL) -m 755 -d $(PMDATMPDIR)
	$(INSTALL) -m 755 -t $(PMDATMPDIR) Install Remove $(SCRIPTS) $(PMDAADMDIR)
	$(INSTALL) -m 644 -t $(PMDATMPDIR)/Makefile $(PMDAADMDIR)/Makefile
	$(INSTALL) -m 644 -t $(PMDATMPDIR) root pmns domain.h $(PMDAADMDIR)
	$(INSTALL) -m 644 -t $(PMDATMPDIR) $(CFILES) $(DFILES) $(PMDAADMDIR)
	$(INSTALL) -m 755 -d $(PMDACONFIG)
	$(INSTALL) -m 644 -t $(PMDATMPDIR)/$(CONFIG) $(CONFIG) $(PMDACONFIG)/$(CONFIG)

$(OBJECTS): domain.h

domain.h: ../../pmns/stdpmid
	$(DOMAIN_MAKERULE)
