# this file is parsed twice: as the build driver (ARCH may be empty in that
# parse, harmless because only kbuild consumes kallrecon-objs) and again
# inside kbuild, where ARCH, SRCARCH and auto.conf are all set. the second
# parse is the one that selects the anchor object.
#
# scripts/subarch.include turns `uname -m` x86_64 into SUBARCH=x86, and kbuild
# then uses `ARCH ?= $(SUBARCH)`, so a native x86_64 build usually has ARCH=x86
# (an explicit ARCH=x86_64 keeps the full name, but there it is SRCARCH that is
# canonicalized to x86). ARCH alone therefore misses most x86_64 builds: also
# accept SRCARCH=x86 with CONFIG_64BIT from auto.conf.
ifneq ($(filter x86_64,$(ARCH)),)
ANCHOR := lib/anchor_x86.o
else ifeq ($(SRCARCH)$(CONFIG_64BIT),x86y)
ANCHOR := lib/anchor_x86.o
else
ANCHOR := lib/anchor.o
endif

kallrecon-objs := src/main.o lib/core.o lib/access.o lib/discover.o lib/symbol.o lib/slide.o $(ANCHOR) src/verify.o
test_probe-objs := test/test_main.o test/dbg.o lib/core.o lib/access.o lib/discover.o lib/symbol.o lib/slide.o $(ANCHOR)

ifeq ($(TARGET),test)
obj-m := test_probe.o
ccflags-y += -DKALLRECON_DEBUG
else
obj-m := kallrecon.o
endif

ifeq ($(CHECK),1)
ccflags-y += -DKALLRECON_CHECK
endif

ifdef KALLRECON_MODULE_LOOKUP
ccflags-y += -DKALLRECON_MODULE_LOOKUP
endif

ifdef KALLRECON_FAST_BOOT
ccflags-y += -DKALLRECON_FAST_BOOT
endif

ifdef KALLRECON_NO_MARKERS
ccflags-y += -DKALLRECON_NO_MARKERS
endif

ccflags-y += -std=gnu11
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-strict-prototypes

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)/out/$(VER)

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- ODIR: $(ODIR))

all:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) srcroot=$(MDIR) modules
clean:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) srcroot=$(MDIR) clean

$(obj)/%.o: $(src)/%.c $(recordmcount_source) FORCE
	$(call if_changed_rule,cc_o_c)
	$(call cmd,force_checksrc)

$(obj)/%.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)
