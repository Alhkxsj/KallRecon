DEPS_LIB_NAME := KallRecon
# same anchor selection as the top Makefile: ARCH alone is x86 on a native
# x86_64 build, so also accept SRCARCH=x86 + CONFIG_64BIT from auto.conf
ifneq ($(filter x86_64,$(ARCH)),)
DEPS_LIB_ANCHOR := lib/anchor_x86.o
else ifeq ($(SRCARCH)$(CONFIG_64BIT),x86y)
DEPS_LIB_ANCHOR := lib/anchor_x86.o
else
DEPS_LIB_ANCHOR := lib/anchor.o
endif
DEPS_LIB_OBJS := lib/core.o lib/access.o lib/discover.o lib/symbol.o lib/slide.o $(DEPS_LIB_ANCHOR)
DEPS_LIB_INCS := lib
DEPS_LIB_DEPS :=
