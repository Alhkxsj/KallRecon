// SPDX-License-Identifier: GPL-2.0-only
/*
 * core.c
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include "core.h"
#include "ks_dbg.h"
#include "access.h"
#include "discover.h"

unsigned long sprint_addr;
unsigned long kernel_base;
unsigned long klbase_addr;
unsigned long klbase_val;
unsigned long kloffs_addr;
unsigned long klindex_addr;
unsigned long klseqs_addr;
unsigned int  klnum_val;
unsigned long klmarks_addr;
unsigned long kltable_addr;
unsigned long klnames_addr;
unsigned long klnum_addr;

enum layout_v kl_layout = LAYOUT_V2;
int is_v1_layout;

unsigned long (*kallrecon_klp)(const char *name);
#ifdef KALLRECON_MODULE_LOOKUP
unsigned long (*kallrecon_module_klp)(const char *name); /* experimental, may be unstable */
#endif

static DEFINE_MUTEX(ks_lock);
static int ks_done;

#ifdef KALLRECON_FAST_BOOT
/* best-effort fast path: walk function boundaries with sprint_symbol
 * from the anchor towards kallsyms_lookup_name. not expected to be
 * stable; the full lookup stays authoritative and runs on a miss */
static unsigned long fast_find_klp(void)
{
	unsigned long addr = sprint_addr;
	char buf[KSYM_SYMBOL_LEN];

	for (int i = 0; i < 200000; i++) {
		char *plus;
		unsigned long off = 0, size = 0;
		const char *q;

		sprint_symbol(buf, addr);
		if (strstr(buf, "kallsyms_lookup_name"))
			return addr;

		plus = strrchr(buf, '+');
		if (!plus)
			return 0;

		/* parse "+off/size" by hand, sscanf is not guaranteed exported */
		q = plus + 1;
		while (*q && *q != '/') {
			char c = *q++;
			unsigned long d;

			if (c >= '0' && c <= '9')
				d = c - '0';
			else if (c >= 'a' && c <= 'f')
				d = c - 'a' + 10;
			else
				return 0;
			off = (off << 4) | d;
		}
		if (*q++ != '/')
			return 0;
		while (*q) {
			char c = *q++;
			unsigned long d;

			if (c >= '0' && c <= '9')
				d = c - '0';
			else if (c >= 'a' && c <= 'f')
				d = c - 'a' + 10;
			else
				break;
			size = (size << 4) | d;
		}

		/* step to the previous function boundary */
		if (off)
			addr = (addr - off) - 1;
		else if (addr > 4)
			addr -= 4;
		else
			return 0;
	}
	return 0;
}
#endif

static void find_kallsyms_base_once(void)
{
	if (!kr_discover_layout())
		return;

	if (kloffs_addr && klnames_addr && klnum_val) {
		unsigned long addr = 0;

#ifdef KALLRECON_FAST_BOOT
		addr = fast_find_klp();
		ks_dbg("[kallrecon] fast boot: %s\n",
			addr ? "hit" : "miss");
#endif
		if (!addr)
			addr = kallsyms_name_to_addr("kallsyms_lookup_name");
		if (addr)
			kallrecon_klp = (unsigned long (*)(const char *))addr;

#ifdef KALLRECON_MODULE_LOOKUP
		unsigned long maddr =
			kallsyms_name_to_addr("module_kallsyms_lookup_name");

		if (maddr)
			kallrecon_module_klp =
				(unsigned long (*)(const char *))maddr;
#endif
	}
}

void find_kallsyms_base(void)
{
	mutex_lock(&ks_lock);
	if (!ks_done) {
		find_kallsyms_base_once();
		ks_done = 1;
	}
	mutex_unlock(&ks_lock);
}
