// SPDX-License-Identifier: GPL-2.0-only
/*
 * core.c
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include "core.h"
#include "slide.h"

#ifdef KALLRECON_DEBUG
#define ks_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define ks_dbg(fmt, ...) do {} while (0)
#endif

#define KS_WIN_SIZE	(64 * 1024)	/* slide window chunk */
#define KS_WIN_MARGIN	512		/* slide window overlap */
#define KS_RUN_MIN	5000		/* min offsets run length */
#define KS_RUN_MAX	500000		/* run scan cap */
#define KS_RB_SEARCH	4096		/* rb delta search range */
#define KS_FALLBACK_OFF	0x1000		/* token_table fallback guess */
#define KS_SCAN_BACK	0x400000	/* scan range below token_table */
#define KS_SCAN_FWD	0x200000	/* scan range above token_index */
#define KS_PCPU_EXT_MAX	100000		/* percpu extend entry cap */
#define KS_PCPU_MAX	0x10000000	/* percpu absolute address cap */
#define KS_2M_MASK	0x1FFFFFULL	/* kernel base alignment */
#define KS_PAGE_MASK	0xFFFULL	/* page alignment */

int safe_read(void *dst, const void *src, size_t sz)
{
	return copy_from_kernel_nofault(dst, src, sz);
}

unsigned long kr_get_sprint_addr(void);

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

int is_v1_layout;
unsigned long (*kallrecon_klp)(const char *name);
#ifdef KALLRECON_MODULE_LOOKUP
unsigned long (*kallrecon_module_klp)(const char *name); /* experimental, may be unstable */
#endif

/* address formula proven by verify_offsets_rb, latched so sym_addr()
 * always uses the formula that resolved real symbols during discovery.
 * x86 5.10~6.12 KALLSYMS_ABSOLUTE_PERCPU is covered by KS_MODE_ABSPCPU,
 * 6.18+ removed the option and uses KS_MODE_RB like arm64 */
#define KS_MODE_RB	0
#define KS_MODE_ABSPCPU	1
static int kl_addr_mode = KS_MODE_RB;

/* strip LTO suffix like kernel cleanup_symbol_name()
 * 5.10/5.15 (no seqs): '$', 6.1+ (seqs): ".llvm."
 */
static int ks_cleanup_name(char *s)
{
	char *res;

	if (klseqs_addr)
		res = strstr(s, ".llvm.");
	else
		res = strrchr(s, '$');
	if (!res)
		return 0;
	*res = '\0';
	return 1;
}

static int (*kallrecon_user_cleanup)(char *s);

static int ks_cleanup_name_chain(char *s)
{
	int (*cb)(char *s) = READ_ONCE(kallrecon_user_cleanup);
	int r = ks_cleanup_name(s);

	if (cb)
		r |= cb(s) ? 1 : 0;
	return r;
}

void kallrecon_set_cleanup(int (*cb)(char *s))
{
	WRITE_ONCE(kallrecon_user_cleanup, cb);
}

static int check_ti_strong(unsigned short *ti)
{
	if (ti[0] != 0)
		return 0;
	for (int i = 1; i < 256; i++)
		if (ti[i] <= ti[i - 1])
			return 0;
	return ti['b'] - ti['a'] == 2 && ti['z'] - ti['a'] == 50;
}

/* locate token_table from token_index: walk back over trailing zeros
 * and the last token string, then step back ti255 (token_index[255]
 * holds the last token's offset inside token_table) */
static unsigned long find_token_table(unsigned long ti_addr,
				      unsigned short ti255)
{
	unsigned long pos = ti_addr - 1;
	unsigned char c;

	while (pos > kernel_base) {
		if (safe_read(&c, (void *)pos, 1) || c != 0)
			break;
		pos--;
	}
	while (pos > kernel_base) {
		if (safe_read(&c, (void *)pos, 1))
			break;
		if (c == 0)
			break;
		pos--;
	}
	if (pos + 1 > ti255)
		return pos + 1 - ti255;
	return 0;
}

/* markers sanity: walking 256 symbols from the stream start must land
 * on the offset stored in markers[1]; only then get_sym_offset() may
 * trust markers to skip ahead */
static int kl_markers_ok;

static void verify_markers(void)
{
	u32 m0, m1;
	const u8 *p;
	int i;

	if (!klmarks_addr || !klnames_addr || klnum_val <= 512)
		return;
	if (safe_read(&m0, (void *)klmarks_addr, 4) ||
	    safe_read(&m1, (void *)(klmarks_addr + 4), 4) || m0 != 0) {
		kl_markers_ok = -1;
		return;
	}

	p = (const u8 *)klnames_addr;
	for (i = 0; i < 256; i++) {
		unsigned char lb;
		int len;

		if (safe_read(&lb, (void *)p, 1))
			break;
		len = lb;
		if (len & 0x80) {
			if (safe_read(&lb, (void *)(p + 1), 1))
				break;
			len = (len & 0x7F) | (lb << 7);
			p += 2 + len;
		} else {
			p += 1 + len;
		}
	}
	kl_markers_ok = (i == 256 &&
			 (unsigned int)(p - (const u8 *)klnames_addr) == m1)
		? 1 : -1;
	ks_dbg("[kallrecon] markers verify: %s\n",
		kl_markers_ok == 1 ? "OK" : "MISMATCH");
}
/* empirically pick the address formula: try candidates in priority
 * order, the first one resolving to a real symbol wins. entries sampled
 * by the caller must sit inside [_stext, _end): head.text (arm64) and
 * the percpu block (x86) resolve to hex under every formula */
static int ks_addr_try(unsigned long rb, u32 off, int *mode)
{
	char name[KSYM_SYMBOL_LEN];

#ifdef CONFIG_X86_64
	{
		s32 so = (s32)off;
		unsigned long a = so >= 0 ? (unsigned long)(u32)so
					  : rb - 1 - so;

		sprint_symbol(name, a);
		ks_dbg("[kallrecon] try abs 0x%x -> 0x%lx '%s'\n", off, a, name);
		if (!(name[0] == '0' && name[1] == 'x')) {
			*mode = KS_MODE_ABSPCPU;
			return 1;
		}
	}
#endif
	sprint_symbol(name, rb + off);
	ks_dbg("[kallrecon] try rb  0x%x -> 0x%lx '%s'\n", off, rb + off, name);
	if (!(name[0] == '0' && name[1] == 'x')) {
		*mode = KS_MODE_RB;
		return 1;
	}
	/* rb+off may land in the .head.text gap; kernel_base fixes the
	 * verification while the rb+off value itself stays correct */
	sprint_symbol(name, kernel_base + off);
	ks_dbg("[kallrecon] try kb  0x%x -> 0x%lx '%s'\n", off, kernel_base + off,
		name);
	if (!(name[0] == '0' && name[1] == 'x')) {
		*mode = KS_MODE_RB;
		return 1;
	}
	return 0;
}

static int verify_offsets_rb(unsigned long cand, int len,
			      unsigned long *rb_out, unsigned long *rb_addr_out)
{
	int skip = 0;
	for (skip = 0; skip < 20; skip++) {
		u32 zv;
		if (safe_read(&zv, (void *)(cand + skip * 4), 4))
			break;
		if (zv != 0)
			break;
	}

	unsigned long real_cand = cand + skip * 4;
	int real_len = len - skip;

	unsigned long base_rb = (cand + len * 4 + 7) & ~7ULL;
	for (int delta = 0; delta < KS_RB_SEARCH; delta += 8) {
		for (int sgn = 0; sgn < 2; sgn++) {
			unsigned long rb_addr;
			unsigned long rb;

			if (delta == 0 && sgn == 1)
				continue;
			rb_addr = sgn ? base_rb + delta : base_rb - delta;
			if (safe_read(&rb, (void *)rb_addr, 8))
				continue;
			if (rb_addr >= real_cand &&
			    rb_addr + 8 <= real_cand + real_len * 4)
				continue;
			{
				unsigned long check = (rb_addr + 8 + 7) & ~7ULL;
				int ok = 0;
				unsigned int ns;
				if (!safe_read(&ns, (void *)check, 4) &&
				    (ns == (unsigned int)len ||
				     ns == (unsigned int)(len - 1)))
					ok = 1;
				if (!ok) {
					ok = 1;
					for (int i = 0; i < 5 && ok; i++) {
						unsigned char b[3];
						unsigned int s;
						if (safe_read(b, (void *)(check + i * 3), 3))
							ok = 0;
						else {
							s = (b[0] << 16) | (b[1] << 8) | b[2];
							if (s >= (unsigned int)len)
								ok = 0;
						}
					}
				}
				if (!ok)
					continue;
			}

			int vok = 1;
			int mode = KS_MODE_RB;

			if (real_len < 3) {
				vok = 0;
			} else {
				/* sample the head: the .head.text gap (arm64)
				 * is covered by ks_addr_try's kernel_base
				 * fallback, same as the proven three-step
				 * verification */
				for (int i = 0; i < 3 && vok; i++) {
					u32 o;
					unsigned long at = real_cand +
						(unsigned long)i * 4;

					if (safe_read(&o, (void *)at, 4)) {
						vok = 0;
						break;
					}
					ks_dbg("[kallrecon] head[%d] @0x%lx = 0x%x\n",
						i, at, o);
					if (!ks_addr_try(rb, o, &mode))
						vok = 0;
				}
			}
			if (!vok)
				continue;

			kl_addr_mode = mode;	/* latch the proven formula */

			if (rb_out)
				*rb_out = rb;
			if (rb_addr_out)
				*rb_addr_out = rb_addr;
			return 1;
		}
	}

	return 0;
}

/* verify a candidate offsets run and publish the globals on success */
static int commit_offsets(unsigned long cand, int len,
			  unsigned long *best_cand, int *best_len)
{
	unsigned long rb, rb_addr;

	if (len < KS_RUN_MIN)
		return 0;
	if (verify_offsets_rb(cand, len, &rb, &rb_addr)) {
		*best_cand = cand;
		*best_len = len;
		kloffs_addr = cand;
		klnum_val = len;
		klbase_addr = rb_addr;
		klbase_val = rb;
		ks_dbg("[kallrecon] hit pg=0x%lx sorted=%d\n",
			(unsigned long)(cand & ~KS_PAGE_MASK), len);
		return 1;
	}
	if (len > KS_RUN_MIN &&
	    verify_offsets_rb(cand, len - 1, &rb, &rb_addr)) {
		*best_cand = cand;
		*best_len = len - 1;
		kloffs_addr = cand;
		klnum_val = len - 1;
		klbase_addr = rb_addr;
		klbase_val = rb;
		ks_dbg("[kallrecon] hit pg=0x%lx sorted=%d (len-1)\n",
			(unsigned long)(cand & ~KS_PAGE_MASK), len);
		return 1;
	}
	ks_dbg("[kallrecon] cand REJECT\n");
	return 0;
}

static int scan_zerou32(unsigned long start, unsigned long end,
			 unsigned long *best_cand, int *best_len)
{
	int found = 0;
	struct slide_win w;

	if (slide_init(&w, start, KS_WIN_SIZE, KS_WIN_MARGIN))
		return 0;

	for (;;) {
		u32 v;
		unsigned long addr = slide_addr(&w);
		if (addr >= end)
			break;

		v = *(u32 *)slide_ptr(&w, slide_buf);
		if (v != 0) {
			if (slide_advance(&w, 4))
				break;
			continue;
		}

		unsigned long cand = addr;
		int len = 0, prev = -1;

		for (;;) {
			unsigned long ext_addr = slide_addr(&w);
			if (ext_addr >= end || len >= KS_RUN_MAX)
				break;
			v = *(u32 *)slide_ptr(&w, slide_buf);
			if ((int)v < prev)
				break;
			prev = (int)v;
			len++;
			if (slide_advance(&w, 4))
				break;
		}

		if (len >= KS_RUN_MIN && len > *best_len) {
			ks_dbg("[kallrecon] cand@0x%lx len=%d prev=0x%x\n",
				cand, len, prev);

			if (prev != 0 && (prev & KS_2M_MASK) == 0)
				len--;

			if (commit_offsets(cand, len, best_cand, best_len))
				found = 1;
		}

		if (slide_init(&w, cand + 4, KS_WIN_SIZE, KS_WIN_MARGIN))
			break;
	}

	return found;
}

#ifdef CONFIG_X86_64
/* x86 5.10~6.12 ABSOLUTE_PERCPU stores normal symbols as rb-1-addr,
 * which decreases as addresses increase; the forward ascending-run
 * scanner cannot see it. walking backwards turns the same entries
 * into an ascending run. rb (2MB aligned) may lead the run and is
 * dropped by the same alignment check the forward scanner uses. */
static int rev_commit(unsigned long cand, int len, int head,
		      unsigned long *best_cand, int *best_len)
{
	unsigned long full = cand;
	int pc = 0, pv = KS_PCPU_MAX;

	/* the percpu block sits at the low end: absolute small positive
	 * addresses, non-increasing when walked backwards */
	while (full >= 4 && pc < KS_PCPU_EXT_MAX) {
		u32 v;
		int vi;

		if (safe_read(&v, (void *)(full - 4), 4))
			break;
		vi = (int)v;
		if (vi < 0 || vi > KS_PCPU_MAX || vi > pv)
			break;
		pv = vi;
		full -= 4;
		pc++;
	}

	if (head != 0 && (head & KS_2M_MASK) == 0)
		len--;

	return commit_offsets(full, len + pc, best_cand, best_len);
}

static int scan_zerou32_rev(unsigned long start, unsigned long end,
			    unsigned long *best_cand, int *best_len)
{
	unsigned long pos = end;
	unsigned long cand = 0;
	int len = 0, prev = 0, head = 0;

	while (pos > start) {
		unsigned long lo = pos - start > KS_WIN_SIZE ?
			pos - KS_WIN_SIZE : start;
		unsigned int n = (unsigned int)((pos - lo) / 4);
		int i;

		if (!n)
			break;
		if (safe_read(slide_buf, (void *)lo, n * 4))
			break;

		for (i = (int)n - 1; i >= 0; i--) {
			u32 v = slide_buf[i];
			unsigned long addr = lo + (unsigned long)i * 4;

			if (len && (int)v < prev) {
				if (len >= KS_RUN_MIN &&
				    rev_commit(cand, len, head,
					       best_cand, best_len))
					return 1;
				len = 0;
			}
			if (!len)
				head = (int)v;
			prev = (int)v;
			cand = addr;
			len++;
		}
		pos = lo;
	}

	if (len >= KS_RUN_MIN && rev_commit(cand, len, head, best_cand, best_len))
		return 1;
	return 0;
}
#endif

static int discover_kallsyms(unsigned long ti_addr)
{
	unsigned long best_cand = 0;
	int best_len = 0;
	unsigned short ti255;
	unsigned long scan_start, scan_end;

	if (safe_read(&ti255, (void *)(ti_addr + 255 * 2), 2))
		return 0;

	kltable_addr = find_token_table(ti_addr, ti255);
	if (!kltable_addr)
		kltable_addr = ti_addr - KS_FALLBACK_OFF;
	scan_start = kltable_addr > KS_SCAN_BACK ?
		(kltable_addr - KS_SCAN_BACK) & ~KS_PAGE_MASK : kernel_base;
	scan_end = (ti_addr + KS_SCAN_FWD + KS_PAGE_MASK) & ~KS_PAGE_MASK;

	ks_dbg("[kallrecon] scan 0x%lx-0x%lx kltable=0x%lx\n",
		scan_start, scan_end, kltable_addr);

	if (scan_zerou32(scan_start, scan_end, &best_cand, &best_len))
		goto found;

#ifdef CONFIG_X86_64
	if (scan_zerou32_rev(scan_start, scan_end, &best_cand, &best_len))
		goto found;
#endif

	ks_dbg("[kallrecon] no offsets found\n");
	return 0;

found:
	klindex_addr = ti_addr;
	is_v1_layout = (kloffs_addr < ti_addr) ? 1 : 0;
	ks_dbg("[kallrecon] discovered: sorted=%u v%d\n",
		klnum_val, is_v1_layout ? 1 : 2);
	return 1;
}

static unsigned long find_token_index(unsigned long start)
{
	struct slide_win w;

	if (slide_init(&w, start, KS_WIN_SIZE, KS_WIN_MARGIN))
		return 0;

	for (;;) {
		unsigned short *ti = (unsigned short *)slide_ptr(&w, slide_buf);
		if (check_ti_strong(ti))
			return slide_addr(&w);
		if (slide_advance(&w, 4))
			break;
	}
	return 0;
}

static unsigned long detect_seqs(unsigned long cand, unsigned int n)
{
	if (!cand || !n)
		return 0;

	int points[] = {0, 1, 2, n/4, n/4+1, n/4+2, n/2, n/2+1, n/2+2,
			3*n/4, 3*n/4+1, 3*n/4+2, n-3, n-2, n-1};
	int np = sizeof(points) / sizeof(points[0]);

	for (int i = 0; i < np; i++) {
		int idx = points[i];
		if (idx < 0 || idx >= (int)n)
			return 0;
		unsigned char buf[3];
		unsigned int seq;
		if (safe_read(buf, (void *)(cand + idx * 3), 3))
			return 0;
		seq = (buf[0] << 16) | (buf[1] << 8) | buf[2];
		if (seq >= n)
			return 0;
	}
	return cand;
}

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
	sprint_addr = kr_get_sprint_addr();
	kernel_base = sprint_addr & ~KS_2M_MASK;
	klbase_val = kernel_base;

ks_dbg("[kallrecon] sprint=0x%lx kernel_base=0x%lx\n",
		sprint_addr, kernel_base);

	unsigned long ti_addr = find_token_index(sprint_addr & ~KS_PAGE_MASK);
	if (!ti_addr) {
ks_dbg("[kallrecon] token_index not found\n");
		return;
	}
ks_dbg("[kallrecon] ti=0x%lx\n", ti_addr);
	klindex_addr = ti_addr;
	if (!discover_kallsyms(ti_addr)) {
ks_dbg("[kallrecon] layout: offsets not found\n");
		return;
	}

	if (is_v1_layout) {
		klnum_addr = (klbase_addr + 8 + 7) & ~7ULL;
		{
			u32 ns;
			if (safe_read(&ns, (void *)klnum_addr, 4) ||
			    (ns != klnum_val && ns != klnum_val - 1))
				klnum_addr = 0;
		}
		klnames_addr = (klnum_addr + 4 + 7) & ~7ULL;

		if (klindex_addr && klnum_val) {
			unsigned short ti255;
			unsigned long tt;

			if (!safe_read(&ti255,
				       (void *)(klindex_addr + 255 * 2), 2)) {
				tt = find_token_table(klindex_addr, ti255);
				if (tt)
					kltable_addr = tt;
			}
		}

		unsigned int markers_cnt = (klnum_val + 255) / 256;
		unsigned long marks_size = markers_cnt * 4;

		unsigned long seqs_cand = kltable_addr ? (kltable_addr - klnum_val * 3) & ~7ULL : 0;
		klseqs_addr = detect_seqs(seqs_cand, klnum_val);
		if (klseqs_addr)
			klmarks_addr = (klseqs_addr - marks_size) & ~7ULL;
		else
			klmarks_addr = (kltable_addr - marks_size) & ~7ULL;
	} else {
		klseqs_addr = detect_seqs(klbase_addr + 8, klnum_val);

		if (klindex_addr && klnum_val) {
			unsigned short ti255;
			unsigned long tt;

			if (!safe_read(&ti255,
				       (void *)(klindex_addr + 255 * 2), 2)) {
				tt = find_token_table(klindex_addr, ti255);
				if (tt)
					kltable_addr = tt;
			}
		}

		if (kltable_addr && klnum_val) {
			unsigned int markers_cnt = (klnum_val + 255) / 256;
			unsigned long marks_size = markers_cnt * 4;
			unsigned long marks_end = (kltable_addr + 7) & ~7ULL;
			klmarks_addr = marks_end - marks_size;
		}

		if (klmarks_addr && klnum_val) {
			unsigned long end_addr = klmarks_addr > 0x300000 ?
				klmarks_addr - 0x300000 : kernel_base;
			end_addr &= ~3ULL;
			for (unsigned long addr = klmarks_addr & ~3ULL;
			     addr >= end_addr; addr -= 4) {
				unsigned int v32;
				if (safe_read(&v32, (void *)addr, 4))
					continue;
				if (v32 == klnum_val || v32 == klnum_val - 1) {
					klnum_addr = addr;
					break;
				}
			}
		}

		if (klnum_addr)
			klnames_addr = (klnum_addr + 4 + 7) & ~7ULL;
	}

	/*
	 * sorted-run cand may sit on a leading zero u32 before
	 * kallsyms_offsets, shifting sym_addr() by one entry.
	 * recompute offsets start from kallsyms_num_syms.
	 */
	if (klbase_addr && klnum_addr) {
		u32 ns;
		if (!safe_read(&ns, (void *)klnum_addr, 4) && ns) {
			kloffs_addr =
				(klbase_addr - (unsigned long)ns * 4) & ~7ULL;
			klnum_val = ns;
		}
	}

	verify_markers();

ks_dbg("[kallrecon] kallsyms data:\n");
ks_dbg("  klbase  @ 0x%lx = 0x%lx\n", klbase_addr, klbase_val);
ks_dbg("  kloffs  @ 0x%lx\n", kloffs_addr);
ks_dbg("  klnum   @ 0x%lx = %u\n", klnum_addr, klnum_val);
ks_dbg("  klindex @ 0x%lx\n", klindex_addr);
ks_dbg("  klseqs  @ 0x%lx\n", klseqs_addr);
ks_dbg("  kltable @ 0x%lx\n", kltable_addr);
ks_dbg("  klmarks @ 0x%lx\n", klmarks_addr);
ks_dbg("  klnames @ 0x%lx\n", klnames_addr);
	ks_dbg("  layout  v%d\n", is_v1_layout ? 1 : 2);

#ifdef KALLRECON_CHECK
	if (kltable_addr && klindex_addr) {
		unsigned short off0;
		unsigned char c;
		if (!safe_read(&off0, (void *)(klindex_addr + '0' * 2), 2) &&
		    !safe_read(&c, (void *)(kltable_addr + off0), 1) &&
		    c == '0')
			ks_dbg("  tbl verify: '0' match\n");
		else
			ks_dbg("  tbl verify: MISMATCH\n");
	}
	if (klmarks_addr && klnum_val) {
		unsigned int m0, m1;
		int mok = !safe_read(&m0, (void *)klmarks_addr, 4) && m0 == 0;
		if (mok && (klnum_val + 255) / 256 > 1)
			mok = !safe_read(&m1, (void *)(klmarks_addr + 4), 4)
				&& m1 >= 256;
		ks_dbg("  markers verify: %s\n", mok ? "OK" : "MISMATCH");
	}
	if (klnames_addr && klmarks_addr && klnum_val) {
		unsigned int markers_cnt = (klnum_val + 255) / 256;
		unsigned int end_off;
		if (!safe_read(&end_off, (void *)(klmarks_addr +
			(markers_cnt - 1) * 4), 4)) {
			unsigned int count = 0;
			for (unsigned long p = klnames_addr;
			     p < klnames_addr + end_off + 1024; ) {
				unsigned char lb;
				unsigned int elen;
				if (safe_read(&lb, (void *)p, 1))
					break;
				if (lb & 0x80) {
					unsigned char lb2;
					if (safe_read(&lb2, (void *)(p + 1), 1))
						break;
					elen = (lb & 0x7F) | (lb2 << 7);
					p += 2;
				} else {
					if (lb == 0)
						break;
					elen = lb;
					p += 1;
				}
				p += elen;
				count++;
			}
			ks_dbg("  names count: dp=%u vs sort=%u %s\n",
				count, klnum_val,
				count == klnum_val ? "MATCH" : "MISMATCH");
		}
	}
#endif

	if (klbase_addr && kloffs_addr) {
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
		unsigned long maddr = kallsyms_name_to_addr("module_kallsyms_lookup_name");
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

unsigned long sym_addr(int idx)
{
	u32 off;
	if (safe_read(&off, (void *)(kloffs_addr + idx * 4), 4))
		return 0;
#ifdef CONFIG_X86_64
	if (kl_addr_mode == KS_MODE_ABSPCPU) {
		s32 so = (s32)off;
		if (so >= 0)
			return (unsigned long)(u32)so;
		return klbase_val - 1 - so;
	}
#endif
	return klbase_val + off;
}

int expand_sym(unsigned int off, char *buf, int max)
{
	unsigned char lb;
	unsigned int len;
	*buf = '\0';
	if (safe_read(&lb, (const void *)(klnames_addr + off), 1))
		return 0;
	len = lb;
	unsigned int off1 = off + 1;

	if (len & 0x80) {
		if (safe_read(&lb, (const void *)(klnames_addr + off1), 1))
			return 0;
		len = (len & 0x7F) | (lb << 7);
		off1++;
	}

	int skipped = 0;
	for (unsigned int i = 0; i < len && max > 1; i++) {
		unsigned char c;
		if (safe_read(&c, (const void *)(klnames_addr + off1 + i), 1))
			return 0;
		unsigned short ti;
		if (safe_read(&ti, (const void *)(klindex_addr + c * 2), 2))
			return 0;
		unsigned int ti_idx = ti;
		{
			unsigned long tp = kltable_addr + ti_idx;
			for (;;) {
				unsigned char ch;
				if (safe_read(&ch, (const void *)tp, 1))
					break;
				if (!ch)
					break;
				if (skipped) {
					if (max <= 1)
						break;
					*buf++ = ch;
					max--;
				} else {
					skipped = 1;
				}
				tp++;
			}
		}
	}
	if (max)
		*buf = '\0';
	return (int)(off1 + len - off);
}

unsigned int get_sym_seq(int idx)
{
	unsigned int i, seq = 0;

	if (klseqs_addr) {
		unsigned char buf[3];
		if (safe_read(buf, (const void *)(klseqs_addr + idx * 3), 3))
			return (unsigned int)idx;
		for (i = 0; i < 3; i++)
			seq = (seq << 8) | buf[i];
		return seq;
	}
	return (unsigned int)idx;
}

unsigned int get_sym_offset(unsigned int seq)
{
	const u8 *p;
	unsigned char lb;

	/* markers hold the stream offset of every 256th symbol; jump to
	 * the nearest one instead of walking the whole stream */
	if (kl_markers_ok == 1 && seq >= 256) {
		unsigned int m = seq / 256;
		u32 mo;

		if (safe_read(&mo, (void *)(klmarks_addr + m * 4), 4))
			return UINT_MAX;
		seq -= m * 256;
		p = (const u8 *)(klnames_addr + mo);
	} else {
		p = (const u8 *)klnames_addr;
	}

	for (unsigned int i = 0; i < seq; i++) {
		if (safe_read(&lb, (void *)p, 1))
			return UINT_MAX;
		int len = lb;
		if (len & 0x80) {
			if (safe_read(&lb, (void *)(p + 1), 1))
				return UINT_MAX;
			len = ((len & 0x7F) | (lb << 7)) + 1;
		}
		p = p + len + 1;
	}
	return p - (const u8 *)klnames_addr;
}

static unsigned short ti_buf[256];
static unsigned char tt_buf[2048];

static int expand_sym_buf(unsigned short *ti, unsigned char *tt,
			  const unsigned char *enc, char *buf, int max)
{
	unsigned int len = *enc++;
	*buf = '\0';
	if (len & 0x80)
		len = (len & 0x7F) | (*enc++ << 7);
	if (len > 256U)
		return 0;

	int skipped = 0;
	for (unsigned int i = 0; i < len && max > 1; i++) {
		unsigned char c = *enc++;
		if (c >= 256U || ti[c] >= sizeof(tt_buf))
			return 0;
		const char *tp = (const char *)tt + ti[c];
		while (*tp) {
			if ((const unsigned char *)tp - tt >= sizeof(tt_buf))
				return 0;
			if (skipped) {
				if (max <= 1)
					return 0;
				*buf++ = *tp;
				max--;
			} else {
				skipped = 1;
			}
			tp++;
		}
	}
	if (max)
		*buf = '\0';
	return 1;
}

static DEFINE_MUTEX(ks_linear_lock);

static unsigned long name_to_addr_linear_locked(const char *name)
{
	unsigned short *ti = ti_buf;
	unsigned char *tt = tt_buf;
	char nbuf[256];
	int idx, hit = 0, decoded = 0;
	struct slide_win w;

	ks_dbg("[kallrecon] linear: search '%s' n=%u\n", name, klnum_val);

	if (safe_read(ti, (void *)klindex_addr, sizeof(ti_buf))) {
		ks_dbg("[kallrecon] linear: ti load FAIL\n");
		return 0;
	}
	if (safe_read(tt, (void *)kltable_addr, sizeof(tt_buf))) {
		ks_dbg("[kallrecon] linear: tt load FAIL\n");
		return 0;
	}

	if (slide_init(&w, klnames_addr, KS_WIN_SIZE, KS_WIN_MARGIN)) {
		ks_dbg("[kallrecon] linear: slide init FAIL\n");
		return 0;
	}

	for (idx = 0; idx < (int)klnum_val; idx++) {
		const unsigned char *name_start = slide_ptr(&w, slide_buf);
		int lb = *name_start;
		int elen = lb;
		int hdr = 1;
		if (lb & 0x80) {
			elen = (lb & 0x7F) | (name_start[1] << 7);
			hdr = 2;
		}
		if ((unsigned int)(hdr + elen) > 256U ||
		    w.off + hdr + elen > w.chunksz + w.margin) {
			ks_dbg("[kallrecon] linear: boundary fail idx=%d hdr=%d elen=%d\n",
				idx, hdr, elen);
			break;
		}

		decoded++;
		expand_sym_buf(ti, tt, name_start, nbuf, sizeof(nbuf));
		{
			int sample = 0;
			if (idx < 5)
				sample = 1;
			else if (idx == (int)klnum_val / 2)
				sample = 1;
			else if (idx >= (int)klnum_val - 5)
				sample = 1;
			else if (nbuf[0] == 'k' && nbuf[1] == 'a')
				sample = 1;
			if (sample)
				ks_dbg("[kallrecon] linear: [%d] '%s'\n", idx, nbuf);
		}
		if (strcmp(nbuf, name) == 0) {
			hit = 1;
			ks_dbg("[kallrecon] linear: HIT idx=%d\n", idx);
			return sym_addr(idx);
		}
		if (ks_cleanup_name_chain(nbuf) && strcmp(nbuf, name) == 0) {
			hit = 1;
			ks_dbg("[kallrecon] linear: HIT(cln) idx=%d\n", idx);
			return sym_addr(idx);
		}

		if (slide_advance(&w, hdr + elen)) {
			ks_dbg("[kallrecon] linear: slide fail idx=%d\n", idx);
			break;
		}
	}

	ks_dbg("[kallrecon] linear: done idx=%d decoded=%d hit=%d\n", idx, decoded, hit);
#ifdef KALLRECON_MODULE_LOOKUP
	if (kallrecon_module_klp)
		return kallrecon_module_klp(name);
#endif
	return 0;
}

/* linear scan shares slide_buf/ti_buf/tt_buf globals, serialize it */
static unsigned long name_to_addr_linear(const char *name)
{
	unsigned long ret;

	mutex_lock(&ks_linear_lock);
	ret = name_to_addr_linear_locked(name);
	mutex_unlock(&ks_linear_lock);
	return ret;
}

unsigned long kallsyms_name_to_addr(const char *name)
{
	if (!klseqs_addr) {
#ifdef KALLRECON_MODULE_LOOKUP
		unsigned long addr = name_to_addr_linear(name);
		if (addr || !kallrecon_module_klp)
			return addr;
		return kallrecon_module_klp(name);
#else
		return name_to_addr_linear(name);
#endif
	}

	int low = 0, high = (int)klnum_val - 1;
	char nbuf[256];

	while (low <= high) {
		int mid = low + (high - low) / 2;
		unsigned int seq = get_sym_seq(mid);
		unsigned int off = get_sym_offset(seq);
		expand_sym(off, nbuf, sizeof(nbuf));
		ks_cleanup_name_chain(nbuf);

		int r = strcmp(name, nbuf);
		if (r > 0)
			low = mid + 1;
		else if (r < 0)
			high = mid - 1;
		else {
			/* walk left to first matching entry, same cleaned
			 * name resolves to smallest address */
			unsigned int first = mid;
			while (first > 0) {
				unsigned int pseq = get_sym_seq(first - 1);
				unsigned int poff = get_sym_offset(pseq);
				expand_sym(poff, nbuf, sizeof(nbuf));
				ks_cleanup_name_chain(nbuf);
				if (strcmp(name, nbuf))
					break;
				first--;
			}
			return sym_addr(get_sym_seq(first));
		}
	}
#ifdef KALLRECON_MODULE_LOOKUP
	if (kallrecon_module_klp)
		return kallrecon_module_klp(name);
#endif
	return 0;
}

int sym_name_at(unsigned long addr, char *buf, int max)
{
	int low = 0, high = (int)klnum_val;

	while (high - low > 1) {
		int mid = low + (high - low) / 2;
		if (sym_addr(mid) <= addr)
			low = mid;
		else
			high = mid;
	}

	unsigned int off = get_sym_offset(low);
	expand_sym(off, buf, max);
	ks_cleanup_name_chain(buf);
	return low;
}
