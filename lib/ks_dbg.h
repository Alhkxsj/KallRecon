// SPDX-License-Identifier: GPL-2.0-only
/*
 * ks_dbg.h
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef KS_DBG_H
#define KS_DBG_H

#include <linux/printk.h>

#ifdef KALLRECON_DEBUG
#define ks_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define ks_dbg(fmt, ...) do {} while (0)
#endif

#endif
