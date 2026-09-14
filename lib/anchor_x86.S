/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * anchor_x86.S
 *
 * Copyright (C) 2026 dere3046
 *
 * LTO links unify the sprint_symbol type to Function (kallsyms.h) and
 * redirect every C-level &sprint_symbol to the module-local .cfi_jt.
 * an asm .quad reference stays a plain ABS64 relocation, resolved by
 * the module loader to the real kernel address.
 */

.section .rodata
.align 8
kr_sprint_addr_ref:
	.quad sprint_symbol
.previous

.text
.globl kr_get_sprint_addr
.type kr_get_sprint_addr, @function
kr_get_sprint_addr:
	movq kr_sprint_addr_ref(%rip), %rax
	ret
.size kr_get_sprint_addr, .-kr_get_sprint_addr
