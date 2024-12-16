/* SPDX-License-Identifier: GPL-2.0 */
/*
 * X86 asm for Rex support
 */
#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/percpu.h>

	.code64
	.section .text, "ax"

/* Dispatcher func for Rex */
SYM_FUNC_START(rex_dispatcher_func)
	/* save the callee-saved registers and the frame pointer*/
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	/* TODO: Handle exceptional control flow for extra credit */

	/* invoke bpf func */
	call *%rdx

	/* restore the callee-saved registers and the frame pointer */
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp

	/* Return */
	RET

SYM_FUNC_END(rex_dispatcher_func)
EXPORT_SYMBOL(rex_dispatcher_func)
