/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Pierre Oliver <pierre.olivier@manchester.ac.uk>
 *          Stefan Lankes <slankes@eonerc.rwth-aachen.de>
 *          Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * Copyright (c) 2019, Virginia Polytechnic Institute and State University.
 *                     All rights reserved.
 * Copyright (c) 2019, RWTH Aachen University, Germany.
 *.                    All rights reserved.
 * Copyright (c) 2019, NEC Laboratories Europe GmbH,
 *                     NEC Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * With the approval of the original authors, some code in this file was
 * derived and adopted from:
 * HermiTux
 * https://github.com/ssrg-vt/hermitux, commit 8780d335
 * File: apps/hermitux-light/hermitux-light.c
 * The authors of the original implementation are attributed in the license
 * header of this file.
 */

#include <limits.h>
#include <string.h>
#include <uk/assert.h>
#include <uk/print.h>
#include <uk/essentials.h>

#include "elf_prog.h"

/* Fields for auxiliary vector
 * (https://lwn.net/Articles/519085/)
 */
#define AT_NULL			0
#define AT_IGNORE		1
#define AT_EXECFD		2
#define AT_PHDR			3
#define AT_PHENT		4
#define AT_PHNUM		5
#define AT_PAGESZ		6
#define AT_BASE			7
#define AT_FLAGS		8
#define AT_ENTRY		9
#define AT_NOTELF		10
#define AT_UID			11
#define AT_EUID			12
#define AT_GID			13
#define AT_EGID			14
#define AT_PLATFORM		15
#define AT_HWCAP		16
#define AT_CLKTCK		17
#define AT_DCACHEBSIZE		19
#define AT_ICACHEBSIZE		20
#define AT_UCACHEBSIZE		21
#define AT_SECURE		23
#define AT_RANDOM		25
#define AT_EXECFN		31
#define AT_SYSINFO_EHDR		33
#define AT_SYSINFO		32

struct auxv_entry {
	long key;
	long val;
};

#if CONFIG_APPELFLOADER_VDSO
extern char *vdso_image_addr;
#endif /* CONFIG_APPELFLOADER_VDSO */

#if CONFIG_ARCH_X86_64
#define UK_AUXV_PLATFORM	"x86_64"
#elif CONFIG_ARCH_ARM_64
#define UK_AUXV_PLATFORM	"aarch64"
#else
#error "Unsupported architecture"
#endif

#if CONFIG_ARCH_ARM_64
/* A field of an ID register: unsigned, or signed for those where 0xf means
 * "not implemented" (FP, AdvSIMD).
 */
#define ID_FIELD(reg, shift)	(((reg) >> (shift)) & 0xf)
#define ID_SFIELD(reg, shift)	((int)((__s64)((reg) << (60 - (shift))) >> 60))

#define ID_READ(name)							\
	({ __u64 __v; __asm__ ("mrs %0, " #name : "=r"(__v)); __v; })

/*
 * AT_HWCAP as Linux reports it on arm64 (uapi/asm/hwcap.h), from the ID
 * registers: userspace learns the CPU's features from it rather than by
 * reading those registers, and some programs refuse to run without it
 * (.NET needs ASIMD).  Features whose state the kernel would have to
 * manage for the program are left out: SVE, pointer authentication keys,
 * and the timer event stream.
 */
static __u64 elf_arm64_hwcap(void)
{
	__u64 pfr0 = ID_READ(id_aa64pfr0_el1);
	__u64 pfr1 = ID_READ(id_aa64pfr1_el1);
	__u64 isar0 = ID_READ(id_aa64isar0_el1);
	__u64 isar1 = ID_READ(id_aa64isar1_el1);
	__u64 mmfr2 = ID_READ(id_aa64mmfr2_el1);
	__u64 hwcap = 1UL << 11;	/* CPUID: ID registers are readable */

	if (ID_SFIELD(pfr0, 16) >= 0)
		hwcap |= 1UL << 0;	/* FP */
	if (ID_SFIELD(pfr0, 16) >= 1)
		hwcap |= 1UL << 9;	/* FPHP */
	if (ID_SFIELD(pfr0, 20) >= 0)
		hwcap |= 1UL << 1;	/* ASIMD */
	if (ID_SFIELD(pfr0, 20) >= 1)
		hwcap |= 1UL << 10;	/* ASIMDHP */
	if (ID_FIELD(pfr0, 48) >= 1)
		hwcap |= 1UL << 24;	/* DIT */
	if (ID_FIELD(isar0, 4) >= 1)
		hwcap |= 1UL << 3;	/* AES */
	if (ID_FIELD(isar0, 4) >= 2)
		hwcap |= 1UL << 4;	/* PMULL */
	if (ID_FIELD(isar0, 8) >= 1)
		hwcap |= 1UL << 5;	/* SHA1 */
	if (ID_FIELD(isar0, 12) >= 1)
		hwcap |= 1UL << 6;	/* SHA2 */
	if (ID_FIELD(isar0, 12) >= 2)
		hwcap |= 1UL << 21;	/* SHA512 */
	if (ID_FIELD(isar0, 16) >= 1)
		hwcap |= 1UL << 7;	/* CRC32 */
	if (ID_FIELD(isar0, 20) >= 2)
		hwcap |= 1UL << 8;	/* ATOMICS */
	if (ID_FIELD(isar0, 28) >= 1)
		hwcap |= 1UL << 12;	/* ASIMDRDM */
	if (ID_FIELD(isar0, 32) >= 1)
		hwcap |= 1UL << 17;	/* SHA3 */
	if (ID_FIELD(isar0, 36) >= 1)
		hwcap |= 1UL << 18;	/* SM3 */
	if (ID_FIELD(isar0, 40) >= 1)
		hwcap |= 1UL << 19;	/* SM4 */
	if (ID_FIELD(isar0, 44) >= 1)
		hwcap |= 1UL << 20;	/* ASIMDDP */
	if (ID_FIELD(isar0, 48) >= 1)
		hwcap |= 1UL << 23;	/* ASIMDFHM */
	if (ID_FIELD(isar0, 52) >= 1)
		hwcap |= 1UL << 27;	/* FLAGM */
	if (ID_FIELD(isar1, 0) >= 1)
		hwcap |= 1UL << 16;	/* DCPOP */
	if (ID_FIELD(isar1, 12) >= 1)
		hwcap |= 1UL << 13;	/* JSCVT */
	if (ID_FIELD(isar1, 16) >= 1)
		hwcap |= 1UL << 14;	/* FCMA */
	if (ID_FIELD(isar1, 20) >= 1)
		hwcap |= 1UL << 15;	/* LRCPC */
	if (ID_FIELD(isar1, 20) >= 2)
		hwcap |= 1UL << 26;	/* ILRCPC */
	if (ID_FIELD(isar1, 36) >= 1)
		hwcap |= 1UL << 29;	/* SB */
	if (ID_FIELD(mmfr2, 32) >= 1)
		hwcap |= 1UL << 25;	/* USCAT */
	if (ID_FIELD(pfr1, 4) >= 2)
		hwcap |= 1UL << 28;	/* SSBS */
	return hwcap;
}
#define UK_AUXV_HWCAP		elf_arm64_hwcap()
#else /* !CONFIG_ARCH_ARM_64 */
#define UK_AUXV_HWCAP		0x0
#endif /* !CONFIG_ARCH_ARM_64 */

/* `len` may be 0: an empty argument or environment string, which
 * execve() allows, is pushed as its NUL alone. */
static void infoblk_push(struct ukarch_ctx *ctx, void *buf, __sz len)
{
	UK_ASSERT(ctx);
	UK_ASSERT(ctx->sp);
	UK_ASSERT(buf);

	ctx->sp -= len + 1;
	memcpy((void *)ctx->sp, buf, len);
	((char *)ctx->sp)[len] = '\0';
}

int elf_arg_env_count(int *argc, const char **argv,
		      int *envc, const char **envp,
		      __sz stack_sz)
{
	const char **a;
	__sz len;

	*argc = *envc = len = 0;
	if (!argv && !envp)
		return 0;

	/* count argv */
	if (argv)
		for (a = argv; *a; ++a) {
			++*argc;
			len += strlen(*a);
		}

	/* count envp */
	if (envp)
		for (a = envp; *a; ++a) {
			++*envc;
			len += strlen(*a);
		}

	/* POSIX defines the minimum total size of argv + envp to ARG_MAX,
	 * and leaves the inclusion of NULL terminators, pointers and / or
	 * alignment bytes as implementation defined. The policy we implement
	 * is:
	 *
	 * - Permit the total length to exceed ARG_MAX as long as it's not
	 * greater than 1/4 of the stack size. This is essentially the same
	 * policy as linux (see execve(2)), with the difference that we
	 * don't apply the MAX_ARG_STRLEN floor of 32 pages.
	 *
	 * - Exclude auxv, NULL, alignment bytes from the checked size, as
	 * these are of fixed size and occupy an insignificant portion of
	 * the stack.
	 */
	UK_ASSERT(IS_ALIGNED(stack_sz, 4));
	if (unlikely(len > ARG_MAX && len > stack_sz / 4))
		return -E2BIG;

	return len;
}

void elf_ctx_init(struct ukarch_ctx *ctx, struct elf_prog *prog,
		  const char *argv0, int argc, const char *argv[],
		  int envc, const char *environ[],
		  uint64_t rand[2])
{
	int args_count = argc + (argv0 ? 1 : 0);
	char *infoblk_argvp[args_count];
	char *infoblk_envp[envc];
	int i, elfvec_len;

	UK_ASSERT(prog);
	UK_ASSERT(argv0 || ((argc >= 1) && argv));

	uk_pr_debug("%s: image:          0x%"PRIx64" - 0x%"PRIx64"\n",
		    prog->name, (uint64_t) prog->vabase,
		    (uint64_t) prog->vabase + prog->valen);
	uk_pr_debug("%s: start:          0x%"PRIx64"\n", prog->name,
		    (uint64_t) prog->start);
	uk_pr_debug("%s: entry:          0x%"PRIx64"\n", prog->name,
		    (uint64_t) prog->entry);
	uk_pr_debug("%s: phdr.off:       0x%"PRIx64"\n", prog->name,
		    (uint64_t) prog->phdr.off);
	uk_pr_debug("%s: phdr.num:       %"PRIu64"\n",   prog->name,
		    (uint64_t) prog->phdr.num);
	uk_pr_debug("%s: phdr.entsize:   0x%"PRIx64"\n", prog->name,
		    (uint64_t) prog->phdr.entsize);
	if (prog->interp.prog) {
		uk_pr_debug("%s: interp:         0x%"PRIx64" - 0x%"PRIx64"\n",
			    prog->name, (uint64_t) prog->interp.prog->vabase,
			    (uint64_t) prog->interp.prog->vabase +
			    prog->interp.prog->valen);
		uk_pr_debug("%s: interp.start:   0x%"PRIx64"\n", prog->name,
			    (uint64_t) prog->interp.prog->start);
		uk_pr_debug("%s: interp.entry:   0x%"PRIx64"\n", prog->name,
			    (uint64_t) prog->interp.prog->entry);
	}

	/* AT_RANDOM points at 16 bytes the program may read at any time
	 * (Go's runtime seeds from them) and may overwrite.  `rand` lives in
	 * the caller's frame, which is stale by the time an execve()d program
	 * runs, so copy the bytes to the program's stack, as Linux does.
	 */
	ctx->sp -= sizeof(uint64_t) * 2;
	memcpy((void *)ctx->sp, rand, sizeof(uint64_t) * 2);
	rand = (uint64_t *)ctx->sp;

	/* list of all auxiliary vector entries whose pointer values need
	 * to point to information block areas
	 */
	struct auxv_entry infoblk_auxv[] = {
		{ AT_PLATFORM, (__uptr)UK_AUXV_PLATFORM	},
	};

	/* list of all auxiliary vector entries whose pointer values need
	 * not be in the information block
	 */
	struct auxv_entry auxv[] = {
		{ AT_NOTELF, 0x0 },
		{ AT_UCACHEBSIZE, 0x0 },
		{ AT_ICACHEBSIZE, 0x0 },
		{ AT_DCACHEBSIZE, 0x0 },
		/* path to executable */
		{ AT_EXECFN, (long) (prog->path ? prog->path : prog->name) },
		{ AT_SECURE, 0x0 },
		{ AT_EGID, 0x0 },
		{ AT_GID, 0x0 },
		{ AT_EUID, 0x0 },
		{ AT_UID, 0x0 },
		{ AT_ENTRY, prog->entry },
		{ AT_FLAGS, 0x0 },
		{ AT_CLKTCK, 0x64 }, /* Mimic Linux */
		{ AT_HWCAP, UK_AUXV_HWCAP },
		{ AT_PAGESZ, 4096 },
		/* base addr of interpreter */
		{ AT_BASE, prog->interp.prog ?
			   prog->interp.prog->start : 0x0 },
		{ AT_RANDOM, (uintptr_t) rand },
		{ AT_PHENT, prog->phdr.entsize },
		{ AT_PHNUM, prog->phdr.num },
		{ AT_PHDR, (__uptr)prog->vabase + prog->phdr.off },
#if CONFIG_APPELFLOADER_VDSO
		/* TODO: This must also be pushed and copied
		 * or mapped to information block. Move it to infoblk_auxv
		 * ASAP.
		 */
		{ AT_SYSINFO_EHDR, (uintptr_t)vdso_image_addr },
#endif /* CONFIG_APPELFLOADER_VDSO */
		{ AT_IGNORE, 0x0 }
	};
	struct auxv_entry auxv_null = { AT_NULL, 0x0 };

	for (i = (int)ARRAY_SIZE(infoblk_auxv) - 1; i >= 0; i--) {
		infoblk_push(ctx, (void *)infoblk_auxv[i].val,
			     strlen((const char*)infoblk_auxv[i].val));
		/* Overwrite previous pointer to our memory to a pointer to
		 * the newly copied buffer in the information block.
		 */
		infoblk_auxv[i].val = ctx->sp;
	}

	if (envc)
		for (i = envc - 1; i >= 0; i--) {
			infoblk_push(ctx, (void *)environ[i],
				     strlen(environ[i]));
			infoblk_envp[i] = (char *)ctx->sp;
		}

	if (argc)
		for (i = argc; i >= 1; i--) {
			infoblk_push(ctx, (void *)argv[i - 1],
				     strlen(argv[i - 1]));
			infoblk_argvp[i] = (char *)ctx->sp;
		}

	if (argv0) {
		infoblk_push(ctx, (void *)argv0, strlen(argv0));
		infoblk_argvp[0] = (char *)ctx->sp;
	}

	/* Add a NULL terminator before argv0 as the cherry on top (bottom?)
	 * and re-align stack to prepare it for what's about to be pushed
	 * next.
	 */
	ctx->sp--;
	((char *)ctx->sp)[0] = '\0';
	ctx->sp--;
	ctx->sp = ALIGN_DOWN(ctx->sp, UKARCH_SP_ALIGN);

	/*
	 * We need to respect the stack alignment ABI requirements at function
	 * calls. (eg: x86_64 requires that the stack is 16-byte aligned)
	 *
	 * Here we count how many bytes are pushed to the stack:
	 * - auxiliary vector;
	 * - environment variables (plus extra NULL pointer);
	 * - arguments (plus extra NULL pointer and argument count (long))
	 */
	elfvec_len = ((ARRAY_SIZE(auxv) + 1) * sizeof(struct auxv_entry))
		+ (envc + 1) * sizeof(uintptr_t)
		+ (argc + (argv0 ? 1 : 0) + 1) * sizeof(uintptr_t)
		+ sizeof(long);

	ctx->sp = ALIGN_DOWN(ctx->sp - elfvec_len, UKARCH_SP_ALIGN)
		+ elfvec_len;

	/*
	 * We need to push the element on the stack in the inverse order they
	 * will be read by the application's C library (i.e. argc in the end)
	 *
	 * Auxiliary vector (NOTE: we push the terminating NULL first)
	 */
	ukarch_rctx_stackpush_packed(ctx, auxv_null);
	for (i = (int)ARRAY_SIZE(infoblk_auxv) - 1; i >= 0; i--)
		ukarch_rctx_stackpush_packed(ctx, infoblk_auxv[i]);
	for (i = (int)ARRAY_SIZE(auxv) - 1; i >= 0; --i)
		ukarch_rctx_stackpush_packed(ctx, auxv[i]);

	/*
	 * envp
	 */
	/* NOTE: As expected, this will push NULL to the stack first */
	ukarch_rctx_stackpush_packed(ctx, (long)NULL);
	if (environ) {
		for (i = envc - 1; i >= 0; --i) {
			uk_pr_debug("env[%d]=\"%s\"\n", i, infoblk_envp[i]);
			ukarch_rctx_stackpush_packed(ctx,
						     (__uptr)infoblk_envp[i]);
		}
	}

	/*
	 * argv + argc
	 */
	/* Same as envp, pushing NULL first */
	ukarch_rctx_stackpush_packed(ctx, (long)NULL);
	if (args_count)
		for (i = args_count - 1; i >= 0; i--)
			ukarch_rctx_stackpush_packed(ctx,
						     (__uptr)infoblk_argvp[i]);
	ukarch_rctx_stackpush_packed(ctx, (long)args_count);

	UK_ASSERT(IS_ALIGNED(ctx->sp, UKARCH_SP_ALIGN));

	/* ctx will enter the entry point with cleared registers. */
	if (prog->interp.required) {
		struct elf_prog *interp = prog->interp.prog;

		UK_ASSERT(prog->interp.prog);

		/* dynamically linked executable, jump into loader instead */
		ukarch_ctx_init(ctx, ctx->sp, 0x0, interp->entry);
	} else {
		/* statically linked executable */
		ukarch_ctx_init(ctx, ctx->sp, 0x0, prog->entry);
	}
}
