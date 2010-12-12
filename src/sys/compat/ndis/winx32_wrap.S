/*-
 * Copyright (c) 2005
 *      Bill Paul <wpaul@windriver.com>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/* The 'ret' macro doesn't work in this file if GPROF is enabled. */
#ifdef GPROF
#undef GPROF
#endif

#include <machine/asmacros.h>

/*
 * This file contains assembly language wrappers for the different
 * calling conventions supported by Windows on the i386 architecture.
 * In FreeBSD, the whole OS typically use same C calling convention
 * everywhere, namely _cdecl. Windows, on the other hand, uses several
 * different C calling conventions depending on the circumstances:
 *
 * _stdcall: Used for most ordinary Windows APIs. With _stdcall,
 * arguments are passed on the stack, and the callee unwinds the stack
 * before returning control to the caller. Not suitable for variadic
 * functions.
 *
 * _fastcall: Used for some APIs that may be invoked frequently and
 * where speed is a critical factor (e.g. KeAcquireSpinLock() and
 * KeReleaseSpinLock()) Similar to _stdcall, except the first 2 32-bit
 * or smaller arguments are passed in the %ecx and %edx registers
 * instead of on the stack. Not suitable for variadic functions.
 *
 * _cdecl: Used for standard C library routines and for variadic
 * functions.
 *
 * _regparm(3): Used for certain assembly routines. All arguments
 * passed in %eax, %ecx and %edx.
 */

/*
 * Handle _stdcall going from Windows to UNIX.
 * This is frustrating, because to do it right you have to
 * know how many arguments the called function takes, and there's
 * no way to figure this out on the fly: you just have to be told
 * ahead of time. We assume there will be 16 arguments. I don't
 * think there are any Windows APIs that require this many.
 */
	.globl x86_stdcall_wrap_call
	.globl x86_stdcall_wrap_arg
	.globl x86_stdcall_wrap_end

ENTRY(x86_stdcall_wrap)
	push	%esi
	push	%edi
	sub	$64,%esp
	mov	%esp,%esi
	add	$64+8+4,%esi
	mov	%esp,%edi
	mov	$16,%ecx	# handle up to 16 args
	rep
	movsl

x86_stdcall_wrap_call:
        movl	$0,%eax
	call	*%eax		# jump to routine

	add	$64,%esp	# clean the stack
	pop	%edi
	pop	%esi
x86_stdcall_wrap_arg:
	ret	$0xFF
x86_stdcall_wrap_end:


/*
 * Handle _stdcall going from UNIX to Windows. This routine
 * expects to be passed the function to be called, number of
 * args and the arguments for the Windows function on the stack.
 */
ENTRY(x86_stdcall_call)
	push	%esi		# must preserve %esi
	push	%edi		# and %edi

	mov	16(%esp),%eax	# get arg cnt
	mov	%eax,%ecx	# save as copy count
	mov	%esp,%esi	# Set source address register to point to
	add	$20,%esi	# first agument to be forwarded.
	shl	$2,%eax		# turn arg cnt into offset
	sub	%eax,%esp	# shift stack to new location
	mov	%esp,%edi	# store dest copy addr
	rep			# do the copy
	movsl

	call	*12(%edi)	# branch to stdcall routine

	mov	%edi,%esp	# restore stack
	pop	%edi		# restore %edi
	pop	%esi		# and %esi
	ret

/*
 * Fastcall support. Similar to _stdcall, except the first
 * two arguments are passed in %ecx and %edx. It happens we
 * only support a small number of _fastcall APIs, none of them
 * take more than three arguments. So to keep the code size
 * and complexity down, we only handle 3 arguments here.
 */
/* Call _fastcall function going from Windows to UNIX. */
	.globl x86_fastcall_wrap_call
	.globl x86_fastcall_wrap_arg
	.globl x86_fastcall_wrap_end

ENTRY(x86_fastcall_wrap)
	mov	4(%esp),%eax
	push	%eax
	push	%edx
	push	%ecx

x86_fastcall_wrap_call:
	mov	$0,%eax
	call	*%eax		# branch to fastcall routine
	add	$12,%esp	# clean the stack
x86_fastcall_wrap_arg:
	ret	$0xFF
x86_fastcall_wrap_end:

/*
 * Call _fastcall function going from UNIX to Windows.
 * This routine isn't normally used since NDIS miniport drivers
 * only have _stdcall entry points, but it's provided anyway
 * to round out the API, and for testing purposes.
 */
ENTRY(x86_fastcall_call)
	mov	4(%esp),%eax
	push	16(%esp)

	mov	12(%esp),%ecx
	mov	16(%esp),%edx
	call	*8(%esp)	# branch to fastcall routine
	add	$4,%esp		# clean the stack
	ret

/*
 * Call regparm(3) function going from Windows to UNIX. Arguments
 * are passed in %eax, %edx and %ecx. Note that while additional
 * arguments are passed on the stack, we never bother when them,
 * since the only regparm(3) routines we need to wrap never take
 * more than 3 arguments.
 */
	.globl x86_regparm_wrap_call
	.globl x86_regparm_wrap_end

ENTRY(x86_regparm_wrap)
	push	%ecx
	push	%edx
	push	%eax

x86_regparm_wrap_call:
	movl	$0,%eax
	call	*%eax		# jump to routine

	add	$12,%esp	# restore stack
	ret
x86_regparm_wrap_end:

/*
 * Call regparm(3) function going from UNIX to Windows.
 * This routine isn't normally used since NDIS miniport drivers
 * only have _stdcall entry points, but it's provided anyway
 * to round out the API, and for testing purposes.
 */
ENTRY(x86_regparm_call)
	mov	8(%esp),%eax
	mov	12(%esp),%edx
	mov	16(%esp),%ecx
	call	*4(%esp)	# branch to fastcall routine
	ret
