/*-
 * Copyright (c) 2003
 *	Bill Paul <wpaul@windriver.com>.  All rights reserved.
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
 *	This product includes software developed by Bill Paul.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>

#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>

#include <sys/systm.h>
#include <machine/bus.h>

#include "pe_var.h"
#include "resource_var.h"
#include "ntoskrnl_var.h"
#include "hal_var.h"
#include "ndis_var.h"

static uint64_t	KeQueryPerformanceCounter(uint64_t *);
static uint8_t	KeRaiseIrqlToDpcLevel(void);
static void	KeStallExecutionProcessor(uint32_t);
static uint32_t	READ_PORT_ULONG(uint32_t *);
static uint16_t	READ_PORT_USHORT(uint16_t *);
static uint8_t	READ_PORT_UCHAR(uint8_t *);
static void	READ_PORT_BUFFER_ULONG(uint32_t *, uint32_t *, uint32_t);
static void	READ_PORT_BUFFER_USHORT(uint16_t *, uint16_t *, uint32_t);
static void	READ_PORT_BUFFER_UCHAR(uint8_t *, uint8_t *, uint32_t);
static void	WRITE_PORT_BUFFER_ULONG(uint32_t *, uint32_t *, uint32_t);
static void	WRITE_PORT_BUFFER_USHORT(uint16_t *, uint16_t *, uint32_t);
static void	WRITE_PORT_BUFFER_UCHAR(uint8_t *, uint8_t *, uint32_t);
static void	WRITE_PORT_ULONG(uint32_t *, uint32_t);
static void	WRITE_PORT_USHORT(uint16_t *, uint16_t);
static void	WRITE_PORT_UCHAR(uint8_t *, uint8_t);
static void	_KeLowerIrql(uint8_t);
static void	dummy(void);

static struct mtx disp_lock;

void
hal_libinit(void)
{

	mtx_init(&disp_lock, "HAL lock", NULL, MTX_DEF | MTX_RECURSE);
	windrv_wrap_table(hal_functbl);
}

void
hal_libfini(void)
{

	mtx_destroy(&disp_lock);
	windrv_unwrap_table(hal_functbl);
}

static void
KeStallExecutionProcessor(uint32_t usecs)
{
	TRACE(NDBG_HAL, "usecs %u\n", usecs);
	DELAY(usecs);
}

static void
WRITE_PORT_ULONG(uint32_t *port, uint32_t value)
{
	TRACE(NDBG_HAL, "port %p value %u\n", port, value);
	bus_space_write_4(X86_BUS_SPACE_IO, 0x0, (bus_size_t)port, value);
}

static void
WRITE_PORT_USHORT(uint16_t *port, uint16_t value)
{
	TRACE(NDBG_HAL, "port %p value %u\n", port, value);
	bus_space_write_2(X86_BUS_SPACE_IO, 0x0, (bus_size_t)port, value);
}

static void
WRITE_PORT_UCHAR(uint8_t *port, uint8_t value)
{
	TRACE(NDBG_HAL, "port %p value %u\n", port, value);
	bus_space_write_1(X86_BUS_SPACE_IO, 0x0, (bus_size_t)port, value);
}

static void
WRITE_PORT_BUFFER_ULONG(uint32_t *port, uint32_t *buffer, uint32_t count)
{
	TRACE(NDBG_HAL, "port %p buffer %p count %u\n", port, buffer, count);
	bus_space_write_multi_4(X86_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static void
WRITE_PORT_BUFFER_USHORT(uint16_t *port, uint16_t *buffer, uint32_t count)
{
	TRACE(NDBG_HAL, "port %p buffer %p count %u\n", port, buffer, count);
	bus_space_write_multi_2(X86_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static void
WRITE_PORT_BUFFER_UCHAR(uint8_t *port, uint8_t *buffer, uint32_t count)
{
	TRACE(NDBG_HAL, "port %p buffer %p count %u\n", port, buffer, count);
	bus_space_write_multi_1(X86_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static uint16_t
READ_PORT_USHORT(uint16_t *port)
{
	TRACE(NDBG_HAL, "port %p\n", port);
	return (bus_space_read_2(X86_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

static uint32_t
READ_PORT_ULONG(uint32_t *port)
{
	TRACE(NDBG_HAL, "port %p\n", port);
	return (bus_space_read_4(X86_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

static uint8_t
READ_PORT_UCHAR(uint8_t *port)
{
	TRACE(NDBG_HAL, "port %p\n", port);
	return (bus_space_read_1(X86_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

static void
READ_PORT_BUFFER_ULONG(uint32_t *port, uint32_t *buffer, uint32_t count)
{
	TRACE(NDBG_HAL, "port %p count %u\n", port, count);
	bus_space_read_multi_4(X86_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static void
READ_PORT_BUFFER_USHORT(uint16_t *port, uint16_t *buffer, uint32_t count)
{
	TRACE(NDBG_HAL, "port %p count %u\n", port, count);
	bus_space_read_multi_2(X86_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static void
READ_PORT_BUFFER_UCHAR(uint8_t *port, uint8_t *buffer, uint32_t count)
{
	TRACE(NDBG_HAL, "port %p count %u\n", port, count);
	bus_space_read_multi_1(X86_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

uint8_t
KfAcquireSpinLock(unsigned long *lock)
{
	uint8_t oldirql;

	TRACE(NDBG_HAL, "lock %p\n", lock);
	KeRaiseIrql(DISPATCH_LEVEL, &oldirql);
	KeAcquireSpinLockAtDpcLevel(lock);

	return (oldirql);
}

void
KfReleaseSpinLock(unsigned long *lock, uint8_t newirql)
{
	TRACE(NDBG_HAL, "lock %p newirql %u\n", lock, newirql);
	KeReleaseSpinLockFromDpcLevel(lock);
	KeLowerIrql(newirql);
}

uint8_t
KeGetCurrentIrql(void)
{
	if (mtx_owned(&disp_lock))
		return (DISPATCH_LEVEL);
	return (PASSIVE_LEVEL);
}

static uint64_t
KeQueryPerformanceCounter(uint64_t *freq)
{
	TRACE(NDBG_HAL, "freq %p\n", freq);
	if (freq != NULL)
		*freq = hz;
	return ((uint64_t)ticks);
}

uint8_t
KfRaiseIrql(uint8_t newirql)
{
	uint8_t oldirql;

	TRACE(NDBG_HAL, "newirql %u\n", newirql);
	oldirql = KeGetCurrentIrql();
	KASSERT(oldirql <= newirql, ("newirql not less"));
	if (oldirql != DISPATCH_LEVEL)
		mtx_lock(&disp_lock);
	return (oldirql);
}

void
KfLowerIrql(uint8_t oldirql)
{
	TRACE(NDBG_HAL, "oldirql %u\n", oldirql);
	if (oldirql == DISPATCH_LEVEL)
		return;

	KASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL, ("irql not greater"));
	mtx_unlock(&disp_lock);
}

static uint8_t
KeRaiseIrqlToDpcLevel(void)
{
	uint8_t irql;

	KeRaiseIrql(DISPATCH_LEVEL, &irql);
	return (irql);
}

static void
_KeLowerIrql(uint8_t oldirql)
{
	KeLowerIrql(oldirql);
}

static void
dummy(void)
{
	printf("hal dummy called...\n");
}

struct image_patch_table hal_functbl[] = {
	IMPORT_FFUNC(KfAcquireSpinLock, 1),
	IMPORT_FFUNC(KfLowerIrql, 1),
	IMPORT_FFUNC(KfRaiseIrql, 1),
	IMPORT_FFUNC(KfReleaseSpinLock, 1),
	IMPORT_SFUNC(KeGetCurrentIrql, 0),
	IMPORT_SFUNC(KeQueryPerformanceCounter, 1),
	IMPORT_SFUNC(KeRaiseIrqlToDpcLevel, 0),
	IMPORT_SFUNC(KeStallExecutionProcessor, 1),
	IMPORT_SFUNC(READ_PORT_BUFFER_UCHAR, 3),
	IMPORT_SFUNC(READ_PORT_BUFFER_ULONG, 3),
	IMPORT_SFUNC(READ_PORT_BUFFER_USHORT, 3),
	IMPORT_SFUNC(READ_PORT_UCHAR, 1),
	IMPORT_SFUNC(READ_PORT_ULONG, 1),
	IMPORT_SFUNC(READ_PORT_USHORT, 1),
	IMPORT_SFUNC(WRITE_PORT_BUFFER_UCHAR, 3),
	IMPORT_SFUNC(WRITE_PORT_BUFFER_ULONG, 3),
	IMPORT_SFUNC(WRITE_PORT_BUFFER_USHORT, 3),
	IMPORT_SFUNC(WRITE_PORT_UCHAR, 2),
	IMPORT_SFUNC(WRITE_PORT_ULONG, 2),
	IMPORT_SFUNC(WRITE_PORT_USHORT, 2),
#undef KeLowerIrql
	IMPORT_SFUNC_MAP(KeLowerIrql, _KeLowerIrql, 1),
	{ NULL, (FUNC)dummy, NULL, 0, STDCALL },
	{ NULL, NULL, NULL }
};
