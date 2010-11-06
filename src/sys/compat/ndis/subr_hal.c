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
#include <sys/types.h>

#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/module.h>

#include <sys/systm.h>
#include <machine/bus.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/cfg_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/hal_var.h>

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
	DELAY(usecs);
}

static void
WRITE_PORT_ULONG(uint32_t *port, uint32_t value)
{
	bus_space_write_4(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port, value);
}

static void
WRITE_PORT_USHORT(uint16_t *port, uint16_t value)
{
	bus_space_write_2(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port, value);
}

static void
WRITE_PORT_UCHAR(uint8_t *port, uint8_t value)
{
	bus_space_write_1(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port, value);
}

static void
WRITE_PORT_BUFFER_ULONG(uint32_t *port, uint32_t *buffer, uint32_t count)
{
	bus_space_write_multi_4(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static void
WRITE_PORT_BUFFER_USHORT(uint16_t *port, uint16_t *buffer, uint32_t count)
{
	bus_space_write_multi_2(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static void
WRITE_PORT_BUFFER_UCHAR(uint8_t *port, uint8_t *buffer, uint32_t count)
{
	bus_space_write_multi_1(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static uint16_t
READ_PORT_USHORT(uint16_t *port)
{
	return (bus_space_read_2(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

static uint32_t
READ_PORT_ULONG(uint32_t *port)
{
	return (bus_space_read_4(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

static uint8_t
READ_PORT_UCHAR(uint8_t *port)
{
	return (bus_space_read_1(NDIS_BUS_SPACE_IO, 0x0, (bus_size_t)port));
}

static void
READ_PORT_BUFFER_ULONG(uint32_t *port, uint32_t *buffer, uint32_t count)
{
	bus_space_read_multi_4(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static void
READ_PORT_BUFFER_USHORT(uint16_t *port, uint16_t *buffer, uint32_t count)
{
	bus_space_read_multi_2(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

static void
READ_PORT_BUFFER_UCHAR(uint8_t *port, uint8_t *buffer, uint32_t count)
{
	bus_space_read_multi_1(NDIS_BUS_SPACE_IO, 0x0,
	    (bus_size_t)port, buffer, count);
}

uint8_t
KfAcquireSpinLock(kspin_lock *lock)
{
	uint8_t oldirql;

	KeRaiseIrql(DISPATCH_LEVEL, &oldirql);
	KeAcquireSpinLockAtDpcLevel(lock);

	return (oldirql);
}

void
KfReleaseSpinLock(kspin_lock *lock, uint8_t newirql)
{
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
	if (freq != NULL)
		*freq = hz;

	return ((uint64_t)ticks);
}

uint8_t
KfRaiseIrql(uint8_t newirql)
{
	uint8_t oldirql;

	oldirql = KeGetCurrentIrql();

	KASSERT(oldirql <= newirql, ("newirql not less"));
	if (oldirql != DISPATCH_LEVEL) {
		sched_pin();
		mtx_lock(&disp_lock);
	}
	return (oldirql);
}

void
KfLowerIrql(uint8_t oldirql)
{
	if (oldirql == DISPATCH_LEVEL)
		return;

	KASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL, ("irql not greater"));
	mtx_unlock(&disp_lock);
	sched_unpin();
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
	IMPORT_SFUNC(KeStallExecutionProcessor, 1),
	IMPORT_SFUNC(WRITE_PORT_ULONG, 2),
	IMPORT_SFUNC(WRITE_PORT_USHORT, 2),
	IMPORT_SFUNC(WRITE_PORT_UCHAR, 2),
	IMPORT_SFUNC(WRITE_PORT_BUFFER_ULONG, 3),
	IMPORT_SFUNC(WRITE_PORT_BUFFER_USHORT, 3),
	IMPORT_SFUNC(WRITE_PORT_BUFFER_UCHAR, 3),
	IMPORT_SFUNC(READ_PORT_ULONG, 1),
	IMPORT_SFUNC(READ_PORT_USHORT, 1),
	IMPORT_SFUNC(READ_PORT_UCHAR, 1),
	IMPORT_SFUNC(READ_PORT_BUFFER_ULONG, 3),
	IMPORT_SFUNC(READ_PORT_BUFFER_USHORT, 3),
	IMPORT_SFUNC(READ_PORT_BUFFER_UCHAR, 3),
	IMPORT_FFUNC(KfAcquireSpinLock, 1),
	IMPORT_FFUNC(KfReleaseSpinLock, 1),
	IMPORT_SFUNC(KeGetCurrentIrql, 0),
	IMPORT_SFUNC(KeQueryPerformanceCounter, 1),
	IMPORT_FFUNC(KfLowerIrql, 1),
	IMPORT_FFUNC(KfRaiseIrql, 1),
	IMPORT_SFUNC(KeRaiseIrqlToDpcLevel, 0),
#undef KeLowerIrql
	IMPORT_SFUNC_MAP(KeLowerIrql, _KeLowerIrql, 1),

	/*
	 * This last entry is a catch-all for any function we haven't
	 * implemented yet. The PE import list patching routine will
	 * use it for any function that doesn't have an explicit match
	 * in this table.
	 */
	{ NULL, (FUNC)dummy, NULL, 0, WINDRV_WRAP_STDCALL },
	{ NULL, NULL, NULL }
};
