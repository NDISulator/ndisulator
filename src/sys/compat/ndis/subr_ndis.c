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

/*
 * This file implements a translation layer between the BSD networking
 * infrasturcture and Windows(R) NDIS network driver modules. A Windows
 * NDIS driver calls into several functions in the NDIS.SYS Windows
 * kernel module and exports a table of functions designed to be called
 * by the NDIS subsystem. Using the PE loader, we can patch our own
 * versions of the NDIS routines into a given Windows driver module and
 * convince the driver that it is in fact running on Windows.
 *
 * We provide a table of all our implemented NDIS routines which is patched
 * into the driver object code. All our exported routines must use the
 * _stdcall calling convention, since that's what the Windows object code
 * expects.
 */

#include <sys/ctype.h>
#include <sys/param.h>

#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/timespec.h>
#include <sys/smp.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/sysproto.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <machine/_inttypes.h>
#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/resource.h>

#include <sys/bus.h>
#include <sys/rman.h>

#include <machine/stdarg.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/hal_var.h>
#include <compat/ndis/ndis_var.h>
#include <dev/if_ndis/if_ndisvar.h>

static funcptr ndis_timercall_wrap;
static funcptr ndis_asyncmem_complete_wrap;
static funcptr ndis_interrupt_nic_wrap;
static funcptr ndis_intrhand_wrap;
static char ndis_filepath[] = "/compat/ndis";

static void NdisInitializeWrapper(void **, struct driver_object *, void *,
    void *);
static int32_t NdisMRegisterMiniport(struct driver_object *,
    struct ndis_miniport_characteristics *, uint32_t);
static int32_t NdisAllocateMemoryWithTag(void **, uint32_t, uint32_t);
static void *NdisAllocateMemoryWithTagPriority(struct ndis_miniport_block *,
    uint32_t, uint32_t, uint32_t);
static int32_t NdisAllocateTimerObject(struct ndis_miniport_block *,
    struct ndis_timer_characteristics *, void **);
static struct io_workitem * NdisAllocateIoWorkItem(struct device_object *);
static void NdisFreeIoWorkItem(struct io_workitem *);
static void NdisQueueIoWorkItem(struct io_workitem *, io_workitem_func, void *);
static int32_t NdisAllocateMemory(void **, uint32_t, uint32_t, uint64_t);
static void NdisFreeMemory(void *, uint32_t, uint32_t);
static int32_t NdisMSetAttributesEx(struct ndis_miniport_block *, void *,
    uint32_t, uint32_t, enum ndis_bus_type);
static void NdisOpenConfiguration(int32_t *, struct ndis_miniport_block **,
    struct ndis_miniport_block *);
static void NdisOpenConfigurationKeyByIndex(int32_t *, void *,
    uint32_t, struct unicode_string *, void **);
static void NdisOpenConfigurationKeyByName(int32_t *, void *,
    struct unicode_string *, void **);
static int32_t ndis_encode_parm(struct ndis_miniport_block *,
    struct sysctl_oid *, enum ndis_parameter_type,
    struct ndis_configuration_parameter **);
static int32_t ndis_decode_parm(struct ndis_miniport_block *,
    struct ndis_configuration_parameter *, char *);
static void NdisReadConfiguration(int32_t *,
    struct ndis_configuration_parameter **, struct ndis_miniport_block *,
    struct unicode_string *, enum ndis_parameter_type);
static void NdisWriteConfiguration(int32_t *, struct ndis_miniport_block *,
    struct unicode_string *, struct ndis_configuration_parameter *);
static void NdisCloseConfiguration(struct ndis_miniport_block *);
static void NdisAllocateSpinLock(struct ndis_spin_lock *);
static void NdisFreeSpinLock(struct ndis_spin_lock *);
static void NdisAcquireSpinLock(struct ndis_spin_lock *);
static void NdisReleaseSpinLock(struct ndis_spin_lock *);
static void NdisDprAcquireSpinLock(struct ndis_spin_lock *);
static void NdisDprReleaseSpinLock(struct ndis_spin_lock *);
static void NdisInitializeReadWriteLock(struct ndis_rw_lock *);
static void NdisAcquireReadWriteLock(struct ndis_rw_lock *, uint8_t,
    struct ndis_lock_state *);
static void NdisReleaseReadWriteLock(struct ndis_rw_lock *,
    struct ndis_lock_state *);
static uint32_t NdisReadPciSlotInformation(struct ndis_miniport_block *,
    uint32_t, uint32_t, void *, uint32_t);
static uint32_t NdisWritePciSlotInformation(struct ndis_miniport_block *,
    uint32_t, uint32_t, void *, uint32_t);
static void NdisMCloseLog(void *);
static int32_t NdisMCreateLog(void *, uint32_t, void *);
static void NdisMFlushLog(void *);
static int32_t NdisMWriteLogData(void *, void *, uint32_t);
static void NdisWriteErrorLogEntry(struct ndis_miniport_block *,
    uint32_t, uint32_t, ...);
static int32_t NdisWriteEventLogEntry(void *, int32_t, uint32_t, uint16_t,
    void *, uint32_t, void *);
static bus_addr_t ndis_dmasize(uint8_t dmasize);
static void ndis_map_cb(void *, bus_dma_segment_t *, int, int);
static void NdisMStartBufferPhysicalMapping(struct ndis_miniport_block *,
    struct mdl *, uint32_t, uint8_t, struct ndis_paddr_unit *, uint32_t *);
static void NdisMCompleteBufferPhysicalMapping(struct ndis_miniport_block *,
    struct mdl *, uint32_t);
static void NdisMInitializeTimer(struct ndis_miniport_timer *,
    struct ndis_miniport_block *, ndis_timer_function, void *);
static void NdisInitializeTimer(struct ndis_timer *, ndis_timer_function,
    void *);
static void NdisCancelTimer(struct ndis_timer *, uint8_t *);
static uint8_t NdisCancelTimerObject(struct ndis_timer *);
static void NdisSetTimer(struct ndis_timer *, uint32_t);
static uint8_t NdisSetTimerObject(struct ndis_timer *, int64_t, uint32_t, void *);
static int32_t NdisScheduleWorkItem(struct ndis_work_item *);
static void NdisMSetPeriodicTimer(struct ndis_miniport_timer *, uint32_t);
static void NdisMSleep(uint32_t);
static void NdisMCancelTimer(struct ndis_miniport_timer *, uint8_t *);
static void ndis_timercall(struct nt_kdpc *, struct ndis_miniport_timer *,
    void *, void *);
static void NdisMQueryAdapterResources(int32_t *, struct ndis_miniport_block *,
    struct cm_partial_resource_list *, uint32_t *);
static int32_t NdisMRegisterIoPortRange(void **, struct ndis_miniport_block *,
    uint32_t, uint32_t);
static void NdisMDeregisterIoPortRange(struct ndis_miniport_block *,
    uint32_t, uint32_t, void *);
static void NdisReadNetworkAddress(int32_t *, void **, uint32_t *,
    struct ndis_miniport_block *);
static int32_t NdisMAllocateMapRegisters(struct ndis_miniport_block *,
    uint32_t, uint8_t, uint32_t, uint32_t);
static void NdisMFreeMapRegisters(struct ndis_miniport_block *);
static void ndis_mapshared_cb(void *, bus_dma_segment_t *, int, int);
static void NdisMAllocateSharedMemory(struct ndis_miniport_block *,
    uint32_t, uint8_t, void **, uint64_t *);
static void ndis_asyncmem_complete(struct device_object *, void *);
static int32_t NdisMAllocateSharedMemoryAsync(struct ndis_miniport_block *,
    uint32_t, uint8_t, void *);
static void NdisMFreeSharedMemory(struct ndis_miniport_block *,
    uint32_t, uint8_t, void *, uint64_t);
static int32_t NdisMMapIoSpace(void **, struct ndis_miniport_block *,
    uint64_t, uint32_t);
static void NdisMUnmapIoSpace(struct ndis_miniport_block *, void *, uint32_t);
static uint32_t NdisGetCacheFillSize(void);
static void *NdisGetRoutineAddress(struct unicode_string *);
static uint32_t NdisMGetDmaAlignment(struct ndis_miniport_block *);
static int32_t NdisMInitializeScatterGatherDma(struct ndis_miniport_block *,
    uint8_t, uint32_t);
static void NdisUnchainBufferAtFront(struct ndis_packet *, struct mdl **);
static void NdisUnchainBufferAtBack(struct ndis_packet *, struct mdl **);
static void NdisAllocateBufferPool(int32_t *, void **, uint32_t);
static void NdisFreeBufferPool(void *);
static void NdisAllocateBuffer(int32_t *, struct mdl **, void *, void *,
    uint32_t);
static void NdisFreeBuffer(struct mdl *);
static uint32_t NdisBufferLength(struct mdl *);
static uint32_t NdisPacketPoolUsage(struct ndis_packet_pool *);
static void NdisQueryBuffer(struct mdl *, void **, uint32_t *);
static void NdisQueryBufferSafe(struct mdl *, void **, uint32_t *, uint32_t);
static void *NdisBufferVirtualAddress(struct mdl *);
static void *NdisBufferVirtualAddressSafe(struct mdl *, uint32_t);
static void NdisAdjustBufferLength(struct mdl *, uint32_t);
static int32_t NdisInterlockedIncrement(int32_t *);
static int32_t NdisInterlockedDecrement(int32_t *);
static void NdisInitializeEvent(struct ndis_event *);
static void NdisSetEvent(struct ndis_event *);
static void NdisResetEvent(struct ndis_event *);
static uint8_t NdisWaitEvent(struct ndis_event *, uint32_t);
static int32_t NdisUnicodeStringToAnsiString(struct ansi_string *,
    struct unicode_string *);
static int32_t NdisUpcaseUnicodeString(struct unicode_string *,
    struct unicode_string *);
static int32_t NdisAnsiStringToUnicodeString(struct unicode_string *,
    struct ansi_string *);
static int32_t NdisMPciAssignResources(struct ndis_miniport_block *,
    uint32_t, struct cm_partial_resource_list **);
static int32_t NdisMRegisterInterrupt(struct ndis_miniport_interrupt *,
    struct ndis_miniport_block *, uint32_t, uint32_t, uint8_t, uint8_t,
    enum ndis_interrupt_mode);
static void NdisMDeregisterInterrupt(struct ndis_miniport_interrupt *);
static void NdisMRegisterAdapterShutdownHandler(struct ndis_miniport_block *,
    void *, ndis_shutdown_func);
static void NdisMDeregisterAdapterShutdownHandler(struct ndis_miniport_block *);
static uint32_t NDIS_BUFFER_TO_SPAN_PAGES(struct mdl *);
static void NdisGetBufferPhysicalArraySize(struct mdl *, uint32_t *);
static void NdisQueryBufferOffset(struct mdl *, uint32_t *, uint32_t *);
static uint32_t NdisReadPcmciaAttributeMemory(struct ndis_miniport_block *,
    uint32_t, void *, uint32_t);
static uint32_t NdisWritePcmciaAttributeMemory(struct ndis_miniport_block *,
    uint32_t, void *, uint32_t);
static struct list_entry *NdisInterlockedInsertHeadList(struct list_entry *,
    struct list_entry *, struct ndis_spin_lock *);
static struct list_entry *NdisInterlockedRemoveHeadList(struct list_entry *,
    struct ndis_spin_lock *);
static struct list_entry *NdisInterlockedInsertTailList(struct list_entry *,
    struct list_entry *, struct ndis_spin_lock *);
static uint8_t NdisMSynchronizeWithInterrupt(struct ndis_miniport_interrupt *,
    void *, void *);
static void NdisGetCurrentSystemTime(int64_t *);
static void NdisGetSystemUpTime(uint32_t *);
static void NdisGetSystemUpTimeEx(int64_t *);
static uint32_t NdisGetVersion(void);
static void NdisInitializeString(struct unicode_string *, char *);
static void NdisInitAnsiString(struct ansi_string *, char *);
static void NdisInitUnicodeString(struct unicode_string *, uint16_t *);
static void NdisFreeString(struct unicode_string *);
static void NdisFreeTimerObject(struct ndis_timer *);
static int32_t NdisMRemoveMiniport(struct ndis_miniport_block *);
static void NdisTerminateWrapper(struct driver_object *, void *);
static void NdisMGetDeviceProperty(struct ndis_miniport_block *block,
    struct device_object **, struct device_object **, struct device_object **,
    struct cm_resource_list *, struct cm_resource_list *);
static void NdisGetFirstBufferFromPacket(struct ndis_packet *, struct mdl **,
    void **, uint32_t *, uint32_t *);
static void NdisGetFirstBufferFromPacketSafe(struct ndis_packet *,
    struct mdl **, void **, uint32_t *, uint32_t *, uint32_t);
static int ndis_find_sym(linker_file_t, char *, char *, caddr_t *);
static void NdisOpenFile(int32_t *, struct ndis_file_handle **, uint32_t *,
    struct unicode_string *, uint64_t);
static void NdisMapFile(int32_t *, void **, struct ndis_file_handle *);
static void NdisUnmapFile(struct ndis_file_handle *);
static void NdisCloseFile(struct ndis_file_handle *);
static uint8_t NdisSystemProcessorCount(void);
static void NdisGetCurrentProcessorCounts(uint32_t *, uint32_t *, uint32_t *);
static void NdisMIndicateStatusComplete(struct ndis_miniport_block *);
static void NdisMIndicateStatus(struct ndis_miniport_block *, int32_t, void *,
    uint32_t);
static uint8_t ndis_interrupt_nic(struct nt_kinterrupt *, struct ndis_softc *);
static void ndis_intrhand(struct nt_kdpc *, struct ndis_miniport_interrupt *,
    void *, void *);
static void NdisCopyFromPacketToPacket(struct ndis_packet *, uint32_t, uint32_t,
    struct ndis_packet *, uint32_t, uint32_t *);
static void NdisCopyFromPacketToPacketSafe(struct ndis_packet *, uint32_t,
    uint32_t, struct ndis_packet *, uint32_t, uint32_t *, uint32_t);
static void NdisIMCopySendPerPacketInfo(struct ndis_packet *,
    struct ndis_packet *);
static int32_t NdisMRegisterDevice(struct driver_object *,
    struct unicode_string *, struct unicode_string *,
    driver_dispatch **, void **, void **);
static int32_t NdisMDeregisterDevice(struct device_object *);
static int32_t NdisMQueryAdapterInstanceName(struct unicode_string *,
    struct ndis_miniport_block *);
static void NdisMRegisterUnloadHandler(struct driver_object *, void *);
static void dummy(void);

MALLOC_DEFINE(M_NDIS_SUBR, "ndis_subr", "ndis_subr buffers");

void
ndis_libinit(void)
{

	windrv_wrap((funcptr)ndis_timercall,
	    &ndis_timercall_wrap, 4, STDCALL);
	windrv_wrap((funcptr)ndis_asyncmem_complete,
	    &ndis_asyncmem_complete_wrap, 2, STDCALL);
	windrv_wrap((funcptr)ndis_interrupt_nic,
	    &ndis_interrupt_nic_wrap, 2, STDCALL);
	windrv_wrap((funcptr)ndis_intrhand,
	    &ndis_intrhand_wrap, 4, STDCALL);
	windrv_wrap_table(ndis_functbl);
}

void
ndis_libfini(void)
{

	windrv_unwrap_table(ndis_functbl);
	windrv_unwrap(ndis_intrhand_wrap);
	windrv_unwrap(ndis_interrupt_nic_wrap);
	windrv_unwrap(ndis_asyncmem_complete_wrap);
	windrv_unwrap(ndis_timercall_wrap);
}

static void
NdisInitializeWrapper(void **wrapper, struct driver_object *drv,
    void *path, void *unused)
{
	TRACE(NDBG_INIT, "wrapper %p drv %p\n", wrapper, drv);
	*wrapper = drv;
}

static void
NdisTerminateWrapper(struct driver_object *drv, void *syspec)
{
	TRACE(NDBG_INIT, "drv %p\n", drv);
}

static int32_t
NdisMRegisterMiniport(struct driver_object *drv,
    struct ndis_miniport_characteristics *characteristics, uint32_t len)
{
	struct ndis_miniport_characteristics *ch = NULL;

	TRACE(NDBG_INIT, "drv %p characteristics %p len %u\n",
	    drv, characteristics, len);
	if (characteristics->version_major < 4)
		return (NDIS_STATUS_BAD_VERSION);

	/*
	 * We must save the NDIS miniport characteristics somewhere.
	 * This data is per-driver, not per-device (all devices handled
	 * by the same driver have the same characteristics) so we hook
	 * it onto the driver object using IoAllocateDriverObjectExtension().
	 * The extra extension info is automagically deleted when
	 * the driver is unloaded (see windrv_unload()).
	 */
	if (IoAllocateDriverObjectExtension(drv, (void *)1,
	    sizeof(struct ndis_miniport_characteristics),
	    (void **)&ch) != NDIS_STATUS_SUCCESS)
		return (NDIS_STATUS_RESOURCES);

	memcpy(ch, characteristics, len);
	return (NDIS_STATUS_SUCCESS);
}

static struct io_workitem *
NdisAllocateIoWorkItem(struct device_object *dobj)
{
	return (IoAllocateWorkItem(dobj));
}

static int32_t
NdisAllocateTimerObject(struct ndis_miniport_block *block,
    struct ndis_timer_characteristics *timer_chars, void **timer_object)
{
	TRACE(NDBG_TIMER, "block %p timer_chars %p\n", block, timer_chars);
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisFreeIoWorkItem(struct io_workitem *iw)
{
	IoFreeWorkItem(iw);
}

static void
NdisFreeTimerObject(struct ndis_timer *timer)
{
	TRACE(NDBG_TIMER, "timer %p\n", timer);
}

static void
NdisQueueIoWorkItem(struct io_workitem *iw, io_workitem_func iw_func, void *ctx)
{
	IoQueueWorkItem(iw, iw_func, DELAYED, ctx);
}

static int32_t
NdisAllocateMemoryWithTag(void **vaddr, uint32_t len, uint32_t tag)
{
	TRACE(NDBG_MEM, "vaddr %p len %u tag %u\n", vaddr, len, tag);
	*vaddr = malloc(len, M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (*vaddr == NULL)
		return (NDIS_STATUS_FAILURE);
	return (NDIS_STATUS_SUCCESS);
}

static void *
NdisAllocateMemoryWithTagPriority(struct ndis_miniport_block *block,
    uint32_t len, uint32_t tag, uint32_t priority)
{
	TRACE(NDBG_MEM, "block %p len %u tag %u priority %u\n",
	    block, len, tag, priority);
	return (malloc(len, M_NDIS_SUBR, M_NOWAIT|M_ZERO));
}

static int32_t
NdisAllocateMemory(void **vaddr, uint32_t len, uint32_t flags, uint64_t high)
{
	TRACE(NDBG_MEM, "len %u flags %u high %"PRIu64"\n", len, flags, high);
	return (NdisAllocateMemoryWithTag(vaddr, len, 0));
}

static void
NdisFreeMemory(void *vaddr, uint32_t len, uint32_t flags)
{
	TRACE(NDBG_MEM, "vaddr %p len %u flags %u\n", vaddr, len, flags);
	free(vaddr, M_NDIS_SUBR);
}

static int32_t
NdisMSetAttributesEx(struct ndis_miniport_block *block, void *adapter_ctx,
    uint32_t hangsecs, uint32_t flags, enum ndis_bus_type bus_type)
{
	TRACE(NDBG_INIT, "block %p hangsecs %u flags %08X bus %d\n",
	    block, hangsecs, flags, bus_type);
	KASSERT(block != NULL, ("no block"));
	block->miniport_adapter_ctx = adapter_ctx;
	block->check_for_hang_secs = hangsecs ? hangsecs * 2 : 4;
	block->bus_type = bus_type;
	block->flags = flags;

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisOpenConfiguration(int32_t *status, struct ndis_miniport_block **block,
    struct ndis_miniport_block *wrapctx)
{
	TRACE(NDBG_CFG, "block %p wrapctx %p\n", block, wrapctx);
	KASSERT(block != NULL, ("no block"));
	*block = wrapctx;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisOpenConfigurationKeyByName(int32_t *status, void *cfg,
    struct unicode_string *subkey, void **subhandle)
{
	TRACE(NDBG_CFG, "cfg %p\n", cfg);
	*subhandle = cfg;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisOpenConfigurationKeyByIndex(int32_t *status, void  *cfg,
    uint32_t idx, struct unicode_string *subkey, void **subhandle)
{
	TRACE(NDBG_CFG, "cfg %p idx %u\n", cfg, idx);
	*status = NDIS_STATUS_FAILURE;
}

static int32_t
ndis_encode_parm(struct ndis_miniport_block *block, struct sysctl_oid *oid,
    enum ndis_parameter_type type, struct ndis_configuration_parameter **parm)
{
	struct ndis_configuration_parameter *p;
	struct ndis_parmlist_entry *np;
	struct ansi_string as;

	np = malloc(sizeof(struct ndis_parmlist_entry),
	    M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (np == NULL)
		return (NDIS_STATUS_RESOURCES);
	InsertHeadList((&block->parmlist), (&np->list));
	*parm = p = &np->parm;
	p->type = type;

	switch (type) {
	case NDIS_PARAMETER_STRING:
		RtlInitAnsiString(&as, (char *)oid->oid_arg1);
		if (RtlAnsiStringToUnicodeString(&p->data.string, &as, TRUE)) {
			free(np, M_NDIS_SUBR);
			return (NDIS_STATUS_RESOURCES);
		}
		break;
	case NDIS_PARAMETER_INTEGER:
		p->data.integer = strtol((char *)oid->oid_arg1, NULL, 0);
		break;
	case NDIS_PARAMETER_HEX_INTEGER:
		p->data.integer = strtoul((char *)oid->oid_arg1, NULL, 16);
		break;
	case NDIS_PARAMETER_BINARY:
		p->data.integer = strtoul((char *)oid->oid_arg1, NULL, 2);
		break;
	default:
		return (NDIS_STATUS_FAILURE);
	}
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisReadConfiguration(int32_t *status,
    struct ndis_configuration_parameter **parm,
    struct ndis_miniport_block *block, struct unicode_string *key,
    enum ndis_parameter_type type)
{
	struct sysctl_ctx_entry *e;
	struct ansi_string as;
	struct ndis_softc *sc;
	struct sysctl_oid *oidp;

	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));

	if (key->len == 0 || key->buf == NULL) {
		*status = NDIS_STATUS_FAILURE;
		return;
	}

	if (RtlUnicodeStringToAnsiString(&as, key, TRUE)) {
		*status = NDIS_STATUS_RESOURCES;
		return;
	}

	TRACE(NDBG_CFG, "block %p key %s type %u\n", block, as.buf, type);

	/*
	 * See if registry key is already in a list of known keys
	 * included with the driver.
	 */
	sc = device_get_softc(block->physdeviceobj->devext);
	TAILQ_FOREACH(e, device_get_sysctl_ctx(sc->ndis_dev), link) {
		oidp = e->entry;
		if (strcasecmp(oidp->oid_name, as.buf) == 0) {
			if (strcmp((char *)oidp->oid_arg1, "UNSET") == 0) {
				RtlFreeAnsiString(&as);
				*status = NDIS_STATUS_FAILURE;
				return;
			}

			*status = ndis_encode_parm(block, oidp, type, parm);
			RtlFreeAnsiString(&as);
			return;
		}
	}

	/*
	 * If the key didn't match, add it to the list of dynamically
	 * created ones. Sometimes, drivers refer to registry keys
	 * that aren't documented in their .INF files. These keys
	 * are supposed to be created by some sort of utility or
	 * control panel snap-in that comes with the driver software.
	 * Sometimes it's useful to be able to manipulate these.
	 * If the driver requests the key in the form of a string,
	 * make its default value an empty string, otherwise default
	 * it to "0".
	 */
	if (type == NDIS_PARAMETER_INTEGER)
		ndis_add_sysctl(sc, as.buf, "(dynamic decimal key)",
		    "UNSET", CTLFLAG_RW);
	else if (type == NDIS_PARAMETER_HEX_INTEGER)
		ndis_add_sysctl(sc, as.buf, "(dynamic hexadecimal key)",
		    "UNSET", CTLFLAG_RW);
	else if (type == NDIS_PARAMETER_BINARY)
		ndis_add_sysctl(sc, as.buf, "(dynamic binary key)",
		    "UNSET", CTLFLAG_RW);
	else
		ndis_add_sysctl(sc, as.buf, "(dynamic string key)",
		    "UNSET", CTLFLAG_RW);

	RtlFreeAnsiString(&as);
	*status = NDIS_STATUS_FAILURE;
}

static int32_t
ndis_decode_parm(struct ndis_miniport_block *block,
    struct ndis_configuration_parameter *parm, char *val)
{
	struct ansi_string as;
	struct unicode_string *ustr;

	switch (parm->type) {
	case NDIS_PARAMETER_STRING:
		ustr = &parm->data.string;
		if (RtlUnicodeStringToAnsiString(&as, ustr, TRUE))
			return (NDIS_STATUS_RESOURCES);
		memcpy(val, as.buf, as.len);
		RtlFreeAnsiString(&as);
		break;
	case NDIS_PARAMETER_INTEGER:
		snprintf(val, sizeof(uint32_t), "%d", parm->data.integer);
		break;
	case NDIS_PARAMETER_HEX_INTEGER:
		snprintf(val, sizeof(uint32_t), "%x", parm->data.integer);
		break;
	case NDIS_PARAMETER_BINARY:
		snprintf(val, sizeof(uint32_t), "%u", parm->data.integer);
		break;
	default:
		return (NDIS_STATUS_FAILURE);
	}
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisWriteConfiguration(int32_t *status, struct ndis_miniport_block *block,
    struct unicode_string *key, struct ndis_configuration_parameter *parm)
{
	struct ansi_string as;
	struct ndis_softc *sc;
	struct sysctl_oid *oidp;
	struct sysctl_ctx_entry *e;
	char val[256];

	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));

	if (RtlUnicodeStringToAnsiString(&as, key, TRUE)) {
		*status = NDIS_STATUS_RESOURCES;
		return;
	}

	TRACE(NDBG_CFG, "block %p key %s\n", block, as.buf);

	memset(val, 0, sizeof(val));
	*status = ndis_decode_parm(block, parm, val);
	if (*status != NDIS_STATUS_SUCCESS) {
		RtlFreeAnsiString(&as);
		return;
	}

	sc = device_get_softc(block->physdeviceobj->devext);
	TAILQ_FOREACH(e, device_get_sysctl_ctx(sc->ndis_dev), link) {
		oidp = e->entry;
		if (strcasecmp(oidp->oid_name, as.buf) == 0) {
			strcpy((char *)oidp->oid_arg1, val);
			RtlFreeAnsiString(&as);
			return;
		}
	}

	ndis_add_sysctl(sc, as.buf, "(dynamically set key)", val, CTLFLAG_RW);
	RtlFreeAnsiString(&as);
}

static void
NdisCloseConfiguration(struct ndis_miniport_block *block)
{
	struct ndis_parmlist_entry *pe;
	struct ndis_configuration_parameter *p;
	struct list_entry *e;

	TRACE(NDBG_CFG, "block %p\n", block);
	KASSERT(block != NULL, ("no block"));
	while (!IsListEmpty(&block->parmlist)) {
		e = RemoveHeadList(&block->parmlist);
		pe = CONTAINING_RECORD(e, struct ndis_parmlist_entry, list);
		p = &pe->parm;
		if (p->type == NDIS_PARAMETER_STRING)
			RtlFreeUnicodeString(&p->data.string);
		free(e, M_NDIS_SUBR);
	}
}

static void
NdisAllocateSpinLock(struct ndis_spin_lock *lock)
{
	KeInitializeSpinLock(&lock->spinlock);
	lock->kirql = PASSIVE_LEVEL;
}

static void
NdisFreeSpinLock(struct ndis_spin_lock *lock)
{
}

static void
NdisAcquireSpinLock(struct ndis_spin_lock *lock)
{
	KeAcquireSpinLock(&lock->spinlock, &lock->kirql);
}

static void
NdisReleaseSpinLock(struct ndis_spin_lock *lock)
{
	KeReleaseSpinLock(&lock->spinlock, lock->kirql);
}

static void
NdisDprAcquireSpinLock(struct ndis_spin_lock *lock)
{
	KeAcquireSpinLockAtDpcLevel(&lock->spinlock);
}

static void
NdisDprReleaseSpinLock(struct ndis_spin_lock *lock)
{
	KeReleaseSpinLockFromDpcLevel(&lock->spinlock);
}

static void
NdisInitializeReadWriteLock(struct ndis_rw_lock *lock)
{
	KeInitializeSpinLock(&lock->u.spinlock);
	memset(&lock->reserved, 0, sizeof(lock->reserved));
}

static void
NdisAcquireReadWriteLock(struct ndis_rw_lock *lock, uint8_t writeacc,
    struct ndis_lock_state *state)
{
	if (writeacc == TRUE) {
		KeAcquireSpinLock(&lock->u.spinlock, &state->oldirql);
		lock->reserved[0]++;
	} else
		lock->reserved[1]++;
}

static void
NdisReleaseReadWriteLock(struct ndis_rw_lock *lock,
    struct ndis_lock_state *state)
{
	if (lock->reserved[0]) {
		lock->reserved[0]--;
		KeReleaseSpinLock(&lock->u.spinlock, state->oldirql);
	} else
		lock->reserved[1]--;
}

static uint32_t
NdisReadPciSlotInformation(struct ndis_miniport_block *block, uint32_t slot,
    uint32_t offset, void *buf, uint32_t len)
{
	int i;
	char *dest = buf;

	TRACE(NDBG_PCI, "block %p slot %u offset %u len %u\n",
	    block, slot, offset, len);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	for (i = 0; i < len; i++)
		dest[i] = pci_read_config(block->physdeviceobj->devext,
		    i + offset, 1);
	return (len);
}

static uint32_t
NdisWritePciSlotInformation(struct ndis_miniport_block *block, uint32_t slot,
    uint32_t offset, void *buf, uint32_t len)
{
	int i;
	char *dest = buf;

	TRACE(NDBG_PCI, "block %p slot %u offset %u len %u\n",
	    block, slot, offset, len);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	for (i = 0; i < len; i++)
		pci_write_config(block->physdeviceobj->devext,
		    i + offset, dest[i], 1);
	return (len);
}

static void NdisMCloseLog(void *log)
{
	TRACE(NDBG_LOG, "log %p\n", log);
}

static int32_t
NdisMCreateLog(void *handle, uint32_t size, void *log)
{
	TRACE(NDBG_LOG, "handle %p size %u log %p\n", handle, size, log);
	return (NDIS_STATUS_SUCCESS);
}

static int32_t
NdisMWriteLogData(void *log, void *buffer, uint32_t size)
{
	TRACE(NDBG_LOG, "log %p size %u\n", log, size);
	return (NDIS_STATUS_SUCCESS);
}

static void NdisMFlushLog(void *log)
{
	TRACE(NDBG_LOG, "log %p\n", log);
}

static int32_t
NdisWriteEventLogEntry(void *handle, int32_t code, uint32_t value, uint16_t n,
    void *strings, uint32_t datasize, void *data)
{
	TRACE(NDBG_LOG, "handle %p code 0x%x value 0x%x n %u datasize %u\n",
	    handle, code, value, n, datasize);
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisWriteErrorLogEntry(struct ndis_miniport_block *block, uint32_t code,
    uint32_t numerrors, ...)
{
	struct ifnet *ifp;
	struct ndis_softc *sc;
	struct driver_object *drv;
	device_t dev;
	va_list ap;
	int i;
	char *str = NULL;
	uint16_t flags;
	struct unicode_string us;
	struct ansi_string as = { 0, 0, NULL };

	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	dev = block->physdeviceobj->devext;
	drv = block->deviceobj->drvobj;
	sc = device_get_softc(dev);
	ifp = sc->ndis_ifp;

	if (ifp != NULL && ifp->if_flags & IFF_DEBUG) {
		if (pe_get_message((vm_offset_t)drv->driver_start,
		    code, &str, &i, &flags) == 0) {
			if (flags & MESSAGE_RESOURCE_UNICODE) {
				RtlInitUnicodeString(&us, (uint16_t *)str);
				if (RtlUnicodeStringToAnsiString(&as,
				    &us, TRUE) == NDIS_STATUS_SUCCESS)
					str = as.buf;
				else
					str = NULL;
			}
		}
	}

	device_printf(dev, "NDIS ERROR: %X (%s)\n", code,
	    str == NULL ? "unknown error" : str);

	if (ifp != NULL && ifp->if_flags & IFF_DEBUG) {
		device_printf(dev, "NDIS NUMERRORS: %X\n", numerrors);
		va_start(ap, numerrors);
		for (i = 0; i < numerrors; i++)
			device_printf(dev, "argptr: %p\n",
			    va_arg(ap, void *));
		va_end(ap);
	}

	if (as.len)
		RtlFreeAnsiString(&as);
}

static void
ndis_map_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct ndis_map_arg *ctx;
	int i;

	if (error)
		return;

	ctx = arg;

	for (i = 0; i < nseg; i++) {
		ctx->fraglist[i].physaddr = segs[i].ds_addr;
		ctx->fraglist[i].len = segs[i].ds_len;
	}

	ctx->cnt = nseg;
}

static void
NdisMStartBufferPhysicalMapping(struct ndis_miniport_block *block,
    struct mdl *buf, uint32_t mapreg, uint8_t writedev,
    struct ndis_paddr_unit *addrarray, uint32_t *arraysize)
{
	struct ndis_softc *sc;
	struct ndis_map_arg nma;
	bus_dmamap_t map;

	TRACE(NDBG_DMA, "block %p buf %p mapreg %u writedev %u addrarray %p "
	    "arraysize %p\n",
	    block, buf, mapreg, writedev, addrarray, arraysize);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));

	sc = device_get_softc(block->physdeviceobj->devext);
	if (mapreg > sc->ndis_mmapcnt)
		return;

	map = sc->ndis_mmaps[mapreg];
	nma.fraglist = addrarray;

	if (bus_dmamap_load(sc->ndis_mtag, map,
	    MmGetMdlVirtualAddress(buf), MmGetMdlByteCount(buf), ndis_map_cb,
	    (void *)&nma, BUS_DMA_NOWAIT) != 0)
		return;

	bus_dmamap_sync(sc->ndis_mtag, map,
	    writedev ? BUS_DMASYNC_PREWRITE : BUS_DMASYNC_PREREAD);

	*arraysize = nma.cnt;
}

static void
NdisMCompleteBufferPhysicalMapping(struct ndis_miniport_block *block,
    struct mdl *buf, uint32_t mapreg)
{
	struct ndis_softc *sc;
	bus_dmamap_t map;

	TRACE(NDBG_DMA, "block %p buf %p mapreg %u\n", block, buf, mapreg);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));

	sc = device_get_softc(block->physdeviceobj->devext);
	if (mapreg > sc->ndis_mmapcnt)
		return;

	map = sc->ndis_mmaps[mapreg];

	bus_dmamap_sync(sc->ndis_mtag, map,
	    BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE);

	bus_dmamap_unload(sc->ndis_mtag, map);
}

static void
NdisInitializeTimer(struct ndis_timer *timer, ndis_timer_function func,
    void *ctx)
{
	TRACE(NDBG_TIMER, "timer %p func %p ctx %p\n", timer, func, ctx);
	KeInitializeTimer(&timer->ktimer);
	KeInitializeDpc(&timer->kdpc, func, ctx);
	KeSetImportanceDpc(&timer->kdpc, IMPORTANCE_LOW);
}

static void
ndis_timercall(struct nt_kdpc *kdpc, struct ndis_miniport_timer *timer,
    void *sysarg1, void *sysarg2)
{
	/*
	 * Since we're called as a DPC, we should be running
	 * at DISPATCH_LEVEL here. This means to acquire the
	 * spinlock, we can use KeAcquireSpinLockAtDpcLevel()
	 * rather than KeAcquireSpinLock().
	 */
	if (NDIS_SERIALIZED(timer->block))
		KeAcquireSpinLockAtDpcLevel(&timer->block->lock);
	MSCALL4(timer->func, kdpc, timer->ctx, sysarg1, sysarg2);
	if (NDIS_SERIALIZED(timer->block))
		KeReleaseSpinLockFromDpcLevel(&timer->block->lock);
}

static void
NdisMInitializeTimer(struct ndis_miniport_timer *timer,
    struct ndis_miniport_block *block, ndis_timer_function func, void *ctx)
{
	TRACE(NDBG_TIMER, "timer %p block %p func %p ctx %p\n",
	    timer, block, func, ctx);
	KASSERT(block != NULL, ("no block"));

	/* Save the driver's funcptr and context */
	timer->func = func;
	timer->ctx = ctx;
	timer->block = block;

	/*
	 * Set up the timer so it will call our intermediate DPC.
	 * Be sure to use the wrapped entry point, since
	 * ntoskrnl_run_dpc() expects to invoke a function with
	 * Microsoft calling conventions.
	 */
	KeInitializeTimer(&timer->ktimer);
	KeInitializeDpc(&timer->kdpc, ndis_timercall_wrap, timer);
	timer->ktimer.dpc = &timer->kdpc;
}

static void
NdisCancelTimer(struct ndis_timer *timer, uint8_t *cancelled)
{
	KASSERT(timer != NULL, ("no timer"));
	*cancelled = KeCancelTimer(&timer->ktimer);
	TRACE(NDBG_TIMER, "timer %p cancelled %u\n", timer, *cancelled);
}

static uint8_t
NdisCancelTimerObject(struct ndis_timer *timer)
{
	KASSERT(timer != NULL, ("no timer"));
	TRACE(NDBG_TIMER, "timer %p\n", timer);
	return (KeCancelTimer(&timer->ktimer));
}

static void
NdisSetTimer(struct ndis_timer *timer, uint32_t msecs)
{
	TRACE(NDBG_TIMER, "timer %p msecs %u\n", timer, msecs);
	KASSERT(timer != NULL, ("no timer"));
	KeSetTimer(&timer->ktimer, ((int64_t)msecs * -10000), &timer->kdpc);
}

static uint8_t
NdisSetTimerObject(struct ndis_timer *timer, int64_t duetime, uint32_t msecs,
    void *ctx)
{
	TRACE(NDBG_TIMER, "timer %p duetime %"PRIu64" msecs %u ctx %p\n",
	    timer, duetime, msecs, ctx);
	return (TRUE);
}

static void
NdisMSetPeriodicTimer(struct ndis_miniport_timer *timer, uint32_t msecs)
{
	TRACE(NDBG_TIMER, "timer %p msecs %u\n", timer, msecs);
	KASSERT(timer != NULL, ("no timer"));
	KeSetTimerEx(&timer->ktimer,
	    ((int64_t)msecs * -10000), msecs, &timer->kdpc);
}

static void
NdisMCancelTimer(struct ndis_miniport_timer *timer, uint8_t *cancelled)
{
	KASSERT(timer != NULL, ("no timer"));
	*cancelled = KeCancelTimer(&timer->ktimer);
	TRACE(NDBG_TIMER, "timer %p cancelled %u\n", timer, *cancelled);
}

static void
NdisMQueryAdapterResources(int32_t *status, struct ndis_miniport_block *block,
    struct cm_partial_resource_list *list, uint32_t *buflen)
{
	struct ndis_softc *sc;
	uint32_t rsclen;

	TRACE(NDBG_INIT, "block %p list %p buflen %p\n", block, list, buflen);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);
	rsclen = sizeof(struct cm_partial_resource_list) +
	    (sizeof(struct cm_partial_resource_desc) * (sc->ndis_rescnt - 1));
	if (*buflen < rsclen) {
		*buflen = rsclen;
		*status = NDIS_STATUS_INVALID_LENGTH;
		return;
	}

	memcpy(list, block->rlist, rsclen);
	*status = NDIS_STATUS_SUCCESS;
}

static int32_t
NdisMRegisterIoPortRange(void **offset, struct ndis_miniport_block *block,
    uint32_t port, uint32_t numports)
{
	struct ndis_softc *sc;

	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);
	if (sc->ndis_res_io == NULL)
		return (NDIS_STATUS_FAILURE);

	/* Don't let the device map more ports than we have. */
	if (rman_get_size(sc->ndis_res_io) < numports)
		return (NDIS_STATUS_INVALID_LENGTH);

	*offset = (void *)rman_get_start(sc->ndis_res_io);

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMDeregisterIoPortRange(struct ndis_miniport_block *block, uint32_t port,
    uint32_t numports, void *offset)
{
}

static void
NdisReadNetworkAddress(int32_t *status, void **addr, uint32_t *addrlen,
    struct ndis_miniport_block *block)
{
	struct ndis_softc *sc;
	uint8_t empty[] = { 0, 0, 0, 0, 0, 0 };

	TRACE(NDBG_CFG, "block %p\n", block);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);
	if (sc->ndis_ifp == NULL) {
		*status = NDIS_STATUS_FAILURE;
		return;
	}

	if (sc->ndis_ifp->if_addr == NULL ||
	    bcmp(IF_LLADDR(sc->ndis_ifp), empty, ETHER_ADDR_LEN) == 0)
		*status = NDIS_STATUS_FAILURE;
	else {
		*addr = IF_LLADDR(sc->ndis_ifp);
		*addrlen = ETHER_ADDR_LEN;
		*status = NDIS_STATUS_SUCCESS;
	}
}

static bus_addr_t
ndis_dmasize(uint8_t dmasize)
{
	switch (dmasize) {
	case NDIS_DMA_24BITS:	return (BUS_SPACE_MAXADDR_24BIT);
	case NDIS_DMA_32BITS:	return (BUS_SPACE_MAXADDR_32BIT);
	case NDIS_DMA_64BITS:	return (BUS_SPACE_MAXADDR);
	}
	return (BUS_SPACE_MAXADDR_24BIT);
}

static int32_t
NdisMAllocateMapRegisters(struct ndis_miniport_block *block,
    uint32_t channel, uint8_t size, uint32_t basemap, uint32_t maxmap)
{
	struct ndis_softc *sc;
	int i, nseg = NDIS_MAXSEG;

	TRACE(NDBG_DMA, "block %p channel %u size %u basemap %u maxmap %u\n",
	    block, channel, size, basemap, maxmap);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);
	sc->ndis_mmaps = malloc(sizeof(bus_dmamap_t) * basemap,
	    M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (sc->ndis_mmaps == NULL)
		return (NDIS_STATUS_RESOURCES);

	if (bus_dma_tag_create(sc->ndis_parent_tag,
			ETHER_ALIGN, 0,
			ndis_dmasize(size),
			BUS_SPACE_MAXADDR,
			NULL, NULL,
			maxmap * nseg,
			nseg,
			maxmap,
			0,
			NULL,
			NULL,
			&sc->ndis_mtag) != 0) {
		free(sc->ndis_mmaps, M_NDIS_SUBR);
		return (NDIS_STATUS_RESOURCES);
	}

	for (i = 0; i < basemap; i++)
		bus_dmamap_create(sc->ndis_mtag, 0, &sc->ndis_mmaps[i]);

	sc->ndis_mmapcnt = basemap;

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMFreeMapRegisters(struct ndis_miniport_block *block)
{
	struct ndis_softc *sc;
	int i;

	TRACE(NDBG_DMA, "block %p\n", block);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);
	for (i = 0; i < sc->ndis_mmapcnt; i++)
		bus_dmamap_destroy(sc->ndis_mtag, sc->ndis_mmaps[i]);

	free(sc->ndis_mmaps, M_NDIS_SUBR);

	bus_dma_tag_destroy(sc->ndis_mtag);
}

static void
ndis_mapshared_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	uint64_t *paddr;

	if (error || nseg > 1)
		return;

	paddr = arg;
	*paddr = segs[0].ds_addr;
}

static void
NdisMAllocateSharedMemory(struct ndis_miniport_block *block, uint32_t len,
    uint8_t cached, void **vaddr, uint64_t *paddr)
{
	struct ndis_softc *sc;
	struct ndis_shmem *sh;

	TRACE(NDBG_DMA, "block %p len %u cached %u vaddr %p paddr %p\n",
	    block, len, cached, vaddr, paddr);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);

	sh = malloc(sizeof(struct ndis_shmem), M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (sh == NULL)
		return;

	InitializeListHead(&sh->ndis_list);

	if (bus_dma_tag_create(sc->ndis_parent_tag,
			ETHER_ALIGN, 0,
			BUS_SPACE_MAXADDR_32BIT,
			BUS_SPACE_MAXADDR,
			NULL, NULL,
			len,
			1,
			len,
			0,
			NULL,
			NULL,
			&sh->ndis_stag) != 0) {
		free(sh, M_NDIS_SUBR);
		return;
	}

	if (bus_dmamem_alloc(sh->ndis_stag, vaddr,
	    BUS_DMA_NOWAIT | BUS_DMA_ZERO, &sh->ndis_smap) != 0) {
		bus_dma_tag_destroy(sh->ndis_stag);
		free(sh, M_NDIS_SUBR);
		return;
	}

	if (bus_dmamap_load(sh->ndis_stag, sh->ndis_smap, *vaddr,
	    len, ndis_mapshared_cb, paddr, BUS_DMA_NOWAIT) != 0) {
		bus_dmamem_free(sh->ndis_stag, *vaddr, sh->ndis_smap);
		bus_dma_tag_destroy(sh->ndis_stag);
		free(sh, M_NDIS_SUBR);
		return;
	}

	/*
	 * Save the physical address along with the source address.
	 * The AirGo MIMO driver will call NdisMFreeSharedMemory()
	 * with a bogus virtual address sometimes, but with a valid
	 * physical address. To keep this from causing trouble, we
	 * use the physical address to as a sanity check in case
	 * searching based on the virtual address fails.
	 */
	NDIS_LOCK(sc);
	sh->ndis_paddr = *paddr;
	sh->ndis_saddr = *vaddr;
	InsertHeadList((&sc->ndis_shlist), (&sh->ndis_list));
	NDIS_UNLOCK(sc);
}

struct ndis_allocwork {
	uint32_t		len;
	uint8_t			cached;
	void			*ctx;
	struct io_workitem	*iw;
};

static void
ndis_asyncmem_complete(struct device_object *dobj, void *arg)
{
	struct ndis_miniport_block *block;
	struct ndis_softc *sc;
	struct ndis_allocwork *w = arg;
	uint64_t paddr;
	void *vaddr;

	block = (struct ndis_miniport_block *)dobj->devext;
	KASSERT(block != NULL, ("no block"));
	sc = device_get_softc(block->physdeviceobj->devext);

	vaddr = NULL;
	paddr = 0;

	NdisMAllocateSharedMemory(block, w->len, w->cached, &vaddr, &paddr);
	KASSERT(sc->ndis_chars->allocate_complete_func != NULL,
	    ("no allocate_complete"));
	MSCALL5(sc->ndis_chars->allocate_complete_func,
	    block, vaddr, &paddr, w->len, w->ctx);

	IoFreeWorkItem(w->iw);
	free(w, M_NDIS_SUBR);
}

static int32_t
NdisMAllocateSharedMemoryAsync(struct ndis_miniport_block *block,
    uint32_t len, uint8_t cached, void *ctx)
{
	struct ndis_allocwork *w;
	struct io_workitem *iw;
	io_workitem_func ifw;

	KASSERT(block != NULL, ("no block"));

	TRACE(NDBG_DMA, "block %p len %u cached %u\n", block, len, cached);
	w = malloc(sizeof(struct ndis_allocwork), M_NDIS_SUBR, M_NOWAIT);
	if (w == NULL)
		return (NDIS_STATUS_FAILURE);

	iw = IoAllocateWorkItem(block->deviceobj);
	if (iw == NULL) {
		free(w, M_NDIS_SUBR);
		return (NDIS_STATUS_FAILURE);
	}

	w->cached = cached;
	w->len = len;
	w->ctx = ctx;
	w->iw = iw;

	ifw = (io_workitem_func)ndis_asyncmem_complete_wrap;
	IoQueueWorkItem(iw, ifw, DELAYED, w);

	return (NDIS_STATUS_PENDING);
}

static void
NdisMFreeSharedMemory(struct ndis_miniport_block *block,
    uint32_t len, uint8_t cached, void *vaddr, uint64_t paddr)
{
	struct ndis_softc *sc;
	struct ndis_shmem *sh = NULL;
	struct list_entry *l;

	TRACE(NDBG_DMA, "block %p len %u cached %u vaddr %p paddr %"PRIu64"\n",
	    block, len, cached, vaddr, paddr);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));

	/* Sanity check: is list empty? */
	sc = device_get_softc(block->physdeviceobj->devext);
	if (IsListEmpty(&sc->ndis_shlist))
		return;

	NDIS_LOCK(sc);
	l = sc->ndis_shlist.flink;
	while (l != &sc->ndis_shlist) {
		sh = CONTAINING_RECORD(l, struct ndis_shmem, ndis_list);
		if (sh->ndis_saddr == vaddr)
			break;
		/*
		 * Check the physaddr too, just in case the driver lied
		 * about the virtual address.
		 */
		if (sh->ndis_paddr == paddr)
			break;
		l = l->flink;
	}

	if (sh == NULL) {
		NDIS_UNLOCK(sc);
		printf("NDIS: buggy driver tried to free "
		    "invalid shared memory: vaddr: %p paddr: 0x%jx\n",
		    vaddr, (uintmax_t)paddr);
		return;
	}

	RemoveEntryList(&sh->ndis_list);

	NDIS_UNLOCK(sc);

	bus_dmamap_unload(sh->ndis_stag, sh->ndis_smap);
	bus_dmamem_free(sh->ndis_stag, sh->ndis_saddr, sh->ndis_smap);
	bus_dma_tag_destroy(sh->ndis_stag);

	free(sh, M_NDIS_SUBR);
}

static int32_t
NdisMMapIoSpace(void **vaddr, struct ndis_miniport_block *block,
    uint64_t paddr, uint32_t len)
{
	struct ndis_softc *sc;

	TRACE(NDBG_MM, "vaddr %p block %p len %u\n", vaddr, block, len);

	sc = device_get_softc(block->physdeviceobj->devext);
	if (sc->ndis_res_mem != NULL &&
	    paddr == rman_get_start(sc->ndis_res_mem))
		*vaddr = (void *)rman_get_virtual(sc->ndis_res_mem);
	else if (sc->ndis_res_altmem != NULL &&
	    paddr == rman_get_start(sc->ndis_res_altmem))
		*vaddr = (void *)rman_get_virtual(sc->ndis_res_altmem);
	else if (sc->ndis_res_am != NULL &&
	    paddr == rman_get_start(sc->ndis_res_am))
		*vaddr = (void *)rman_get_virtual(sc->ndis_res_am);
	else
		return (NDIS_STATUS_FAILURE);
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMUnmapIoSpace(struct ndis_miniport_block *block, void *vaddr, uint32_t len)
{
	TRACE(NDBG_MM, "block %p vaddr %p len %u\n", block, vaddr, len);
}

static uint32_t
NdisGetCacheFillSize(void)
{
	return (ETHER_ALIGN);
}

static void *
NdisGetRoutineAddress(struct unicode_string *ustr)
{
	struct ansi_string astr;

	if (RtlUnicodeStringToAnsiString(&astr, ustr, TRUE))
		return (NULL);
	TRACE(NDBG_INIT, "routine %s\n", astr.buf);
	return (ndis_get_routine_address(ndis_functbl, astr.buf));
}

static uint32_t
NdisMGetDmaAlignment(struct ndis_miniport_block *block)
{
	return (ETHER_ALIGN);
}

/*
 * NDIS has two methods for dealing with NICs that support DMA.
 * One is to just pass packets to the driver and let it call
 * NdisMStartBufferPhysicalMapping() to map each buffer in the packet
 * all by itself, and the other is to let the NDIS library handle the
 * buffer mapping internally, and hand the driver an already populated
 * scatter/gather fragment list. If the driver calls
 * NdisMInitializeScatterGatherDma(), it wants to use the latter
 * method.
 */
static int32_t
NdisMInitializeScatterGatherDma(struct ndis_miniport_block *block,
    uint8_t is64, uint32_t maxphysmap)
{
	struct ndis_softc *sc;

	TRACE(NDBG_DMA, "block %p is64 %u maxphysmap %u\n",
	    block, is64, maxphysmap);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));

	sc = device_get_softc(block->physdeviceobj->devext);
	if (sc->ndis_sc == 1)	/* Don't do this twice. */
		return (NDIS_STATUS_SUCCESS);

	if (bus_dma_tag_create(sc->ndis_parent_tag, ETHER_ALIGN, 0,
	    is64 ? BUS_SPACE_MAXADDR : BUS_SPACE_MAXADDR_32BIT,
	    BUS_SPACE_MAXADDR, NULL, NULL, MCLBYTES * NDIS_MAXSEG,
	    NDIS_MAXSEG, MCLBYTES, BUS_DMA_ALLOCNOW, NULL, NULL,
	    &sc->ndis_ttag) != 0)
		return (NDIS_STATUS_RESOURCES);

	sc->ndis_sc = 1;

	return (NDIS_STATUS_SUCCESS);
}

void
NdisAllocatePacketPool(int32_t *status, struct ndis_packet_pool **pool,
    uint32_t descnum, uint32_t protrsvdlen)
{
	struct ndis_packet_pool *p;
	struct ndis_packet *packets;
	int i;

	TRACE(NDBG_PACKET, "pool %p descnum %u protrsvdlen %u\n",
	    pool, descnum, protrsvdlen);
	p = malloc(sizeof(struct ndis_packet_pool),
	    M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (p == NULL) {
		*status = NDIS_STATUS_RESOURCES;
		return;
	}

	p->cnt = descnum;
	p->len = sizeof(struct ndis_packet) + protrsvdlen;

	packets = malloc(p->cnt * p->len, M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (packets == NULL) {
		free(p, M_NDIS_SUBR);
		*status = NDIS_STATUS_RESOURCES;
		return;
	}

	p->pktmem = packets;

	for (i = 0; i < p->cnt; i++)
		InterlockedPushEntrySList(&p->head,
		    (struct slist_entry *)&packets[i]);

	*pool = p;
	*status = NDIS_STATUS_SUCCESS;
}

void
NdisAllocatePacketPoolEx(int32_t *status, struct ndis_packet_pool **pool,
    uint32_t descnum, uint32_t overflow, uint32_t protrsvdlen)
{
	TRACE(NDBG_PACKET, "pool %p descnum %u overflow %u protrsvdlen %u\n",
	    pool, descnum, protrsvdlen, overflow);
	return (NdisAllocatePacketPool(status, pool,
	    descnum + overflow, protrsvdlen));
}

static uint32_t
NdisPacketPoolUsage(struct ndis_packet_pool *pool)
{
	return (pool->cnt - ExQueryDepthSList(&pool->head));
}

void
NdisFreePacketPool(struct ndis_packet_pool *pool)
{
	TRACE(NDBG_PACKET, "pool %p\n", pool);
	free(pool->pktmem, M_NDIS_SUBR);
	free(pool, M_NDIS_SUBR);
}

void
NdisAllocatePacket(int32_t *status, struct ndis_packet **packet,
    struct ndis_packet_pool *pool)
{
	struct ndis_packet *pkt;

	TRACE(NDBG_PACKET, "packet %p pool %p\n", packet, pool);
	pkt = (struct ndis_packet *)InterlockedPopEntrySList(&pool->head);
	if (pkt == NULL) {
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	memset(pkt, 0, sizeof(struct ndis_packet));

	/* Save pointer to the pool. */
	pkt->private.pool = pool;

	/* Set the oob offset pointer. Lots of things expect this. */
	pkt->private.packetooboffset = offsetof(struct ndis_packet, oob);

	/*
	 * We must initialize the packet flags correctly in order
	 * for the NDIS_SET_PACKET_MEDIA_SPECIFIC_INFO() and
	 * NDIS_GET_PACKET_MEDIA_SPECIFIC_INFO() macros to work
	 * correctly.
	 */
	pkt->private.ndispktflags = NDIS_PACKET_ALLOCATED_BY_NDIS;
	pkt->private.validcounts = FALSE;

	*packet = pkt;
	*status = NDIS_STATUS_SUCCESS;
}

void
NdisFreePacket(struct ndis_packet *packet)
{
	struct ndis_packet_pool *p;

	TRACE(NDBG_PACKET, "packet %p\n", packet);
	p = (struct ndis_packet_pool *)packet->private.pool;
	InterlockedPushEntrySList(&p->head, (struct slist_entry *)packet);
}

static void
NdisUnchainBufferAtFront(struct ndis_packet *packet, struct mdl **buf)
{
	struct ndis_packet_private *priv;

	if (packet == NULL || buf == NULL)
		return;
	priv = &packet->private;
	priv->validcounts = FALSE;
	if (priv->head == priv->tail) {
		*buf = priv->head;
		priv->head = priv->tail = NULL;
	} else {
		*buf = priv->head;
		priv->head = (*buf)->next;
	}
}

static void
NdisUnchainBufferAtBack(struct ndis_packet *packet, struct mdl **buf)
{
	struct ndis_packet_private *priv;
	struct mdl *tmp;

	if (packet == NULL || buf == NULL)
		return;
	priv = &packet->private;
	priv->validcounts = FALSE;
	if (priv->head == priv->tail) {
		*buf = priv->head;
		priv->head = priv->tail = NULL;
	} else {
		*buf = priv->tail;
		tmp = priv->head;
		while (tmp->next != priv->tail)
			tmp = tmp->next;
		priv->tail = tmp;
		tmp->next = NULL;
	}
}

/*
 * The NDIS "buffer" is really an MDL (memory descriptor list)
 * which is used to describe a buffer in a way that allows it
 * to mapped into different contexts. We have to be careful how
 * we handle them: in some versions of Windows, the NdisFreeBuffer()
 * routine is an actual function in the NDIS API, but in others
 * it's just a macro wrapper around IoFreeMdl(). There's really
 * no way to use the 'descnum' parameter to count how many
 * "buffers" are allocated since in order to use IoFreeMdl() to
 * dispose of a buffer, we have to use IoAllocateMdl() to allocate
 * them, and IoAllocateMdl() just grabs them out of the heap.
 */
static void
NdisAllocateBufferPool(int32_t *status, void **pool,
    uint32_t descnum)
{
	/*
	 * The only thing we can really do here is verify that descnum
	 * is a reasonable value, but I really don't know what to check
	 * it against.
	 */
	*pool = NON_PAGED_POOL;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisFreeBufferPool(void *pool)
{
}

static void
NdisAllocateBuffer(int32_t *status, struct mdl **buffer, void *pool,
    void *vaddr, uint32_t len)
{
	struct mdl *buf;

	TRACE(NDBG_MEM, "buffer %p pool %p vaddr %p len %u\n",
	    buffer, pool, vaddr, len);
	buf = IoAllocateMdl(vaddr, len, FALSE, FALSE, NULL);
	if (buf == NULL) {
		*buffer = NULL;
		*status = NDIS_STATUS_FAILURE;
		return;
	}
	MmBuildMdlForNonPagedPool(buf);

	*buffer = buf;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisFreeBuffer(struct mdl *buf)
{
	TRACE(NDBG_MEM, "buf %p\n", buf);
	IoFreeMdl(buf);
}

static uint32_t
NdisBufferLength(struct mdl *buf)
{
	TRACE(NDBG_MM, "buf %p\n", buf);
	return (MmGetMdlByteCount(buf));
}

/*
 * Get the virtual address and length of a buffer.
 * Note: the vaddr argument is optional.
 */
static void
NdisQueryBuffer(struct mdl *buf, void **vaddr, uint32_t *len)
{
	if (vaddr != NULL)
		*vaddr = MmGetMdlVirtualAddress(buf);
	*len = MmGetMdlByteCount(buf);
	TRACE(NDBG_MM, "buf %p vaddr %p len %u\n", buf, *vaddr, *len);
}

static void
NdisQueryBufferSafe(struct mdl *buf, void **vaddr, uint32_t *len,
    uint32_t prio)
{
	NdisQueryBuffer(buf, vaddr, len);
}

static void *
NdisBufferVirtualAddress(struct mdl *buf)
{
	TRACE(NDBG_MM, "buf %p\n", buf);
	return (MmGetMdlVirtualAddress(buf));
}

static void *
NdisBufferVirtualAddressSafe(struct mdl *buf, uint32_t prio)
{
	TRACE(NDBG_MM, "buf %p prio %u\n", buf, prio);
	return (MmGetMdlVirtualAddress(buf));
}

static void
NdisAdjustBufferLength(struct mdl *buf, uint32_t len)
{
	MmGetMdlByteCount(buf) = len;
}

static int32_t
NdisInterlockedIncrement(int32_t *addend)
{
	atomic_add_int(addend, 1);

	return (*addend);
}

static int32_t
NdisInterlockedDecrement(int32_t *addend)
{
	atomic_subtract_int(addend, 1);

	return (*addend);
}

static void
NdisInitializeEvent(struct ndis_event *event)
{
	TRACE(NDBG_EVENT, "event %p\n", event);
	KeInitializeEvent(&event->kevent, NOTIFICATION_EVENT, FALSE);
}

static void
NdisSetEvent(struct ndis_event *event)
{
	TRACE(NDBG_EVENT, "event %p\n", event);
	KeSetEvent(&event->kevent, IO_NO_INCREMENT, FALSE);
}

static void
NdisResetEvent(struct ndis_event *event)
{
	TRACE(NDBG_EVENT, "event %p\n", event);
	KeResetEvent(&event->kevent);
}

static uint8_t
NdisWaitEvent(struct ndis_event *event, uint32_t msecs)
{
	int64_t duetime;
	uint32_t ret;

	TRACE(NDBG_EVENT, "event %p msecs %u\n", event, msecs);
	duetime = ((int64_t)msecs * -10000);
	ret = KeWaitForSingleObject(event, 0, 0, TRUE, msecs ? &duetime : NULL);
	if (ret == NDIS_STATUS_SUCCESS)
		return (TRUE);
	else
		return (FALSE);
}

static int32_t
NdisUnicodeStringToAnsiString(struct ansi_string *dst,
    struct unicode_string *src)
{
	return (RtlUnicodeStringToAnsiString(dst, src, FALSE));
}

static int32_t
NdisUpcaseUnicodeString(struct unicode_string *dst, struct unicode_string *src)
{
	return (RtlUpcaseUnicodeString(dst, src, FALSE));
}

static int32_t
NdisAnsiStringToUnicodeString(struct unicode_string *dst,
    struct ansi_string *src)
{
	return (RtlAnsiStringToUnicodeString(dst, src, FALSE));
}

static int32_t
NdisMPciAssignResources(struct ndis_miniport_block *block, uint32_t slot,
    struct cm_partial_resource_list **list)
{
	TRACE(NDBG_PCI, "block %p slot %u list %p\n", block, slot, list);
	KASSERT(block != NULL, ("no block"));
	*list = block->rlist;

	return (NDIS_STATUS_SUCCESS);
}

static uint8_t
ndis_interrupt_nic(struct nt_kinterrupt *iobj, struct ndis_softc *sc)
{
	uint8_t is_our_intr = FALSE, call_isr = FALSE;

	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	if (sc->ndis_block->interrupt == NULL)
		return (FALSE);
	if (sc->ndis_block->interrupt->isr_requested)
		MSCALL3(sc->ndis_block->interrupt->isr_func, &is_our_intr,
		    &call_isr, sc->ndis_block->miniport_adapter_ctx);
	else {
		ndis_disable_interrupts_nic(sc);
		call_isr = TRUE;
	}
	if (call_isr)
		IoRequestDpc(sc->ndis_block->deviceobj, NULL, sc);
	return (is_our_intr);
}

static void
ndis_intrhand(struct nt_kdpc *kdpc, struct ndis_miniport_interrupt *intr,
    void *sysarg1, void *sysarg2)
{
	struct ndis_softc *sc;

	KASSERT(intr != NULL, ("no intr"));
	KASSERT(intr->block != NULL, ("no block"));
	KASSERT(intr->block->miniport_adapter_ctx != NULL, ("no adapter"));
	KASSERT(intr->block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(intr->block->physdeviceobj->devext);
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeAcquireSpinLockAtDpcLevel(&intr->block->lock);
	MSCALL1(intr->dpc_func, intr->block->miniport_adapter_ctx);
	ndis_enable_interrupts_nic(sc);
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeReleaseSpinLockFromDpcLevel(&intr->block->lock);

	/*
	 * Set the completion event if we've drained all pending interrupts.
	 */
	KeAcquireSpinLockAtDpcLevel(&intr->dpc_count_lock);
	intr->dpc_count--;
	if (intr->dpc_count == 0)
		KeSetEvent(&intr->dpc_completed_event, IO_NO_INCREMENT, FALSE);
	KeReleaseSpinLockFromDpcLevel(&intr->dpc_count_lock);
}

static int32_t
NdisMRegisterInterrupt(struct ndis_miniport_interrupt *intr,
    struct ndis_miniport_block *block, uint32_t vec, uint32_t level,
    uint8_t reqisr, uint8_t shared, enum ndis_interrupt_mode mode)
{
	struct ndis_miniport_characteristics *ch;
	struct ndis_softc *sc;

	TRACE(NDBG_INTR, "intr %p block %p vec %u level %u reqisr %u shared %u "
	    "mode %d\n", intr, block, vec, level, reqisr, shared, mode);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);
	ch = IoGetDriverObjectExtension(block->deviceobj->drvobj, (void *)1);
	if (ch == NULL)
		return (NDIS_STATUS_RESOURCES);

	intr->block = block;
	intr->isr_requested = reqisr;
	intr->shared_interrupt = shared;
	intr->dpc_count = 0;
	intr->isr_func = ch->isr_func;
	intr->dpc_func = ch->interrupt_func;

	KeInitializeEvent(&intr->dpc_completed_event, NOTIFICATION_EVENT, TRUE);
	KeInitializeDpc(&intr->interrupt_dpc, ndis_intrhand_wrap, intr);
	KeSetImportanceDpc(&intr->interrupt_dpc, IMPORTANCE_LOW);

	if (IoConnectInterrupt(&intr->interrupt_object,
	    ndis_interrupt_nic_wrap, sc, NULL,
	    vec, level, 0, mode, shared, 0, FALSE) != NDIS_STATUS_SUCCESS)
		return (NDIS_STATUS_FAILURE);

	block->interrupt = intr;

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMDeregisterInterrupt(struct ndis_miniport_interrupt *intr)
{
	uint8_t irql;

	TRACE(NDBG_INTR, "intr %p\n", intr);
	/* Should really be KeSynchronizeExecution() */
	KeAcquireSpinLock(intr->interrupt_object->lock, &irql);
	intr->block->interrupt = NULL;
	KeReleaseSpinLock(intr->interrupt_object->lock, irql);
/*
	KeFlushQueuedDpcs();
*/
	/* Disconnect our ISR */
	IoDisconnectInterrupt(intr->interrupt_object);

	KeWaitForSingleObject(&intr->dpc_completed_event, 0, 0, FALSE, NULL);
	KeResetEvent(&intr->dpc_completed_event);
}

static void
NdisMRegisterAdapterShutdownHandler(struct ndis_miniport_block *block,
    void *ctx, ndis_shutdown_func func)
{
	struct ndis_softc *sc;

	TRACE(NDBG_INIT, "block %p ctx %p func %p\n", block, ctx, func);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);
	sc->ndis_chars->shutdown_func = func;
	sc->ndis_chars->reserved0 = ctx;
}

static void
NdisMDeregisterAdapterShutdownHandler(struct ndis_miniport_block *block)
{
	struct ndis_softc *sc;

	TRACE(NDBG_INIT, "block %p\n", block);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	sc = device_get_softc(block->physdeviceobj->devext);
	sc->ndis_chars->shutdown_func = NULL;
	sc->ndis_chars->reserved0 = NULL;
}

static uint32_t
NDIS_BUFFER_TO_SPAN_PAGES(struct mdl *buf)
{
	if (buf == NULL)
		return (0);
	if (MmGetMdlByteCount(buf) == 0)
		return (1);
	return (SPAN_PAGES(MmGetMdlVirtualAddress(buf),
	    MmGetMdlByteCount(buf)));
}

static void
NdisGetBufferPhysicalArraySize(struct mdl *buf, uint32_t *pages)
{
	*pages = NDIS_BUFFER_TO_SPAN_PAGES(buf);
}

static void
NdisQueryBufferOffset(struct mdl *buf, uint32_t *off, uint32_t *len)
{
	if (buf == NULL)
		return;
	*off = MmGetMdlByteOffset(buf);
	*len = MmGetMdlByteCount(buf);
}

static void
NdisMSleep(uint32_t usecs)
{
	struct nt_ktimer timer;

	TRACE(NDBG_INTR, "usecs %u\n", usecs);

	KeInitializeTimer(&timer);
	KeSetTimer(&timer, ((int64_t)usecs * -10), NULL);
	KeWaitForSingleObject(&timer, 0, 0, FALSE, NULL);
}

static uint32_t
NdisReadPcmciaAttributeMemory(struct ndis_miniport_block *block,
    uint32_t offset, void *buf, uint32_t len)
{
	struct ndis_softc *sc;
	bus_space_handle_t bh;
	bus_space_tag_t bt;
	char *dest = buf;
	int i;

	TRACE(NDBG_PCMCIA, "block %p offset %u buf %p len %u\n",
	    block, offset, buf, len);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));

	sc = device_get_softc(block->physdeviceobj->devext);
	bh = rman_get_bushandle(sc->ndis_res_am);
	bt = rman_get_bustag(sc->ndis_res_am);

	for (i = 0; i < len; i++)
		dest[i] = bus_space_read_1(bt, bh, (offset + i) * 2);

	return (i);
}

static uint32_t
NdisWritePcmciaAttributeMemory(struct ndis_miniport_block *block,
    uint32_t offset, void *buf, uint32_t len)
{
	struct ndis_softc *sc;
	bus_space_handle_t bh;
	bus_space_tag_t bt;
	char *src = buf;
	int i;

	TRACE(NDBG_PCMCIA, "block %p offset %u buf %p len %u\n",
	    block, offset, buf, len);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));

	sc = device_get_softc(block->physdeviceobj->devext);
	bh = rman_get_bushandle(sc->ndis_res_am);
	bt = rman_get_bustag(sc->ndis_res_am);

	for (i = 0; i < len; i++)
		bus_space_write_1(bt, bh, (offset + i) * 2, src[i]);

	return (i);
}

static struct list_entry *
NdisInterlockedInsertHeadList(struct list_entry *head, struct list_entry *entry,
    struct ndis_spin_lock *lock)
{
	struct list_entry *flink;

	KeAcquireSpinLock(&lock->spinlock, &lock->kirql);
	flink = head->flink;
	entry->flink = flink;
	entry->blink = head;
	flink->blink = entry;
	head->flink = entry;
	KeReleaseSpinLock(&lock->spinlock, lock->kirql);

	return (flink);
}

static struct list_entry *
NdisInterlockedRemoveHeadList(struct list_entry *head,
    struct ndis_spin_lock *lock)
{
	struct list_entry *flink;
	struct list_entry *entry;

	KeAcquireSpinLock(&lock->spinlock, &lock->kirql);
	entry = head->flink;
	flink = entry->flink;
	head->flink = flink;
	flink->blink = head;
	KeReleaseSpinLock(&lock->spinlock, lock->kirql);

	return (entry);
}

static struct list_entry *
NdisInterlockedInsertTailList(struct list_entry *head, struct list_entry *entry,
    struct ndis_spin_lock *lock)
{
	struct list_entry *blink;

	KeAcquireSpinLock(&lock->spinlock, &lock->kirql);
	blink = head->blink;
	entry->flink = head;
	entry->blink = blink;
	blink->flink = entry;
	head->blink = entry;
	KeReleaseSpinLock(&lock->spinlock, lock->kirql);

	return (blink);
}

static uint8_t
NdisMSynchronizeWithInterrupt(struct ndis_miniport_interrupt *intr,
    void *func, void *ctx)
{
	TRACE(NDBG_INTR, "intr %p func %p ctx %p\n", intr, func, ctx);
	KASSERT(intr != NULL, ("no intr"));
	return (KeSynchronizeExecution(intr->interrupt_object, func, ctx));
}

static void
NdisGetCurrentSystemTime(int64_t *tval)
{
	ntoskrnl_time(tval);
}

/*
 * Return the number of milliseconds since the system booted.
 */
static void
NdisGetSystemUpTime(uint32_t *tval)
{
	struct timespec ts;

	nanouptime(&ts);
	*tval = ts.tv_nsec / 1000000 + ts.tv_sec * 1000;
}

static void
NdisGetSystemUpTimeEx(int64_t *tval)
{
	struct timespec ts;

	nanouptime(&ts);
	*tval = ts.tv_nsec / 1000000 + ts.tv_sec * 1000;
}

static uint32_t
NdisGetVersion(void)
{
	return (0x00050001);
}

static void
NdisInitializeString(struct unicode_string *dst, char *src)
{
	if (src == NULL) {
		dst->len = dst->maxlen = 0;
		dst->buf = NULL;
	} else {
		struct ansi_string as;
		RtlInitAnsiString(&as, src);
		RtlAnsiStringToUnicodeString(dst, &as, TRUE);
	}
}

static void
NdisFreeString(struct unicode_string *str)
{
	RtlFreeUnicodeString(str);
}

static int32_t
NdisMRemoveMiniport(struct ndis_miniport_block *block)
{
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisInitAnsiString(struct ansi_string *dst, char *src)
{
	RtlInitAnsiString(dst, src);
}

static void
NdisInitUnicodeString(struct unicode_string *dst, uint16_t *src)
{
	RtlInitUnicodeString(dst, src);
}

static void
NdisMGetDeviceProperty(struct ndis_miniport_block *block,
    struct device_object **phydevobj, struct device_object **funcdevobj,
    struct device_object **nextdevobj, struct cm_resource_list *resources,
    struct cm_resource_list *tresources)
{

	KASSERT(block != NULL, ("no block"));
	if (phydevobj != NULL)
		*phydevobj = block->physdeviceobj;
	if (funcdevobj != NULL)
		*funcdevobj = block->deviceobj;
	if (nextdevobj != NULL)
		*nextdevobj = block->nextdeviceobj;
}

static void
NdisGetFirstBufferFromPacket(struct ndis_packet *packet, struct mdl **buf,
    void **firstva, uint32_t *firstlen, uint32_t *totlen)
{
	struct mdl *tmp;

	tmp = packet->private.head;
	*buf = tmp;
	if (tmp == NULL) {
		*firstva = NULL;
		*firstlen = *totlen = 0;
	} else {
		*firstva = MmGetMdlVirtualAddress(tmp);
		*firstlen = *totlen = MmGetMdlByteCount(tmp);
		for (tmp = tmp->next; tmp != NULL; tmp = tmp->next)
			*totlen += MmGetMdlByteCount(tmp);
	}
}

static void
NdisGetFirstBufferFromPacketSafe(struct ndis_packet *packet, struct mdl **buf,
    void **firstva, uint32_t *firstlen, uint32_t *totlen, uint32_t prio)
{
	NdisGetFirstBufferFromPacket(packet, buf, firstva, firstlen, totlen);
}

static int
ndis_find_sym(linker_file_t lf, char *filename, char *suffix, caddr_t *sym)
{
	char *fullsym, *suf;
	int i;

	fullsym = malloc(MAXPATHLEN, M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (fullsym == NULL)
		return (ENOMEM);
	strncpy(fullsym, filename, MAXPATHLEN);
	if (strlen(filename) < 4) {
		free(fullsym, M_NDIS_SUBR);
		return (EINVAL);
	}

	/* If the filename has a .ko suffix, strip if off. */
	suf = fullsym + (strlen(filename) - 3);
	if (strcmp(suf, ".ko") == 0)
		*suf = '\0';

	for (i = 0; i < strlen(fullsym); i++) {
		if (fullsym[i] == '.')
			fullsym[i] = '_';
		else
			fullsym[i] = tolower(fullsym[i]);
	}
	strcat(fullsym, suffix);
	*sym = linker_file_lookup_symbol(lf, fullsym, 0);
	free(fullsym, M_NDIS_SUBR);
	if (*sym == 0)
		return (ENOENT);

	return (0);
}

struct ndis_module {
	char				*afilename;
	struct ndis_file_handle		*fh;
};

static int
ndis_check_module(linker_file_t lf, void *context)
{
	struct ndis_module *nc;
	caddr_t kldstart, kldend;

	nc = (struct ndis_module *)context;
	if (ndis_find_sym(lf, nc->afilename, "_start", &kldstart) ||
	    ndis_find_sym(lf, nc->afilename, "_end", &kldend))
		return (FALSE);
	nc->fh->vp = lf;
	nc->fh->map = NULL;
	nc->fh->type = NDIS_FILE_HANDLE_TYPE_MODULE;
	nc->fh->maplen = (kldend - kldstart) & 0xFFFFFFFF;
	return (TRUE);
}

static void
NdisOpenFile(int32_t *status, struct ndis_file_handle **filehandle,
    uint32_t *filelength, struct unicode_string *filename, uint64_t highestaddr)
{
	struct ansi_string as;
	char *afilename = NULL, *path;
	struct thread *td = curthread;
	struct nameidata nd;
	struct ndis_module nc;
	struct vattr vat, *vap = &vat;
	struct ndis_file_handle *fh;
	int flags, vfslocked;

	if (RtlUnicodeStringToAnsiString(&as, filename, TRUE)) {
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	afilename = strdup(as.buf, M_NDIS_SUBR);
	RtlFreeAnsiString(&as);

	fh = malloc(sizeof(struct ndis_file_handle), M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (fh == NULL) {
		free(afilename, M_NDIS_SUBR);
		*status = NDIS_STATUS_RESOURCES;
		return;
	}

	fh->name = afilename;

	nc.afilename = afilename;
	nc.fh = fh;
	if (linker_file_foreach(ndis_check_module, &nc)) {
		*filelength = fh->maplen;
		*filehandle = fh;
		*status = NDIS_STATUS_SUCCESS;
		return;
	}

	path = malloc(MAXPATHLEN, M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (path == NULL) {
		free(fh, M_NDIS_SUBR);
		free(afilename, M_NDIS_SUBR);
		*status = NDIS_STATUS_RESOURCES;
		return;
	}
	snprintf(path, MAXPATHLEN, "%s/%s", ndis_filepath, afilename);

	/* Some threads don't have a current working directory. */
	if (td->td_proc->p_fd->fd_rdir == NULL)
		td->td_proc->p_fd->fd_rdir = rootvnode;
	if (td->td_proc->p_fd->fd_cdir == NULL)
		td->td_proc->p_fd->fd_cdir = rootvnode;

	NDINIT(&nd, LOOKUP, FOLLOW | MPSAFE, UIO_SYSSPACE, path, td);

	flags = FREAD;
	if (vn_open(&nd, &flags, 0, NULL) != 0) {
		*status = NDIS_STATUS_FILE_NOT_FOUND;
		free(fh, M_NDIS_SUBR);
		printf("NDIS: open file %s failed\n", path);
		free(path, M_NDIS_SUBR);
		free(afilename, M_NDIS_SUBR);
		return;
	}
	vfslocked = NDHASGIANT(&nd);

	free(path, M_NDIS_SUBR);

	NDFREE(&nd, NDF_ONLY_PNBUF);

	/* Get the file size. */
	VOP_GETATTR(nd.ni_vp, vap, td->td_ucred);
	VOP_UNLOCK(nd.ni_vp, 0);
	VFS_UNLOCK_GIANT(vfslocked);

	fh->vp = nd.ni_vp;
	fh->map = NULL;
	fh->type = NDIS_FILE_HANDLE_TYPE_VFS;
	*filehandle = fh;
	*filelength = fh->maplen = vap->va_size & 0xFFFFFFFF;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisMapFile(int32_t *status, void **mappedbuffer, struct ndis_file_handle *file)
{
	struct vnode *vp;
	struct thread *td = curthread;
	linker_file_t lf;
	caddr_t kldstart;
	int error, vfslocked;
	ssize_t resid;

	if (file == NULL) {
		*status = NDIS_STATUS_FAILURE;
		return;
	}
	if (file->vp == NULL) {
		*status = NDIS_STATUS_FAILURE;
		return;
	}
	if (file->map != NULL) {
		*status = NDIS_STATUS_ALREADY_MAPPED;
		return;
	}
	if (file->type == NDIS_FILE_HANDLE_TYPE_MODULE) {
		lf = file->vp;
		if (ndis_find_sym(lf, file->name, "_start", &kldstart)) {
			*status = NDIS_STATUS_FAILURE;
			return;
		}
		file->map = kldstart;
		*status = NDIS_STATUS_SUCCESS;
		*mappedbuffer = file->map;
		return;
	}

	file->map = malloc(file->maplen, M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (file->map == NULL) {
		*status = NDIS_STATUS_RESOURCES;
		return;
	}

	vp = file->vp;
	vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	error = vn_rdwr(UIO_READ, vp, file->map, file->maplen, 0,
	    UIO_SYSSPACE, 0, td->td_ucred, NOCRED, &resid, td);
	VFS_UNLOCK_GIANT(vfslocked);
	if (error)
		*status = NDIS_STATUS_FAILURE;
	else {
		*status = NDIS_STATUS_SUCCESS;
		*mappedbuffer = file->map;
	}
}

static void
NdisUnmapFile(struct ndis_file_handle *file)
{
	if (file->map == NULL)
		return;
	if (file->type == NDIS_FILE_HANDLE_TYPE_VFS)
		free(file->map, M_NDIS_SUBR);
	file->map = NULL;
}

static void
NdisCloseFile(struct ndis_file_handle *file)
{
	struct vnode *vp;
	struct thread *td = curthread;
	int vfslocked;

	if (file == NULL)
		return;
	if (file->map != NULL) {
		if (file->type == NDIS_FILE_HANDLE_TYPE_VFS)
			free(file->map, M_NDIS_SUBR);
		file->map = NULL;
	}
	if (file->vp == NULL)
		return;
	if (file->type == NDIS_FILE_HANDLE_TYPE_VFS) {
		vp = file->vp;
		vfslocked = VFS_LOCK_GIANT(vp->v_mount);
		vn_close(vp, FREAD, td->td_ucred, td);
		VFS_UNLOCK_GIANT(vfslocked);
	}
	file->vp = NULL;
	free(file->name, M_NDIS_SUBR);
	free(file, M_NDIS_SUBR);
}

static uint8_t
NdisSystemProcessorCount(void)
{
	return (mp_ncpus);
}

static void
NdisGetCurrentProcessorCounts(uint32_t *idle_count, uint32_t *kernel_and_user,
    uint32_t *index)
{
	struct pcpu *pcpu;

	pcpu = pcpu_find(curthread->td_oncpu);
	*index = pcpu->pc_cpuid;
	*idle_count = pcpu->pc_cp_time[CP_IDLE];
	*kernel_and_user = pcpu->pc_cp_time[CP_INTR];
}

static void
NdisMIndicateStatusComplete(struct ndis_miniport_block *block)
{
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->status_done_func != NULL, ("no status_done"));
	MSCALL1(block->status_done_func, block);
}

static void
NdisMIndicateStatus(struct ndis_miniport_block *block, int32_t status,
    void *sbuf, uint32_t slen)
{
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->status_func != NULL, ("no status"));
	MSCALL4(block->status_func, block, status, sbuf, slen);
}

static int32_t
NdisScheduleWorkItem(struct ndis_work_item *work)
{
	TRACE(NDBG_WORK, "work %p\n", work);
	schedule_ndis_work_item(work);
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisCopyFromPacketToPacket(struct ndis_packet *dpkt, uint32_t doff,
    uint32_t reqlen, struct ndis_packet *spkt, uint32_t soff, uint32_t *cpylen)
{
	struct mdl *src, *dst;
	char *sptr, *dptr;
	int resid, copied, len, scnt, dcnt;

	TRACE(NDBG_PACKET, "dpkt %p doff %u reqlen %d spkt %p soff %u\n",
	    dpkt, doff, reqlen, spkt, soff);
	*cpylen = 0;

	src = spkt->private.head;
	dst = dpkt->private.head;

	sptr = MmGetMdlVirtualAddress(src);
	dptr = MmGetMdlVirtualAddress(dst);
	scnt = MmGetMdlByteCount(src);
	dcnt = MmGetMdlByteCount(dst);

	while (soff) {
		if (MmGetMdlByteCount(src) > soff) {
			sptr += soff;
			scnt = MmGetMdlByteCount(src)- soff;
			break;
		}
		soff -= MmGetMdlByteCount(src);
		src = src->next;
		if (src == NULL)
			return;
		sptr = MmGetMdlVirtualAddress(src);
	}

	while (doff) {
		if (MmGetMdlByteCount(dst) > doff) {
			dptr += doff;
			dcnt = MmGetMdlByteCount(dst) - doff;
			break;
		}
		doff -= MmGetMdlByteCount(dst);
		dst = dst->next;
		if (dst == NULL)
			return;
		dptr = MmGetMdlVirtualAddress(dst);
	}

	resid = reqlen;
	copied = 0;

	for (;;) {
		if (resid < scnt)
			len = resid;
		else
			len = scnt;
		if (dcnt < len)
			len = dcnt;

		memcpy(dptr, sptr, len);

		copied += len;
		resid -= len;
		if (resid == 0)
			break;

		dcnt -= len;
		if (dcnt == 0) {
			dst = dst->next;
			if (dst == NULL)
				break;
			dptr = MmGetMdlVirtualAddress(dst);
			dcnt = MmGetMdlByteCount(dst);
		}

		scnt -= len;
		if (scnt == 0) {
			src = src->next;
			if (src == NULL)
				break;
			sptr = MmGetMdlVirtualAddress(src);
			scnt = MmGetMdlByteCount(src);
		}
	}

	*cpylen = copied;
}

static void
NdisCopyFromPacketToPacketSafe(struct ndis_packet *dpkt, uint32_t doff,
    uint32_t reqlen, struct ndis_packet *spkt, uint32_t soff, uint32_t *cpylen,
    uint32_t prio)
{
	NdisCopyFromPacketToPacket(dpkt, doff, reqlen, spkt, soff, cpylen);
}

static void
NdisIMCopySendPerPacketInfo(struct ndis_packet *dpkt, struct ndis_packet *spkt)
{
	memcpy(&dpkt->ext, &spkt->ext, sizeof(struct ndis_packet_extension));
}

static int32_t
NdisMRegisterDevice(struct driver_object *drv_obj,
    struct unicode_string *devname, struct unicode_string *symname,
    driver_dispatch *majorfuncs[], void **dev_obj, void **devhandle)
{
	struct device_object *dobj;
	uint32_t status;

	TRACE(NDBG_INIT, "drv_obj %p devname %p symname %p dev_obj %p "
	    "devhandle %p\n", drv_obj, devname, symname, dev_obj, devhandle);
	status = IoCreateDevice(drv_obj, 0, devname,
	    FILE_DEVICE_NETWORK, 0, FALSE, &dobj);
	if (status == NDIS_STATUS_SUCCESS) {
		*dev_obj = dobj;
		*devhandle = dobj;
	}
	return (status);
}

static int32_t
NdisMDeregisterDevice(struct device_object *dev_obj)
{
	TRACE(NDBG_INIT, "dev_obj %p\n", dev_obj);
	IoDeleteDevice(dev_obj);
	return (NDIS_STATUS_SUCCESS);
}

static int32_t
NdisMQueryAdapterInstanceName(struct unicode_string *name,
    struct ndis_miniport_block *block)
{
	struct ansi_string as;

	TRACE(NDBG_INIT, "name %p block %p\n", name, block);
	KASSERT(block != NULL, ("no block"));
	KASSERT(block->physdeviceobj != NULL, ("no physdeviceobj"));
	RtlInitAnsiString(&as, device_get_nameunit(block->physdeviceobj->devext));
	if (RtlAnsiStringToUnicodeString(name, &as, TRUE))
		return (NDIS_STATUS_RESOURCES);
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMRegisterUnloadHandler(struct driver_object *drv_obj, void *func)
{
	TRACE(NDBG_INIT, "drv_obj %p func %p\n", drv_obj, func);
	KASSERT(drv_obj != NULL, ("no drv_obj"));
	drv_obj->driver_unload_func = func;
}

static void
dummy(void)
{
	printf("ndis dummy called...\n");
}

/*
 * Note: a couple of entries in this table specify the
 * number of arguments as "foo + 1". These are routines
 * that accept a 64-bit argument, passed by value. On
 * x86, these arguments consume two longwords on the stack,
 * so we lie and say there's one additional argument so
 * that the wrapping routines will do the right thing.
 */
struct image_patch_table ndis_functbl[] = {
	IMPORT_CFUNC(NdisWriteErrorLogEntry, 0),
	IMPORT_SFUNC(NDIS_BUFFER_TO_SPAN_PAGES, 1),
	IMPORT_SFUNC(NdisAcquireReadWriteLock, 3),
	IMPORT_SFUNC(NdisAcquireSpinLock, 1),
	IMPORT_SFUNC(NdisAdjustBufferLength, 2),
	IMPORT_SFUNC(NdisAllocateBuffer, 5),
	IMPORT_SFUNC(NdisAllocateBufferPool, 3),
	IMPORT_SFUNC(NdisAllocateIoWorkItem, 1),
	IMPORT_SFUNC(NdisAllocateMemory, 4 + 1),
	IMPORT_SFUNC(NdisAllocateMemoryWithTag, 3),
	IMPORT_SFUNC(NdisAllocateMemoryWithTagPriority, 4),
	IMPORT_SFUNC(NdisAllocatePacket, 3),
	IMPORT_SFUNC(NdisAllocatePacketPool, 4),
	IMPORT_SFUNC(NdisAllocatePacketPoolEx, 5),
	IMPORT_SFUNC(NdisAllocateSpinLock, 1),
	IMPORT_SFUNC(NdisAllocateTimerObject, 3),
	IMPORT_SFUNC(NdisAnsiStringToUnicodeString, 2),
	IMPORT_SFUNC(NdisBufferLength, 1),
	IMPORT_SFUNC(NdisBufferVirtualAddress, 1),
	IMPORT_SFUNC(NdisBufferVirtualAddressSafe, 2),
	IMPORT_SFUNC(NdisCancelTimer, 2),
	IMPORT_SFUNC(NdisCancelTimerObject, 1),
	IMPORT_SFUNC(NdisCloseConfiguration, 1),
	IMPORT_SFUNC(NdisCloseFile, 1),
	IMPORT_SFUNC(NdisCopyFromPacketToPacket, 6),
	IMPORT_SFUNC(NdisCopyFromPacketToPacketSafe, 7),
	IMPORT_SFUNC(NdisDprAcquireSpinLock, 1),
	IMPORT_SFUNC(NdisDprReleaseSpinLock, 1),
	IMPORT_SFUNC(NdisFreeBuffer, 1),
	IMPORT_SFUNC(NdisFreeBufferPool, 1),
	IMPORT_SFUNC(NdisFreeIoWorkItem, 1),
	IMPORT_SFUNC(NdisFreeMemory, 3),
	IMPORT_SFUNC(NdisFreePacket, 1),
	IMPORT_SFUNC(NdisFreePacketPool, 1),
	IMPORT_SFUNC(NdisFreeSpinLock, 1),
	IMPORT_SFUNC(NdisFreeString, 1),
	IMPORT_SFUNC(NdisFreeTimerObject, 1),
	IMPORT_SFUNC(NdisGetBufferPhysicalArraySize, 2),
	IMPORT_SFUNC(NdisGetCacheFillSize, 0),
	IMPORT_SFUNC(NdisGetCurrentProcessorCounts, 3),
	IMPORT_SFUNC(NdisGetCurrentSystemTime, 1),
	IMPORT_SFUNC(NdisGetFirstBufferFromPacket, 5),
	IMPORT_SFUNC(NdisGetFirstBufferFromPacketSafe, 6),
	IMPORT_SFUNC(NdisGetRoutineAddress, 1),
	IMPORT_SFUNC(NdisGetSystemUpTime, 1),
	IMPORT_SFUNC(NdisGetSystemUpTimeEx, 1),
	IMPORT_SFUNC(NdisGetVersion, 0),
	IMPORT_SFUNC(NdisIMCopySendPerPacketInfo, 2),
	IMPORT_SFUNC(NdisInitAnsiString, 2),
	IMPORT_SFUNC(NdisInitUnicodeString, 2),
	IMPORT_SFUNC(NdisInitializeEvent, 1),
	IMPORT_SFUNC(NdisInitializeReadWriteLock, 1),
	IMPORT_SFUNC(NdisInitializeString, 2),
	IMPORT_SFUNC(NdisInitializeTimer, 3),
	IMPORT_SFUNC(NdisInitializeWrapper, 4),
	IMPORT_SFUNC(NdisInterlockedDecrement, 1),
	IMPORT_SFUNC(NdisInterlockedIncrement, 1),
	IMPORT_SFUNC(NdisInterlockedInsertHeadList, 3),
	IMPORT_SFUNC(NdisInterlockedInsertTailList, 3),
	IMPORT_SFUNC(NdisInterlockedRemoveHeadList, 2),
	IMPORT_SFUNC(NdisMAllocateMapRegisters, 5),
	IMPORT_SFUNC(NdisMAllocateSharedMemory, 5),
	IMPORT_SFUNC(NdisMAllocateSharedMemoryAsync, 4),
	IMPORT_SFUNC(NdisMCancelTimer, 2),
	IMPORT_SFUNC(NdisMCloseLog, 1),
	IMPORT_SFUNC(NdisMCompleteBufferPhysicalMapping, 3),
	IMPORT_SFUNC(NdisMCreateLog, 3),
	IMPORT_SFUNC(NdisMFlushLog, 1),
	IMPORT_SFUNC(NdisMWriteLogData, 3),
	IMPORT_SFUNC(NdisMDeregisterAdapterShutdownHandler, 1),
	IMPORT_SFUNC(NdisMDeregisterDevice, 1),
	IMPORT_SFUNC(NdisMDeregisterInterrupt, 1),
	IMPORT_SFUNC(NdisMDeregisterIoPortRange, 4),
	IMPORT_SFUNC(NdisMFreeMapRegisters, 1),
	IMPORT_SFUNC(NdisMFreeSharedMemory, 5 + 1),
	IMPORT_SFUNC(NdisMGetDeviceProperty, 6),
	IMPORT_SFUNC(NdisMGetDmaAlignment, 1),
	IMPORT_SFUNC(NdisMIndicateStatus, 4),
	IMPORT_SFUNC(NdisMIndicateStatusComplete, 1),
	IMPORT_SFUNC(NdisMInitializeScatterGatherDma, 3),
	IMPORT_SFUNC(NdisMInitializeTimer, 4),
	IMPORT_SFUNC(NdisMMapIoSpace, 4 + 1),
	IMPORT_SFUNC(NdisMPciAssignResources, 3),
	IMPORT_SFUNC(NdisMQueryAdapterInstanceName, 2),
	IMPORT_SFUNC(NdisMQueryAdapterResources, 4),
	IMPORT_SFUNC(NdisMRegisterAdapterShutdownHandler, 3),
	IMPORT_SFUNC(NdisMRegisterDevice, 6),
	IMPORT_SFUNC(NdisMRegisterInterrupt, 7),
	IMPORT_SFUNC(NdisMRegisterIoPortRange, 4),
	IMPORT_SFUNC(NdisMRegisterMiniport, 3),
	IMPORT_SFUNC(NdisMRegisterUnloadHandler, 2),
	IMPORT_SFUNC(NdisMRemoveMiniport, 1),
	IMPORT_SFUNC(NdisMSetAttributesEx, 5),
	IMPORT_SFUNC(NdisMSetPeriodicTimer, 2),
	IMPORT_SFUNC(NdisMSleep, 1),
	IMPORT_SFUNC(NdisMStartBufferPhysicalMapping, 6),
	IMPORT_SFUNC(NdisMSynchronizeWithInterrupt, 3),
	IMPORT_SFUNC(NdisMUnmapIoSpace, 3),
	IMPORT_SFUNC(NdisMapFile, 3),
	IMPORT_SFUNC(NdisOpenConfiguration, 3),
	IMPORT_SFUNC(NdisOpenConfigurationKeyByIndex, 5),
	IMPORT_SFUNC(NdisOpenConfigurationKeyByName, 4),
	IMPORT_SFUNC(NdisOpenFile, 5 + 1),
	IMPORT_SFUNC(NdisPacketPoolUsage, 1),
	IMPORT_SFUNC(NdisQueryBuffer, 3),
	IMPORT_SFUNC(NdisQueryBufferOffset, 3),
	IMPORT_SFUNC(NdisQueryBufferSafe, 4),
	IMPORT_SFUNC(NdisQueueIoWorkItem, 3),
	IMPORT_SFUNC(NdisReadConfiguration, 5),
	IMPORT_SFUNC(NdisReadNetworkAddress, 4),
	IMPORT_SFUNC(NdisReadPciSlotInformation, 5),
	IMPORT_SFUNC(NdisReadPcmciaAttributeMemory, 4),
	IMPORT_SFUNC(NdisReleaseReadWriteLock, 2),
	IMPORT_SFUNC(NdisReleaseSpinLock, 1),
	IMPORT_SFUNC(NdisResetEvent, 1),
	IMPORT_SFUNC(NdisScheduleWorkItem, 1),
	IMPORT_SFUNC(NdisSetEvent, 1),
	IMPORT_SFUNC(NdisSetTimer, 2),
	IMPORT_SFUNC(NdisSetTimerObject, 4 + 1),
	IMPORT_SFUNC(NdisSystemProcessorCount, 0),
	IMPORT_SFUNC(NdisTerminateWrapper, 2),
	IMPORT_SFUNC(NdisUnchainBufferAtBack, 2),
	IMPORT_SFUNC(NdisUnchainBufferAtFront, 2),
	IMPORT_SFUNC(NdisUnicodeStringToAnsiString, 2),
	IMPORT_SFUNC(NdisUnmapFile, 1),
	IMPORT_SFUNC(NdisUpcaseUnicodeString, 2),
	IMPORT_SFUNC(NdisWaitEvent, 2),
	IMPORT_SFUNC(NdisWriteConfiguration, 4),
	IMPORT_SFUNC(NdisWriteEventLogEntry, 7),
	IMPORT_SFUNC(NdisWritePciSlotInformation, 5),
	IMPORT_SFUNC(NdisWritePcmciaAttributeMemory, 4),
	IMPORT_SFUNC_MAP(NdisDprAllocatePacket, NdisAllocatePacket, 3),
	IMPORT_SFUNC_MAP(NdisDprFreePacket, NdisFreePacket, 1),
	IMPORT_SFUNC_MAP(NdisImmediateReadPciSlotInformation,
	    NdisReadPciSlotInformation, 5),
	IMPORT_SFUNC_MAP(NdisImmediateWritePciSlotInformation,
	    NdisWritePciSlotInformation, 5),
	{ NULL, (FUNC)dummy, NULL, 0, STDCALL },
	{ NULL, NULL, NULL }
};
