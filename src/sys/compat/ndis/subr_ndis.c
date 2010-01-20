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
#include <sys/errno.h>

#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/timespec.h>
#include <sys/smp.h>
#include <sys/queue.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/kthread.h>
#include <sys/linker.h>
#include <sys/mount.h>
#include <sys/sysproto.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

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
#include <compat/ndis/cfg_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/hal_var.h>
#include <compat/ndis/ndis_var.h>
#include <dev/if_ndis/if_ndisvar.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/uma.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

static char ndis_filepath[MAXPATHLEN] = "/compat/ndis";

SYSCTL_STRING(_hw, OID_AUTO, ndis_filepath, CTLFLAG_RW, ndis_filepath,
    MAXPATHLEN, "Path used by NdisOpenFile() to search for files");

static void NdisInitializeWrapper(ndis_handle *, driver_object *, void *,
    void *);
static ndis_status NdisMRegisterMiniport(ndis_handle,
    ndis_miniport_driver_characteristics *, uint32_t);
static ndis_status NdisAllocateMemoryWithTag(void **, uint32_t, uint32_t);
static ndis_status NdisAllocateMemory(void **, uint32_t, uint32_t,
    ndis_physaddr);
static void NdisFreeMemory(void *, uint32_t, uint32_t);
static ndis_status NdisMSetAttributesEx(ndis_handle, ndis_handle,
    uint32_t, uint32_t, ndis_interface_type);
static void NdisOpenConfiguration(ndis_status *, ndis_handle *, ndis_handle);
static void NdisOpenConfigurationKeyByIndex(ndis_status *, ndis_handle,
    uint32_t, unicode_string *, ndis_handle *);
static void NdisOpenConfigurationKeyByName(ndis_status *, ndis_handle,
    unicode_string *, ndis_handle *);
static ndis_status ndis_encode_parm(ndis_miniport_block *, struct sysctl_oid *,
    ndis_parm_type, ndis_config_parm **);
static ndis_status ndis_decode_parm(ndis_miniport_block *, ndis_config_parm *,
    char *);
static void NdisReadConfiguration(ndis_status *, ndis_config_parm **,
    ndis_handle, unicode_string *, ndis_parm_type);
static void NdisWriteConfiguration(ndis_status *, ndis_handle,
    unicode_string *, ndis_config_parm *);
static void NdisCloseConfiguration(ndis_handle);
static void NdisAllocateSpinLock(ndis_spin_lock *);
static void NdisFreeSpinLock(ndis_spin_lock *);
static void NdisAcquireSpinLock(ndis_spin_lock *);
static void NdisReleaseSpinLock(ndis_spin_lock *);
static void NdisDprAcquireSpinLock(ndis_spin_lock *);
static void NdisDprReleaseSpinLock(ndis_spin_lock *);
static void NdisInitializeReadWriteLock(ndis_rw_lock *);
static void NdisAcquireReadWriteLock(ndis_rw_lock *, uint8_t,
    ndis_lock_state *);
static void NdisReleaseReadWriteLock(ndis_rw_lock *, ndis_lock_state *);
static uint32_t NdisReadPciSlotInformation(ndis_handle, uint32_t, uint32_t,
    void *, uint32_t);
static uint32_t NdisWritePciSlotInformation(ndis_handle, uint32_t, uint32_t,
    void *, uint32_t);
static void NdisWriteErrorLogEntry(ndis_handle, ndis_error_code, uint32_t, ...);
static bus_addr_t ndis_dmasize(uint8_t dmasize);
static void ndis_map_cb(void *, bus_dma_segment_t *, int, int);
static void NdisMStartBufferPhysicalMapping(ndis_handle, ndis_buffer *,
    uint32_t, uint8_t, ndis_paddr_unit *, uint32_t *);
static void NdisMCompleteBufferPhysicalMapping(ndis_handle, ndis_buffer *,
    uint32_t);
static void NdisMInitializeTimer(ndis_miniport_timer *, ndis_handle,
    ndis_timer_function, void *);
static void NdisInitializeTimer(ndis_timer *, ndis_timer_function, void *);
static void NdisSetTimer(ndis_timer *, uint32_t);
static ndis_status NdisScheduleWorkItem(ndis_work_item *);
static void NdisMSetPeriodicTimer(ndis_miniport_timer *, uint32_t);
static void NdisMSleep(uint32_t);
static void NdisMCancelTimer(ndis_timer *, uint8_t *);
static void ndis_timercall(kdpc *, ndis_miniport_timer *, void *, void *);
static void NdisMQueryAdapterResources(ndis_status *, ndis_handle,
    cm_partial_resource_list *, uint32_t *);
static ndis_status NdisMRegisterIoPortRange(void **, ndis_handle, uint32_t,
    uint32_t);
static void NdisMDeregisterIoPortRange(ndis_handle, uint32_t, uint32_t, void *);
static void NdisReadNetworkAddress(ndis_status *, void **, uint32_t *,
    ndis_handle);
static ndis_status NdisQueryMapRegisterCount(uint32_t, uint32_t *);
static ndis_status NdisMAllocateMapRegisters(ndis_handle, uint32_t, uint8_t,
    uint32_t, uint32_t);
static void NdisMFreeMapRegisters(ndis_handle);
static void ndis_mapshared_cb(void *, bus_dma_segment_t *, int, int);
static void NdisMAllocateSharedMemory(ndis_handle, uint32_t, uint8_t, void **,
    ndis_physaddr *);
static void ndis_asyncmem_complete(device_object *, void *);
static ndis_status NdisMAllocateSharedMemoryAsync(ndis_handle, uint32_t,
    uint8_t, void *);
static void NdisMFreeSharedMemory(ndis_handle, uint32_t, uint8_t, void *,
    ndis_physaddr);
static ndis_status NdisMMapIoSpace(void **, ndis_handle, ndis_physaddr,
    uint32_t);
static void NdisMUnmapIoSpace(ndis_handle, void *, uint32_t);
static uint32_t NdisGetCacheFillSize(void);
static uint32_t NdisMGetDmaAlignment(ndis_handle);
static ndis_status NdisMInitializeScatterGatherDma(ndis_handle, uint8_t,
    uint32_t);
static void NdisUnchainBufferAtFront(ndis_packet *, ndis_buffer **);
static void NdisUnchainBufferAtBack(ndis_packet *, ndis_buffer **);
static void NdisAllocateBufferPool(ndis_status *, ndis_handle *, uint32_t);
static void NdisFreeBufferPool(ndis_handle);
static void NdisAllocateBuffer(ndis_status *, ndis_buffer **, ndis_handle,
    void *, uint32_t);
static void NdisFreeBuffer(ndis_buffer *);
static uint32_t NdisBufferLength(ndis_buffer *);
static void NdisQueryBuffer(ndis_buffer *, void **, uint32_t *);
static void NdisQueryBufferSafe(ndis_buffer *, void **, uint32_t *, uint32_t);
static void *NdisBufferVirtualAddress(ndis_buffer *);
static void *NdisBufferVirtualAddressSafe(ndis_buffer *, uint32_t);
static void NdisAdjustBufferLength(ndis_buffer *, uint32_t);
static uint32_t NdisInterlockedIncrement(uint32_t *);
static uint32_t NdisInterlockedDecrement(uint32_t *);
static void NdisInitializeEvent(ndis_event *);
static void NdisSetEvent(ndis_event *);
static void NdisResetEvent(ndis_event *);
static uint8_t NdisWaitEvent(ndis_event *, uint32_t);
static ndis_status NdisUnicodeStringToAnsiString(ansi_string *,
    unicode_string *);
static ndis_status NdisAnsiStringToUnicodeString(unicode_string *,
    ansi_string *);
static ndis_status NdisMPciAssignResources(ndis_handle, uint32_t,
    cm_partial_resource_list **);
static ndis_status NdisMRegisterInterrupt(ndis_miniport_interrupt *,
    ndis_handle, uint32_t, uint32_t, uint8_t, uint8_t, ndis_interrupt_mode);
static void NdisMDeregisterInterrupt(ndis_miniport_interrupt *);
static void NdisMRegisterAdapterShutdownHandler(ndis_handle, void *,
    ndis_shutdown_func);
static void NdisMDeregisterAdapterShutdownHandler(ndis_handle);
static uint32_t NDIS_BUFFER_TO_SPAN_PAGES(ndis_buffer *);
static void NdisGetBufferPhysicalArraySize(ndis_buffer *, uint32_t *);
static void NdisQueryBufferOffset(ndis_buffer *, uint32_t *, uint32_t *);
static uint32_t NdisReadPcmciaAttributeMemory(ndis_handle, uint32_t, void *,
    uint32_t);
static uint32_t NdisWritePcmciaAttributeMemory(ndis_handle, uint32_t, void *,
    uint32_t);
static list_entry *NdisInterlockedInsertHeadList(list_entry *, list_entry *,
    ndis_spin_lock *);
static list_entry *NdisInterlockedRemoveHeadList(list_entry *,
    ndis_spin_lock *);
static list_entry *NdisInterlockedInsertTailList(list_entry *, list_entry *,
    ndis_spin_lock *);
static uint8_t NdisMSynchronizeWithInterrupt(ndis_miniport_interrupt *,
    void *, void *);
static void NdisGetCurrentSystemTime(int64_t *);
static void NdisGetSystemUpTime(uint32_t *);
static void NdisInitializeString(unicode_string *, char *);
static void NdisInitAnsiString(ansi_string *, char *);
static void NdisInitUnicodeString(unicode_string *, uint16_t *);
static void NdisFreeString(unicode_string *);
static ndis_status NdisMRemoveMiniport(ndis_handle *);
static void NdisTerminateWrapper(ndis_handle, void *);
static void NdisMGetDeviceProperty(ndis_handle, device_object **,
    device_object **, device_object **, cm_resource_list *, cm_resource_list *);
static void NdisGetFirstBufferFromPacket(ndis_packet *, ndis_buffer **,
    void **, uint32_t *, uint32_t *);
static void NdisGetFirstBufferFromPacketSafe(ndis_packet *, ndis_buffer **,
    void **, uint32_t *, uint32_t *, uint32_t);
static int ndis_find_sym(linker_file_t, char *, char *, caddr_t *);
static void NdisOpenFile(ndis_status *, ndis_handle *, uint32_t *,
    unicode_string *, ndis_physaddr);
static void NdisMapFile(ndis_status *, void **, ndis_handle);
static void NdisUnmapFile(ndis_handle);
static void NdisCloseFile(ndis_handle);
static uint8_t NdisSystemProcessorCount(void);
static void NdisMIndicateStatusComplete(ndis_handle);
static void NdisMIndicateStatus(ndis_handle, ndis_status, void *, uint32_t);
static uint8_t ndis_interrupt_nic(kinterrupt *, void *);
static void ndis_intrhand(kdpc *, ndis_miniport_interrupt *, void *, void *);
static funcptr ndis_findwrap(funcptr);
static void NdisCopyFromPacketToPacket(ndis_packet *, uint32_t, uint32_t,
    ndis_packet *, uint32_t, uint32_t *);
static void NdisCopyFromPacketToPacketSafe(ndis_packet *, uint32_t, uint32_t,
    ndis_packet *, uint32_t, uint32_t *, uint32_t);
static void NdisIMCopySendPerPacketInfo(ndis_packet *, ndis_packet *);
static ndis_status NdisMRegisterDevice(ndis_handle, unicode_string *,
    unicode_string *, driver_dispatch **, void **, ndis_handle *);
static ndis_status NdisMDeregisterDevice(ndis_handle);
static ndis_status NdisMQueryAdapterInstanceName(unicode_string *, ndis_handle);
static void NdisMRegisterUnloadHandler(ndis_handle, void *);
static void dummy(void);

MALLOC_DEFINE(M_NDIS_SUBR, "ndis_subr", "ndis_subr buffers");

/*
 * Some really old drivers do not properly check the return value
 * from NdisAllocatePacket() and NdisAllocateBuffer() and will
 * sometimes allocate few more buffers/packets that they originally
 * requested when they created the pool. To prevent this from being
 * a problem, we allocate a few extra buffers/packets beyond what
 * the driver asks for. This #define controls how many.
 */
#define	NDIS_POOL_EXTRA	16
void
ndis_libinit(void)
{
	image_patch_table *patch;

	patch = ndis_functbl;
	while (patch->ipt_func != NULL) {
		windrv_wrap((funcptr)patch->ipt_func,
		    (funcptr *)&patch->ipt_wrap,
		    patch->ipt_argcnt, patch->ipt_ftype);
		patch++;
	}
}

void
ndis_libfini(void)
{
	image_patch_table *patch;

	patch = ndis_functbl;
	while (patch->ipt_func != NULL) {
		windrv_unwrap(patch->ipt_wrap);
		patch++;
	}
}

static funcptr
ndis_findwrap(funcptr func)
{
	image_patch_table *patch;

	patch = ndis_functbl;
	while (patch->ipt_func != NULL) {
		if ((funcptr)patch->ipt_func == func)
			return ((funcptr)patch->ipt_wrap);
		patch++;
	}

	return (NULL);
}

/*
 * This routine does the messy Windows Driver Model device attachment
 * stuff on behalf of NDIS drivers. We register our own AddDevice
 * routine here
 */
static void
NdisInitializeWrapper(ndis_handle *wrapper, driver_object *drv, void *path,
    void *unused)
{
	/*
	 * As of yet, I haven't come up with a compelling
	 * reason to define a private NDIS wrapper structure,
	 * so we use a pointer to the driver object as the
	 * wrapper handle. The driver object has the miniport
	 * characteristics struct for this driver hung off it
	 * via IoAllocateDriverObjectExtension(), and that's
	 * really all the private data we need.
	 */
	*wrapper = drv;

	/*
	 * If this was really Windows, we'd be registering dispatch
	 * routines for the NDIS miniport module here, but we're
	 * not Windows so all we really need to do is set up an
	 * AddDevice function that'll be invoked when a new device
	 * instance appears.
	 */
	drv->driver_extension->adddevicefunc = NdisAddDevice;
}

static void
NdisTerminateWrapper(ndis_handle handle, void *syspec)
{
	/* Nothing to see here, move along. */
}

static ndis_status
NdisMRegisterMiniport(ndis_handle handle,
    ndis_miniport_driver_characteristics *characteristics, uint32_t len)
{
	ndis_miniport_driver_characteristics *ch = NULL;
	driver_object *drv;

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
	drv = (driver_object *)handle;
	if (IoAllocateDriverObjectExtension(drv, (void *)1,
	    sizeof(ndis_miniport_driver_characteristics), (void **)&ch) !=
	    NDIS_STATUS_SUCCESS) {
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);
	}

	memset(ch, 0, sizeof(ndis_miniport_driver_characteristics));
	memcpy(ch, characteristics, len);

	return (NDIS_STATUS_SUCCESS);
}

static ndis_status
NdisAllocateMemoryWithTag(void **vaddr, uint32_t len, uint32_t tag)
{
	void *mem;

	mem = ExAllocatePoolWithTag(NonPagedPool, len, tag);
	if (mem == NULL)
		return (NDIS_STATUS_FAILURE);
	*vaddr = mem;

	return (NDIS_STATUS_SUCCESS);
}

static ndis_status
NdisAllocateMemory(void **vaddr, uint32_t len, uint32_t flags,
    ndis_physaddr highaddr)
{
	return (NdisAllocateMemoryWithTag(vaddr, len, 0));
}

static void
NdisFreeMemory(void *vaddr, uint32_t len, uint32_t flags)
{
	if (len == 0)
		return;
	ExFreePool(vaddr);
}

static ndis_status
NdisMSetAttributesEx(ndis_handle adapter_handle, ndis_handle adapter_ctx,
    uint32_t hangsecs, uint32_t flags, ndis_interface_type iftype)
{
	ndis_miniport_block *block;

	/*
	 * Save the adapter context, we need it for calling
	 * the driver's internal functions.
	 */
	block = (ndis_miniport_block *)adapter_handle;
	block->miniport_adapter_ctx = adapter_ctx;
	block->check_for_hang_secs = hangsecs;
	block->flags = flags;

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisOpenConfiguration(ndis_status *status, ndis_handle *cfg,
    ndis_handle wrapctx)
{
	*cfg = wrapctx;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisOpenConfigurationKeyByName(ndis_status *status, ndis_handle cfg,
    unicode_string *subkey, ndis_handle *subhandle)
{
	*subhandle = cfg;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisOpenConfigurationKeyByIndex(ndis_status *status, ndis_handle cfg,
    uint32_t idx, unicode_string *subkey, ndis_handle *subhandle)
{
	*status = NDIS_STATUS_FAILURE;
}

static ndis_status
ndis_encode_parm(ndis_miniport_block *block, struct sysctl_oid *oid,
    ndis_parm_type type, ndis_config_parm **parm)
{
	ndis_config_parm *p;
	ndis_parmlist_entry *np;
	unicode_string *us;
	ansi_string as;

	np = ExAllocatePoolWithTag(NonPagedPool,
	    sizeof(ndis_parmlist_entry), 0);
	if (np == NULL)
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);
	InsertHeadList((&block->parmlist), (&np->list));
	*parm = p = &np->parm;
	p->type = type;

	switch (type) {
	case ndis_parm_string:
		us = &p->parmdata.stringdata;
		RtlInitAnsiString(&as, (char *)oid->oid_arg1);
		if (RtlAnsiStringToUnicodeString(us, &as, TRUE)) {
			ExFreePool(np);
			return (NDIS_STATUS_INSUFFICIENT_RESOURCES);
		}
		break;
	case ndis_parm_int:
		p->parmdata.intdata =
		    strtol((char *)oid->oid_arg1, NULL, 0);
		break;
	case ndis_parm_hexint:
		p->parmdata.intdata =
		    strtoul((char *)oid->oid_arg1, NULL, 16);
		break;
	case ndis_parm_binary:
		p->parmdata.intdata =
		    strtoul((char *)oid->oid_arg1, NULL, 2);
		break;
	default:
		return (NDIS_STATUS_FAILURE);
	}

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisReadConfiguration(ndis_status *status, ndis_config_parm **parm,
    ndis_handle cfg, unicode_string *key, ndis_parm_type type)
{
	struct ndis_softc *sc;
	struct sysctl_oid *oidp;
	struct sysctl_ctx_entry *e;
	ndis_miniport_block *block;
	char *keystr = NULL;
	ansi_string as;

	block = (ndis_miniport_block *)cfg;
	sc = device_get_softc(block->physdeviceobj->devext);

	if (key->us_len == 0 || key->us_buf == NULL) {
		*status = NDIS_STATUS_FAILURE;
		return;
	}

	if (RtlUnicodeStringToAnsiString(&as, key, TRUE)) {
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}

	keystr = as.as_buf;

	/*
	 * See if registry key is already in a list of known keys
	 * included with the driver.
	 */
	TAILQ_FOREACH(e, device_get_sysctl_ctx(sc->ndis_dev), link) {
		oidp = e->entry;
		if (strcasecmp(oidp->oid_name, keystr) == 0) {
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
	if (type == ndis_parm_int || type == ndis_parm_hexint)
		ndis_add_sysctl(sc, keystr, "(dynamic integer key)",
		    "UNSET", CTLFLAG_RW);
	else
		ndis_add_sysctl(sc, keystr, "(dynamic string key)",
		    "UNSET", CTLFLAG_RW);

	RtlFreeAnsiString(&as);
	*status = NDIS_STATUS_FAILURE;
}

static ndis_status
ndis_decode_parm(ndis_miniport_block *block, ndis_config_parm *parm, char *val)
{
	unicode_string *ustr;
	ansi_string as;

	switch (parm->type) {
	case ndis_parm_string:
		ustr = &parm->parmdata.stringdata;
		if (RtlUnicodeStringToAnsiString(&as, ustr, TRUE))
			return (NDIS_STATUS_INSUFFICIENT_RESOURCES);
		memcpy(val, as.as_buf, as.as_len);
		RtlFreeAnsiString(&as);
		break;
	case ndis_parm_int:
		snprintf(val, sizeof(uint32_t), "%d",
		    parm->parmdata.intdata);
		break;
	case ndis_parm_hexint:
		snprintf(val, sizeof(uint32_t), "%x",
		    parm->parmdata.intdata);
		break;
	case ndis_parm_binary:
		snprintf(val, sizeof(uint32_t), "%u",
		    parm->parmdata.intdata);
		break;
	default:
		return (NDIS_STATUS_FAILURE);
	}
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisWriteConfiguration(ndis_status *status, ndis_handle cfg,
    unicode_string *key, ndis_config_parm *parm)
{
	struct ndis_softc *sc;
	struct sysctl_oid *oidp;
	struct sysctl_ctx_entry *e;
	ansi_string as;
	char *keystr = NULL, val[256];
	ndis_miniport_block *block;

	block = (ndis_miniport_block *)cfg;
	sc = device_get_softc(block->physdeviceobj->devext);

	if (RtlUnicodeStringToAnsiString(&as, key, TRUE)) {
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}

	keystr = as.as_buf;

	memset(val, 0, sizeof(val));
	*status = ndis_decode_parm(block, parm, val);
	if (*status != NDIS_STATUS_SUCCESS) {
		RtlFreeAnsiString(&as);
		return;
	}

	TAILQ_FOREACH(e, device_get_sysctl_ctx(sc->ndis_dev), link) {
		oidp = e->entry;
		if (strcasecmp(oidp->oid_name, keystr) == 0) {
			strcpy((char *)oidp->oid_arg1, val);
			RtlFreeAnsiString(&as);
			return;
		}
	}

	ndis_add_sysctl(sc, keystr, "(dynamically set key)", val, CTLFLAG_RW);
	RtlFreeAnsiString(&as);
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisCloseConfiguration(ndis_handle cfg)
{
	list_entry *e;
	ndis_parmlist_entry *pe;
	ndis_miniport_block *block;
	ndis_config_parm *p;

	block = (ndis_miniport_block *)cfg;
	while (!IsListEmpty(&block->parmlist)) {
		e = RemoveHeadList(&block->parmlist);
		pe = CONTAINING_RECORD(e, ndis_parmlist_entry, list);
		p = &pe->parm;
		if (p->type == ndis_parm_string)
			RtlFreeUnicodeString(&p->parmdata.stringdata);
		ExFreePool(e);
	}
}

/*
 * Initialize a Windows spinlock.
 */
static void
NdisAllocateSpinLock(ndis_spin_lock *lock)
{
	KeInitializeSpinLock(&lock->nsl_spinlock);
	lock->nsl_kirql = 0;
}

/*
 * Destroy a Windows spinlock. This is a no-op for now. There are two reasons
 * for this. One is that it's sort of superfluous: we don't have to do anything
 * special to deallocate the spinlock. The other is that there are some buggy
 * drivers which call NdisFreeSpinLock() _after_ calling NdisFreeMemory() on
 * the block of memory in which the spinlock resides. (Yes, ADMtek, I'm
 * talking to you.)
 */
static void
NdisFreeSpinLock(ndis_spin_lock *lock)
{
#ifdef notdef
	KeInitializeSpinLock(&lock->nsl_spinlock);
	lock->nsl_kirql = 0;
#endif
}

/*
 * Acquire a spinlock from IRQL <= DISPATCH_LEVEL.
 */
static void
NdisAcquireSpinLock(ndis_spin_lock *lock)
{
	KeAcquireSpinLock(&lock->nsl_spinlock, &lock->nsl_kirql);
}

/*
 * Release a spinlock from IRQL == DISPATCH_LEVEL.
 */
static void
NdisReleaseSpinLock(ndis_spin_lock *lock)
{
	KeReleaseSpinLock(&lock->nsl_spinlock, lock->nsl_kirql);
}

/*
 * Acquire a spinlock when already running at IRQL == DISPATCH_LEVEL.
 */
static void
NdisDprAcquireSpinLock(ndis_spin_lock *lock)
{
	KeAcquireSpinLockAtDpcLevel(&lock->nsl_spinlock);
}

/*
 * Release a spinlock without leaving IRQL == DISPATCH_LEVEL.
 */
static void
NdisDprReleaseSpinLock(ndis_spin_lock *lock)
{
	KeReleaseSpinLockFromDpcLevel(&lock->nsl_spinlock);
}

static void
NdisInitializeReadWriteLock(ndis_rw_lock *lock)
{
	KeInitializeSpinLock(&lock->u.spinlock);
	memset(&lock->reserved, 0, sizeof(lock->reserved));
}

static void
NdisAcquireReadWriteLock(ndis_rw_lock *lock, uint8_t writeacc,
    ndis_lock_state *state)
{
	if (writeacc == TRUE) {
		KeAcquireSpinLock(&lock->u.spinlock, &state->oldirql);
		lock->reserved[0]++;
	} else
		lock->reserved[1]++;
}

static void
NdisReleaseReadWriteLock(ndis_rw_lock *lock, ndis_lock_state *state)
{
	if (lock->reserved[0]) {
		lock->reserved[0]--;
		KeReleaseSpinLock(&lock->u.spinlock, state->oldirql);
	} else
		lock->reserved[1]--;
}

static uint32_t
NdisReadPciSlotInformation(ndis_handle adapter, uint32_t slot,
    uint32_t offset, void *buf, uint32_t len)
{
	ndis_miniport_block *block;
	device_t dev;
	int i;
	char *dest = buf;

	KASSERT(adapter != NULL, ("no adapter"));
	block = (ndis_miniport_block *)adapter;
	dev = block->physdeviceobj->devext;
	for (i = 0; i < len; i++)
		dest[i] = pci_read_config(dev, i + offset, 1);

	return (len);
}

static uint32_t
NdisWritePciSlotInformation(ndis_handle adapter, uint32_t slot,
    uint32_t offset, void *buf, uint32_t len)
{
	ndis_miniport_block *block;
	device_t dev;
	int i;
	char *dest = buf;

	KASSERT(adapter != NULL, ("no adapter"));
	block = (ndis_miniport_block *)adapter;
	dev = block->physdeviceobj->devext;
	for (i = 0; i < len; i++)
		pci_write_config(dev, i + offset, dest[i], 1);

	return (len);
}

/*
 * The errorlog routine uses a variable argument list, so we
 * have to declare it this way.
 */
#define	ERRMSGLEN	512
static void
NdisWriteErrorLogEntry(ndis_handle adapter, ndis_error_code code,
    uint32_t numerrors, ...)
{
	struct ifnet *ifp;
	struct ndis_softc *sc;
	ndis_miniport_block *block;
	device_t dev;
	driver_object *drv;
	va_list ap;
	int i;
	char *str = NULL;
	uint16_t flags;
	unicode_string us;
	ansi_string as = { 0, 0, NULL };

	block = (ndis_miniport_block *)adapter;
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
					str = as.as_buf;
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

	if (as.as_len)
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
		ctx->fraglist[i].physaddr.quad = segs[i].ds_addr;
		ctx->fraglist[i].len = segs[i].ds_len;
	}

	ctx->cnt = nseg;
}

static void
NdisMStartBufferPhysicalMapping(ndis_handle adapter, ndis_buffer *buf,
    uint32_t mapreg, uint8_t writedev, ndis_paddr_unit *addrarray,
    uint32_t *arraysize)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;
	struct ndis_map_arg nma;
	bus_dmamap_t map;

	if (adapter == NULL)
		return;

	block = (ndis_miniport_block *)adapter;
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
NdisMCompleteBufferPhysicalMapping(ndis_handle adapter, ndis_buffer *buf,
    uint32_t mapreg)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;
	bus_dmamap_t map;

	if (adapter == NULL)
		return;

	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);

	if (mapreg > sc->ndis_mmapcnt)
		return;

	map = sc->ndis_mmaps[mapreg];

	bus_dmamap_sync(sc->ndis_mtag, map,
	    BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE);

	bus_dmamap_unload(sc->ndis_mtag, map);
}

/*
 * This is an older (?) timer init routine which doesn't
 * accept a miniport context handle. Serialized miniports should
 * never call this function.
 */
static void
NdisInitializeTimer(ndis_timer *timer, ndis_timer_function func, void *ctx)
{
	KeInitializeTimer(&timer->nt_ktimer);
	KeInitializeDpc(&timer->nt_kdpc, func, ctx);
	KeSetImportanceDpc(&timer->nt_kdpc, KDPC_IMPORTANCE_LOW);
}

static void
ndis_timercall(kdpc *dpc, ndis_miniport_timer *timer, void *sysarg1,
    void *sysarg2)
{
	/*
	 * Since we're called as a DPC, we should be running
	 * at DISPATCH_LEVEL here. This means to acquire the
	 * spinlock, we can use KeAcquireSpinLockAtDpcLevel()
	 * rather than KeAcquireSpinLock().
	 */
	if (NDIS_SERIALIZED(timer->nmt_block))
		KeAcquireSpinLockAtDpcLevel(&timer->nmt_block->lock);
	MSCALL4(timer->nmt_timerfunc, dpc, timer->nmt_timerctx,
	    sysarg1, sysarg2);
	if (NDIS_SERIALIZED(timer->nmt_block))
		KeReleaseSpinLockFromDpcLevel(&timer->nmt_block->lock);
}

/*
 * For a long time I wondered why there were two NDIS timer initialization
 * routines, and why this one needed an NDIS_MINIPORT_TIMER and the
 * MiniportAdapterHandle. The NDIS_MINIPORT_TIMER has its own callout
 * function and context pointers separate from those in the DPC, which
 * allows for another level of indirection: when the timer fires, we
 * can have our own timer function invoked, and from there we can call
 * the driver's function. But why go to all that trouble? Then it hit
 * me: for serialized miniports, the timer callouts are not re-entrant.
 * By trapping the callouts and having access to the MiniportAdapterHandle,
 * we can protect the driver callouts by acquiring the NDIS serialization
 * lock. This is essential for allowing serialized miniports to work
 * correctly on SMP systems. On UP hosts, setting IRQL to DISPATCH_LEVEL
 * is enough to prevent other threads from pre-empting you, but with
 * SMP, you must acquire a lock as well, otherwise the other CPU is
 * free to clobber you.
 */
static void
NdisMInitializeTimer(ndis_miniport_timer *timer, ndis_handle handle,
    ndis_timer_function func, void *ctx)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;

	block = (ndis_miniport_block *)handle;
	sc = device_get_softc(block->physdeviceobj->devext);

	/* Save the driver's funcptr and context */
	timer->nmt_timerfunc = func;
	timer->nmt_timerctx = ctx;
	timer->nmt_block = handle;

	/*
	 * Set up the timer so it will call our intermediate DPC.
	 * Be sure to use the wrapped entry point, since
	 * ntoskrnl_run_dpc() expects to invoke a function with
	 * Microsoft calling conventions.
	 */
	KeInitializeTimer(&timer->nmt_ktimer);
	KeInitializeDpc(&timer->nmt_kdpc,
	    ndis_findwrap((funcptr)ndis_timercall), timer);
	timer->nmt_ktimer.k_dpc = &timer->nmt_kdpc;
}

/*
 * In Windows, there's both an NdisMSetTimer() and an NdisSetTimer(),
 * but the former is just a macro wrapper around the latter.
 */
static void
NdisSetTimer(ndis_timer *timer, uint32_t msecs)
{
	/*
	 * KeSetTimer() wants the period in
	 * hundred nanosecond intervals.
	 */
	KeSetTimer(&timer->nt_ktimer,
	    ((int64_t)msecs * -10000), &timer->nt_kdpc);
}

static void
NdisMSetPeriodicTimer(ndis_miniport_timer *timer, uint32_t msecs)
{
	KeSetTimerEx(&timer->nmt_ktimer,
	    ((int64_t)msecs * -10000), msecs, &timer->nmt_kdpc);
}

/*
 * Technically, this is really NdisCancelTimer(), but we also
 * (ab)use it for NdisMCancelTimer(), since in our implementation
 * we don't need the extra info in the ndis_miniport_timer
 * structure just to cancel a timer.
 */
static void
NdisMCancelTimer(ndis_timer *timer, uint8_t *cancelled)
{
	*cancelled = KeCancelTimer(&timer->nt_ktimer);
}

static void
NdisMQueryAdapterResources(ndis_status *status, ndis_handle adapter,
    cm_partial_resource_list *list, uint32_t *buflen)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;
	uint32_t rsclen;

	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);

	rsclen = sizeof(cm_partial_resource_list) +
	    (sizeof(cm_partial_resource_desc) * (sc->ndis_rescnt - 1));
	if (*buflen < rsclen) {
		*buflen = rsclen;
		*status = NDIS_STATUS_INVALID_LENGTH;
		return;
	}

	memcpy(list, block->rlist, rsclen);
	*status = NDIS_STATUS_SUCCESS;
}

static ndis_status
NdisMRegisterIoPortRange(void **offset, ndis_handle adapter, uint32_t port,
    uint32_t numports)
{
	struct ndis_miniport_block *block;
	struct ndis_softc *sc;

	if (adapter == NULL)
		return (NDIS_STATUS_FAILURE);

	block = (ndis_miniport_block *)adapter;
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
NdisMDeregisterIoPortRange(ndis_handle adapter, uint32_t port,
    uint32_t numports, void *offset)
{
}

static void
NdisReadNetworkAddress(ndis_status *status, void **addr, uint32_t *addrlen,
    ndis_handle adapter)
{
	struct ndis_softc *sc;
	ndis_miniport_block *block;
	uint8_t empty[] = { 0, 0, 0, 0, 0, 0 };

	block = (ndis_miniport_block *)adapter;
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

static ndis_status
NdisQueryMapRegisterCount(uint32_t bustype, uint32_t *cnt)
{
	*cnt = 8192;
	return (NDIS_STATUS_SUCCESS);
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

static ndis_status
NdisMAllocateMapRegisters(ndis_handle adapter, uint32_t dmachannel,
    uint8_t dmasize, uint32_t physmapneeded, uint32_t maxmap)
{
	struct ndis_softc *sc;
	ndis_miniport_block *block;
	int i, nseg = NDIS_MAXSEG;

	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);

	sc->ndis_mmaps = malloc(sizeof(bus_dmamap_t) * physmapneeded,
	    M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (sc->ndis_mmaps == NULL)
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);

	if (bus_dma_tag_create(sc->ndis_parent_tag,
			ETHER_ALIGN, 0,
			ndis_dmasize(dmasize),
			BUS_SPACE_MAXADDR,
			NULL, NULL,
			maxmap * nseg,
			nseg,
			maxmap,
			BUS_DMA_ALLOCNOW,
			NULL,
			NULL,
			&sc->ndis_mtag) != 0) {
		free(sc->ndis_mmaps, M_NDIS_SUBR);
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);
	}

	for (i = 0; i < physmapneeded; i++)
		bus_dmamap_create(sc->ndis_mtag, 0, &sc->ndis_mmaps[i]);

	sc->ndis_mmapcnt = physmapneeded;

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMFreeMapRegisters(ndis_handle adapter)
{
	struct ndis_softc *sc;
	ndis_miniport_block *block;
	int i;

	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);

	for (i = 0; i < sc->ndis_mmapcnt; i++)
		bus_dmamap_destroy(sc->ndis_mtag, sc->ndis_mmaps[i]);

	free(sc->ndis_mmaps, M_NDIS_SUBR);

	bus_dma_tag_destroy(sc->ndis_mtag);
}

static void
ndis_mapshared_cb(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	ndis_physaddr *p;

	if (error || nseg > 1)
		return;

	p = arg;
	p->quad = segs[0].ds_addr;
}

/*
 * This maps to bus_dmamem_alloc().
 */
static void
NdisMAllocateSharedMemory(ndis_handle adapter, uint32_t len, uint8_t cached,
    void **vaddr, ndis_physaddr *paddr)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;
	struct ndis_shmem *sh;

	if (adapter == NULL)
		return;

	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);

	sh = malloc(sizeof(struct ndis_shmem), M_NDIS_SUBR, M_NOWAIT|M_ZERO);
	if (sh == NULL)
		return;

	InitializeListHead(&sh->ndis_list);

	if (bus_dma_tag_create(sc->ndis_parent_tag,
			64, 0,
			BUS_SPACE_MAXADDR_32BIT,
			BUS_SPACE_MAXADDR,
			NULL, NULL,
			len,
			1,
			len,
			BUS_DMA_ALLOCNOW,
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
	    len, ndis_mapshared_cb, (void *)paddr, BUS_DMA_NOWAIT) != 0) {
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
	sh->ndis_paddr.quad = paddr->quad;
	sh->ndis_saddr = *vaddr;
	InsertHeadList((&sc->ndis_shlist), (&sh->ndis_list));
	NDIS_UNLOCK(sc);
}

struct ndis_allocwork {
	uint32_t		na_len;
	uint8_t			na_cached;
	void			*na_ctx;
	io_workitem		*na_iw;
};

static void
ndis_asyncmem_complete(device_object *dobj, void *arg)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;
	struct ndis_allocwork *w;
	void *vaddr;
	ndis_physaddr paddr;

	w = arg;
	block = (ndis_miniport_block *)dobj->devext;
	sc = device_get_softc(block->physdeviceobj->devext);

	vaddr = NULL;
	paddr.quad = 0;

	NdisMAllocateSharedMemory(block, w->na_len,
	    w->na_cached, &vaddr, &paddr);
	KASSERT(block != NULL, ("no block"));
	KASSERT(sc->ndis_chars->allocate_complete_func != NULL,
	    ("no allocate_complete"));
	MSCALL5(sc->ndis_chars->allocate_complete_func,
	    block, vaddr, &paddr, w->na_len, w->na_ctx);

	IoFreeWorkItem(w->na_iw);
	free(w, M_NDIS_SUBR);
}

static ndis_status
NdisMAllocateSharedMemoryAsync(ndis_handle adapter, uint32_t len,
    uint8_t cached, void *ctx)
{
	ndis_miniport_block *block;
	struct ndis_allocwork *w;
	io_workitem *iw;
	io_workitem_func ifw;

	if (adapter == NULL)
		return (NDIS_STATUS_FAILURE);
	block = adapter;

	w = malloc(sizeof(struct ndis_allocwork), M_NDIS_SUBR, M_NOWAIT);
	if (w == NULL)
		return (NDIS_STATUS_FAILURE);

	iw = IoAllocateWorkItem(block->deviceobj);
	if (iw == NULL) {
		free(w, M_NDIS_SUBR);
		return (NDIS_STATUS_FAILURE);
	}

	w->na_cached = cached;
	w->na_len = len;
	w->na_ctx = ctx;
	w->na_iw = iw;

	ifw = (io_workitem_func)ndis_findwrap((funcptr)ndis_asyncmem_complete);
	IoQueueWorkItem(iw, ifw, WORKQUEUE_DELAYED, w);

	return (NDIS_STATUS_PENDING);
}

static void
NdisMFreeSharedMemory(ndis_handle adapter, uint32_t len, uint8_t cached,
    void *vaddr, ndis_physaddr paddr)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;
	struct ndis_shmem *sh = NULL;
	list_entry *l;

	if (vaddr == NULL || adapter == NULL)
		return;

	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);

	/* Sanity check: is list empty? */
	if (IsListEmpty(&sc->ndis_shlist))
		return;

	NDIS_LOCK(sc);
	l = sc->ndis_shlist.nle_flink;
	while (l != &sc->ndis_shlist) {
		sh = CONTAINING_RECORD(l, struct ndis_shmem, ndis_list);
		if (sh->ndis_saddr == vaddr)
			break;
		/*
		 * Check the physaddr too, just in case the driver lied
		 * about the virtual address.
		 */
		if (sh->ndis_paddr.quad == paddr.quad)
			break;
		l = l->nle_flink;
	}

	if (sh == NULL) {
		NDIS_UNLOCK(sc);
		printf("NDIS: buggy driver tried to free "
		    "invalid shared memory: vaddr: %p paddr: 0x%jx\n",
		    vaddr, (uintmax_t)paddr.quad);
		return;
	}

	RemoveEntryList(&sh->ndis_list);

	NDIS_UNLOCK(sc);

	bus_dmamap_unload(sh->ndis_stag, sh->ndis_smap);
	bus_dmamem_free(sh->ndis_stag, sh->ndis_saddr, sh->ndis_smap);
	bus_dma_tag_destroy(sh->ndis_stag);

	free(sh, M_NDIS_SUBR);
}

static ndis_status
NdisMMapIoSpace(void **vaddr, ndis_handle adapter, ndis_physaddr paddr,
    uint32_t len)
{
	if (adapter == NULL)
		return (NDIS_STATUS_FAILURE);

	*vaddr = MmMapIoSpace(paddr.quad, len, 0);
	if (*vaddr == NULL)
		return (NDIS_STATUS_FAILURE);

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMUnmapIoSpace(ndis_handle adapter, void *vaddr, uint32_t len)
{
	MmUnmapIoSpace(vaddr, len);
}

static uint32_t
NdisGetCacheFillSize(void)
{
	return (128);
}

static uint32_t
NdisMGetDmaAlignment(ndis_handle handle)
{
	return (16);
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
static ndis_status
NdisMInitializeScatterGatherDma(ndis_handle adapter, uint8_t is64,
    uint32_t maxphysmap)
{
	struct ndis_softc *sc;
	ndis_miniport_block *block;

	if (adapter == NULL)
		return (NDIS_STATUS_FAILURE);
	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);

	/* Don't do this twice. */
	if (sc->ndis_sc == 1)
		return (NDIS_STATUS_SUCCESS);

	if (bus_dma_tag_create(sc->ndis_parent_tag,
			ETHER_ALIGN, 0,
			BUS_SPACE_MAXADDR_32BIT,
			BUS_SPACE_MAXADDR,
			NULL, NULL,
			MCLBYTES * NDIS_MAXSEG,
			NDIS_MAXSEG,
			MCLBYTES,
			BUS_DMA_ALLOCNOW,
			NULL,
			NULL,
			&sc->ndis_ttag) != 0)
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);

	sc->ndis_sc = 1;

	return (NDIS_STATUS_SUCCESS);
}

void
NdisAllocatePacketPool(ndis_status *status, ndis_handle *pool,
    uint32_t descnum, uint32_t protrsvdlen)
{
	ndis_packet_pool *p;
	ndis_packet *packets;
	int i;

	p = ExAllocatePoolWithTag(NonPagedPool, sizeof(ndis_packet_pool), 0);
	if (p == NULL) {
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}

	p->cnt = descnum + NDIS_POOL_EXTRA;
	p->len = sizeof(ndis_packet) + protrsvdlen;

	packets = ExAllocatePoolWithTag(NonPagedPool, p->cnt *
	    p->len, 0);
	if (packets == NULL) {
		ExFreePool(p);
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}

	p->pktmem = packets;

	for (i = 0; i < p->cnt; i++)
		InterlockedPushEntrySList(&p->head,
		    (struct slist_entry *)&packets[i]);

#ifdef NDIS_DEBUG_PACKETS
	p->dead = 0;
	KeInitializeSpinLock(&p->lock);
	KeInitializeEvent(&p->event, EVENT_TYPE_NOTIFY, TRUE);
#endif

	*pool = p;
	*status = NDIS_STATUS_SUCCESS;
}

void
NdisAllocatePacketPoolEx(ndis_status *status, ndis_handle *pool,
    uint32_t descnum, uint32_t oflowdescnum, uint32_t protrsvdlen)
{
	return (NdisAllocatePacketPool(status, pool,
	    descnum + oflowdescnum, protrsvdlen));
}

uint32_t
NdisPacketPoolUsage(ndis_handle pool)
{
	ndis_packet_pool *p;

	p = (ndis_packet_pool *)pool;

	return (p->cnt - ExQueryDepthSList(&p->head));
}

void
NdisFreePacketPool(ndis_handle pool)
{
	ndis_packet_pool *p;
	int usage;
#ifdef NDIS_DEBUG_PACKETS
	uint8_t irql;
#endif
	p = (ndis_packet_pool *)pool;
#ifdef NDIS_DEBUG_PACKETS
	KeAcquireSpinLock(&p->lock, &irql);
#endif
	usage = NdisPacketPoolUsage(pool);
#ifdef NDIS_DEBUG_PACKETS
	if (usage) {
		p->dead = 1;
		KeResetEvent(&p->event);
		KeReleaseSpinLock(&p->lock, irql);
		KeWaitForSingleObject(&p->event, 0, 0, FALSE, NULL);
	} else
		KeReleaseSpinLock(&p->lock, irql);
#endif
	ExFreePool(p->pktmem);
	ExFreePool(p);
}

void
NdisAllocatePacket(ndis_status *status, ndis_packet **packet, ndis_handle pool)
{
	ndis_packet_pool *p;
	ndis_packet *pkt;
#ifdef NDIS_DEBUG_PACKETS
	uint8_t irql;
#endif
	p = (ndis_packet_pool *)pool;
#ifdef NDIS_DEBUG_PACKETS
	KeAcquireSpinLock(&p->lock, &irql);
	if (p->dead) {
		KeReleaseSpinLock(&p->lock, irql);
		printf("NDIS: tried to allocate packet from dead pool %p\n",
		    pool);
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}
#endif
	pkt = (ndis_packet *)InterlockedPopEntrySList(&p->head);
#ifdef NDIS_DEBUG_PACKETS
	KeReleaseSpinLock(&p->lock, irql);
#endif
	if (pkt == NULL) {
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}
	memset(pkt, 0, sizeof(ndis_packet));

	/* Save pointer to the pool. */
	pkt->private.pool = pool;

	/* Set the oob offset pointer. Lots of things expect this. */
	pkt->private.packetooboffset = offsetof(ndis_packet, oob);

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
NdisFreePacket(ndis_packet *packet)
{
	ndis_packet_pool *p;
#ifdef NDIS_DEBUG_PACKETS
	uint8_t irql;
#endif
	p = (ndis_packet_pool *)packet->private.pool;

#ifdef NDIS_DEBUG_PACKETS
	KeAcquireSpinLock(&p->lock, &irql);
#endif
	InterlockedPushEntrySList(&p->head, (slist_entry *)packet);

#ifdef NDIS_DEBUG_PACKETS
	if (p->dead) {
		if (ExQueryDepthSList(&p->head) == p->cnt)
			KeSetEvent(&p->event, IO_NO_INCREMENT, FALSE);
	}
	KeReleaseSpinLock(&p->lock, irql);
#endif
}

static void
NdisUnchainBufferAtFront(ndis_packet *packet, ndis_buffer **buf)
{
	ndis_packet_private *priv;

	if (packet == NULL || buf == NULL)
		return;
	priv = &packet->private;
	priv->validcounts = FALSE;
	if (priv->head == priv->tail) {
		*buf = priv->head;
		priv->head = priv->tail = NULL;
	} else {
		*buf = priv->head;
		priv->head = (*buf)->mdl_next;
	}
}

static void
NdisUnchainBufferAtBack(ndis_packet *packet, ndis_buffer **buf)
{
	ndis_packet_private *priv;
	ndis_buffer *tmp;

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
		while (tmp->mdl_next != priv->tail)
			tmp = tmp->mdl_next;
		priv->tail = tmp;
		tmp->mdl_next = NULL;
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
NdisAllocateBufferPool(ndis_status *status, ndis_handle *pool,
    uint32_t descnum)
{
	/*
	 * The only thing we can really do here is verify that descnum
	 * is a reasonable value, but I really don't know what to check
	 * it against.
	 */
	*pool = NonPagedPool;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisFreeBufferPool(ndis_handle pool)
{
}

static void
NdisAllocateBuffer(ndis_status *status, ndis_buffer **buffer, ndis_handle pool,
    void *vaddr, uint32_t len)
{
	ndis_buffer *buf;

	buf = IoAllocateMdl(vaddr, len, FALSE, FALSE, NULL);
	if (buf == NULL) {
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}
	MmBuildMdlForNonPagedPool(buf);

	*buffer = buf;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisFreeBuffer(ndis_buffer *buf)
{
	IoFreeMdl(buf);
}

/* Aw c'mon. */
static uint32_t
NdisBufferLength(ndis_buffer *buf)
{
	return (MmGetMdlByteCount(buf));
}

/*
 * Get the virtual address and length of a buffer.
 * Note: the vaddr argument is optional.
 */
static void
NdisQueryBuffer(buf, vaddr, len)
	ndis_buffer		*buf;
	void			**vaddr;
	uint32_t		*len;
{
	if (vaddr != NULL)
		*vaddr = MmGetMdlVirtualAddress(buf);
	*len = MmGetMdlByteCount(buf);
}

/* Same as above -- we don't care about the priority. */
static void
NdisQueryBufferSafe(ndis_buffer *buf, void **vaddr, uint32_t *len,
    uint32_t prio)
{
	if (vaddr != NULL)
		*vaddr = MmGetMdlVirtualAddress(buf);
	*len = MmGetMdlByteCount(buf);
}

/* Damnit Microsoft!! How many ways can you do the same thing?! */
static void *
NdisBufferVirtualAddress(ndis_buffer *buf)
{
	return (MmGetMdlVirtualAddress(buf));
}

static void *
NdisBufferVirtualAddressSafe(ndis_buffer *buf, uint32_t prio)
{
	return (MmGetMdlVirtualAddress(buf));
}

static void
NdisAdjustBufferLength(ndis_buffer *buf, uint32_t len)
{
	MmGetMdlByteCount(buf) = len;
}

static uint32_t
NdisInterlockedIncrement(uint32_t *addend)
{
	atomic_add_long((unsigned long *)addend, 1);

	return (*addend);
}

static uint32_t
NdisInterlockedDecrement(uint32_t *addend)
{
	atomic_subtract_long((unsigned long *)addend, 1);

	return (*addend);
}

static void
NdisInitializeEvent(ndis_event *event)
{
	/*
	 * NDIS events are always notification
	 * events, and should be initialized to the
	 * not signaled state.
	 */
	KeInitializeEvent(&event->ne_event, EVENT_TYPE_NOTIFY, FALSE);
}

static void
NdisSetEvent(ndis_event *event)
{
	KeSetEvent(&event->ne_event, IO_NO_INCREMENT, FALSE);
}

static void
NdisResetEvent(ndis_event *event)
{
	KeResetEvent(&event->ne_event);
}

static uint8_t
NdisWaitEvent(ndis_event *event, uint32_t msecs)
{
	int64_t duetime;
	uint32_t rval;

	duetime = ((int64_t)msecs * -10000);
	rval = KeWaitForSingleObject(event,
	    0, 0, TRUE, msecs ? & duetime : NULL);
	if (rval == NDIS_STATUS_TIMEOUT)
		return (FALSE);

	return (TRUE);
}

static ndis_status
NdisUnicodeStringToAnsiString(ansi_string *dstr, unicode_string *sstr)
{
	uint32_t rval;

	rval = RtlUnicodeStringToAnsiString(dstr, sstr, FALSE);
	if (rval == NDIS_STATUS_INSUFFICIENT_RESOURCES)
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);
	if (rval)
		return (NDIS_STATUS_FAILURE);

	return (NDIS_STATUS_SUCCESS);
}

static ndis_status
NdisAnsiStringToUnicodeString(unicode_string *dstr, ansi_string *sstr)
{
	uint32_t rval;

	rval = RtlAnsiStringToUnicodeString(dstr, sstr, FALSE);
	if (rval == NDIS_STATUS_INSUFFICIENT_RESOURCES)
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);
	if (rval)
		return (NDIS_STATUS_FAILURE);

	return (NDIS_STATUS_SUCCESS);
}

static ndis_status
NdisMPciAssignResources(ndis_handle adapter, uint32_t slot,
    cm_partial_resource_list **list)
{
	ndis_miniport_block *block;

	if (adapter == NULL || list == NULL)
		return (NDIS_STATUS_FAILURE);
	block = (ndis_miniport_block *)adapter;
	*list = block->rlist;

	return (NDIS_STATUS_SUCCESS);
}

static uint8_t
ndis_interrupt_nic(kinterrupt *iobj, void *arg)
{
	struct ndis_softc *sc = arg;
	uint8_t is_our_intr = FALSE;
	int call_isr = 0;

	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL,
	    ("no adapter"));
	if (sc->ndis_block->interrupt == NULL)
		return (FALSE);
	if (sc->ndis_block->interrupt->isr_requested == TRUE)
		MSCALL3(sc->ndis_block->interrupt->isr_func,
		    &is_our_intr, &call_isr,
		    sc->ndis_block->miniport_adapter_ctx);
	else {
		ndis_disable_interrupts_nic(sc);
		call_isr = 1;
	}
	if (call_isr)
		IoRequestDpc(sc->ndis_block->deviceobj, NULL, sc);
	return (is_our_intr);
}

static void
ndis_intrhand(kdpc *dpc, ndis_miniport_interrupt *intr, void *sysarg1,
    void *sysarg2)
{
	struct ndis_softc *sc;

	KASSERT(intr != NULL, ("no intr"));
	KASSERT(intr->block != NULL, ("no block"));
	KASSERT(intr->block->miniport_adapter_ctx != NULL,
	    ("no adapter"));
	sc = device_get_softc(intr->block->physdeviceobj->devext);
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeAcquireSpinLockAtDpcLevel(&intr->block->lock);
	MSCALL1(intr->dpc_func, intr->block->miniport_adapter_ctx);
	ndis_enable_interrupts_nic(sc);
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeReleaseSpinLockFromDpcLevel(&intr->block->lock);

	/*
	 * Set the completion event if we've drained all
	 * pending interrupts.
	 */
	KeAcquireSpinLockAtDpcLevel(&intr->dpc_count_lock);
	intr->dpc_count--;
	if (intr->dpc_count == 0)
		KeSetEvent(&intr->dpcs_completed_event,
		    IO_NO_INCREMENT, FALSE);
	KeReleaseSpinLockFromDpcLevel(&intr->dpc_count_lock);
}

static ndis_status
NdisMRegisterInterrupt(ndis_miniport_interrupt *intr, ndis_handle adapter,
    uint32_t ivec, uint32_t ilevel, uint8_t reqisr, uint8_t shared,
    ndis_interrupt_mode imode)
{
	ndis_miniport_block *block = adapter;
	ndis_miniport_driver_characteristics *ch;
	struct ndis_softc *sc;

	sc = device_get_softc(block->physdeviceobj->devext);
	ch = IoGetDriverObjectExtension(block->deviceobj->drvobj,
	    (void *)1);
	if (ch == NULL)
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);

	intr->block = adapter;
	intr->isr_requested = reqisr;
	intr->shared_interrupt = shared;
	intr->dpc_count = 0;
	intr->isr_func = ch->isr_func;
	intr->dpc_func = ch->interrupt_func;

	KeInitializeEvent(&intr->dpcs_completed_event,
	    EVENT_TYPE_NOTIFY, TRUE);
	KeInitializeDpc(&intr->interrupt_dpc,
	    ndis_findwrap((funcptr)ndis_intrhand), intr);
	KeSetImportanceDpc(&intr->interrupt_dpc, KDPC_IMPORTANCE_LOW);

	if (IoConnectInterrupt(&intr->interrupt_object,
	    ndis_findwrap((funcptr)ndis_interrupt_nic), sc, NULL,
	    ivec, ilevel, 0, imode, shared, 0, FALSE) != NDIS_STATUS_SUCCESS)
		return (NDIS_STATUS_FAILURE);

	block->interrupt = intr;

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMDeregisterInterrupt(ndis_miniport_interrupt *intr)
{
	uint8_t irql;

	/* Should really be KeSynchronizeExecution() */
	KeAcquireSpinLock(intr->interrupt_object->ki_lock, &irql);
	intr->block->interrupt = NULL;
	KeReleaseSpinLock(intr->interrupt_object->ki_lock, irql);
/*
	KeFlushQueuedDpcs();
*/
	/* Disconnect our ISR */
	IoDisconnectInterrupt(intr->interrupt_object);

	KeWaitForSingleObject(&intr->dpcs_completed_event,
	    0, 0, FALSE, NULL);
	KeResetEvent(&intr->dpcs_completed_event);
}

static void
NdisMRegisterAdapterShutdownHandler(ndis_handle adapter, void *shutdownctx,
    ndis_shutdown_func shutdownfunc)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;

	if (adapter == NULL)
		return;
	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);
	sc->ndis_chars->shutdown_func = shutdownfunc;
	sc->ndis_chars->reserved0 = shutdownctx;
}

static void
NdisMDeregisterAdapterShutdownHandler(ndis_handle adapter)
{
	ndis_miniport_block *block;
	struct ndis_softc *sc;

	if (adapter == NULL)
		return;
	block = (ndis_miniport_block *)adapter;
	sc = device_get_softc(block->physdeviceobj->devext);
	sc->ndis_chars->shutdown_func = NULL;
	sc->ndis_chars->reserved0 = NULL;
}

static uint32_t
NDIS_BUFFER_TO_SPAN_PAGES(ndis_buffer *buf)
{
	if (buf == NULL)
		return (0);
	if (MmGetMdlByteCount(buf) == 0)
		return (1);
	return (SPAN_PAGES(MmGetMdlVirtualAddress(buf),
	    MmGetMdlByteCount(buf)));
}

static void
NdisGetBufferPhysicalArraySize(ndis_buffer *buf, uint32_t *pages)
{
	if (buf == NULL)
		return;
	*pages = NDIS_BUFFER_TO_SPAN_PAGES(buf);
}

static void
NdisQueryBufferOffset(ndis_buffer *buf, uint32_t *off, uint32_t *len)
{
	if (buf == NULL)
		return;
	*off = MmGetMdlByteOffset(buf);
	*len = MmGetMdlByteCount(buf);
}

static void
NdisMSleep(uint32_t usecs)
{
	DELAY(usecs);
}

static uint32_t
NdisReadPcmciaAttributeMemory(ndis_handle handle, uint32_t offset, void *buf,
    uint32_t len)
{
	struct ndis_softc *sc;
	ndis_miniport_block *block;
	bus_space_handle_t bh;
	bus_space_tag_t bt;
	char *dest;
	int i;

	if (handle == NULL)
		return (0);
	block = (ndis_miniport_block *)handle;
	sc = device_get_softc(block->physdeviceobj->devext);
	dest = buf;

	bh = rman_get_bushandle(sc->ndis_res_am);
	bt = rman_get_bustag(sc->ndis_res_am);

	for (i = 0; i < len; i++)
		dest[i] = bus_space_read_1(bt, bh, (offset + i) * 2);

	return (i);
}

static uint32_t
NdisWritePcmciaAttributeMemory(ndis_handle handle, uint32_t offset,
    void *buf, uint32_t len)
{
	struct ndis_softc *sc;
	ndis_miniport_block *block;
	bus_space_handle_t bh;
	bus_space_tag_t bt;
	char *src;
	int i;

	if (handle == NULL)
		return (0);
	block = (ndis_miniport_block *)handle;
	sc = device_get_softc(block->physdeviceobj->devext);
	src = buf;

	bh = rman_get_bushandle(sc->ndis_res_am);
	bt = rman_get_bustag(sc->ndis_res_am);

	for (i = 0; i < len; i++)
		bus_space_write_1(bt, bh, (offset + i) * 2, src[i]);

	return (i);
}

static list_entry *
NdisInterlockedInsertHeadList(list_entry *head, list_entry *entry,
    ndis_spin_lock *lock)
{
	list_entry *flink;

	KeAcquireSpinLock(&lock->nsl_spinlock, &lock->nsl_kirql);
	flink = head->nle_flink;
	entry->nle_flink = flink;
	entry->nle_blink = head;
	flink->nle_blink = entry;
	head->nle_flink = entry;
	KeReleaseSpinLock(&lock->nsl_spinlock, lock->nsl_kirql);

	return (flink);
}

static list_entry *
NdisInterlockedRemoveHeadList(list_entry *head, ndis_spin_lock *lock)
{
	list_entry *flink;
	list_entry *entry;

	KeAcquireSpinLock(&lock->nsl_spinlock, &lock->nsl_kirql);
	entry = head->nle_flink;
	flink = entry->nle_flink;
	head->nle_flink = flink;
	flink->nle_blink = head;
	KeReleaseSpinLock(&lock->nsl_spinlock, lock->nsl_kirql);

	return (entry);
}

static list_entry *
NdisInterlockedInsertTailList(list_entry *head, list_entry *entry,
    ndis_spin_lock *lock)
{
	list_entry *blink;

	KeAcquireSpinLock(&lock->nsl_spinlock, &lock->nsl_kirql);
	blink = head->nle_blink;
	entry->nle_flink = head;
	entry->nle_blink = blink;
	blink->nle_flink = entry;
	head->nle_blink = entry;
	KeReleaseSpinLock(&lock->nsl_spinlock, lock->nsl_kirql);

	return (blink);
}

static uint8_t
NdisMSynchronizeWithInterrupt(ndis_miniport_interrupt *intr, void *syncfunc,
    void *syncctx)
{
	KASSERT(intr != NULL, ("no intr"));
	return (KeSynchronizeExecution(intr->interrupt_object,
	    syncfunc, syncctx));
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
NdisInitializeString(unicode_string *dst, char *src)
{
	ansi_string as;

	RtlInitAnsiString(&as, src);
	RtlAnsiStringToUnicodeString(dst, &as, TRUE);
}

static void
NdisFreeString(unicode_string *str)
{
	RtlFreeUnicodeString(str);
}

static ndis_status
NdisMRemoveMiniport(ndis_handle *adapter)
{
	return (NDIS_STATUS_SUCCESS);
}

static void
NdisInitAnsiString(ansi_string *dst, char *src)
{
	RtlInitAnsiString(dst, src);
}

static void
NdisInitUnicodeString(unicode_string *dst, uint16_t *src)
{
	RtlInitUnicodeString(dst, src);
}

static void
NdisMGetDeviceProperty(ndis_handle adapter, device_object **phydevobj,
    device_object **funcdevobj, device_object **nextdevobj,
    cm_resource_list *resources, cm_resource_list *transresources)
{
	ndis_miniport_block *block;

	block = (ndis_miniport_block *)adapter;

	if (phydevobj != NULL)
		*phydevobj = block->physdeviceobj;
	if (funcdevobj != NULL)
		*funcdevobj = block->deviceobj;
	if (nextdevobj != NULL)
		*nextdevobj = block->nextdeviceobj;
}

static void
NdisGetFirstBufferFromPacket(ndis_packet *packet, ndis_buffer **buf,
    void **firstva, uint32_t *firstlen, uint32_t *totlen)
{
	ndis_buffer *tmp;

	tmp = packet->private.head;
	*buf = tmp;
	if (tmp == NULL) {
		*firstva = NULL;
		*firstlen = *totlen = 0;
	} else {
		*firstva = MmGetMdlVirtualAddress(tmp);
		*firstlen = *totlen = MmGetMdlByteCount(tmp);
		for (tmp = tmp->mdl_next; tmp != NULL; tmp = tmp->mdl_next)
			*totlen += MmGetMdlByteCount(tmp);
	}
}

static void
NdisGetFirstBufferFromPacketSafe(ndis_packet *packet, ndis_buffer **buf,
    void **firstva, uint32_t *firstlen, uint32_t *totlen, uint32_t prio)
{
	NdisGetFirstBufferFromPacket(packet, buf, firstva, firstlen, totlen);
}

static int
ndis_find_sym(linker_file_t lf, char *filename, char *suffix, caddr_t *sym)
{
	char *fullsym, *suf;
	int i;

	fullsym = ExAllocatePoolWithTag(NonPagedPool, MAXPATHLEN, 0);
	if (fullsym == NULL)
		return (ENOMEM);
	strncpy(fullsym, filename, MAXPATHLEN);
	if (strlen(filename) < 4) {
		ExFreePool(fullsym);
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
	ExFreePool(fullsym);
	if (*sym == 0)
		return (ENOENT);

	return (0);
}

struct ndis_checkmodule {
	char	*afilename;
	ndis_fh	*fh;
};

/*
 * See if a single module contains the symbols for a specified file.
 */
static int
NdisCheckModule(linker_file_t lf, void *context)
{
	struct ndis_checkmodule *nc;
	caddr_t kldstart, kldend;

	nc = (struct ndis_checkmodule *)context;
	if (ndis_find_sym(lf, nc->afilename, "_start", &kldstart))
		return (0);
	if (ndis_find_sym(lf, nc->afilename, "_end", &kldend))
		return (0);
	nc->fh->vp = lf;
	nc->fh->map = NULL;
	nc->fh->type = NDIS_FH_TYPE_MODULE;
	nc->fh->maplen = (kldend - kldstart) & 0xFFFFFFFF;
	return (1);
}

/* can also return NDIS_STATUS_INSUFFICIENT_RESOURCES/NDIS_STATUS_ERROR_READING_FILE */
static void
NdisOpenFile(ndis_status *status, ndis_handle *filehandle, 
    uint32_t *filelength, unicode_string *filename, ndis_physaddr highestaddr)
{
	ansi_string as;
	char *afilename = NULL, *path;
	struct thread *td = curthread;
	struct nameidata nd;
	struct ndis_checkmodule nc;
	struct vattr vat, *vap = &vat;
	int flags, vfslocked;
	ndis_fh *fh;

	if (RtlUnicodeStringToAnsiString(&as, filename, TRUE)) {
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}
	afilename = strdup(as.as_buf, M_NDIS_SUBR);
	RtlFreeAnsiString(&as);

	fh = ExAllocatePoolWithTag(NonPagedPool, sizeof(ndis_fh), 0);
	if (fh == NULL) {
		free(afilename, M_NDIS_SUBR);
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}

	fh->name = afilename;

	/*
	 * During system bootstrap, it's impossible to load files
	 * from the rootfs since it's not mounted yet. We therefore
	 * offer the possibility of opening files that have been
	 * preloaded as modules instead. Both choices will work
	 * when kldloading a module from multiuser, but only the
	 * module option will work during bootstrap. The module
	 * loading option works by using the ndiscvt(8) utility
	 * to convert the arbitrary file into a .ko using objcopy(1).
	 * This file will contain two special symbols: filename_start
	 * and filename_end. All we have to do is traverse the KLD
	 * list in search of those symbols and we've found the file
	 * data. As an added bonus, ndiscvt(8) will also generate
	 * a normal .o file which can be linked statically with
	 * the kernel. This means that the symbols will actual reside
	 * in the kernel's symbol table, but that doesn't matter to
	 * us since the kernel appears to us as just another module.
	 */
	nc.afilename = afilename;
	nc.fh = fh;
	if (linker_file_foreach(NdisCheckModule, &nc)) {
		*filelength = fh->maplen;
		*filehandle = fh;
		*status = NDIS_STATUS_SUCCESS;
		return;
	}

	if (TAILQ_EMPTY(&mountlist)) {
		ExFreePool(fh);
		*status = NDIS_STATUS_FILE_NOT_FOUND;
		printf("NDIS: could not find file %s in linker list\n",
		    afilename);
		printf("NDIS: and no filesystems mounted yet, "
		    "aborting NdisOpenFile()\n");
		free(afilename, M_NDIS_SUBR);
		return;
	}

	path = ExAllocatePoolWithTag(NonPagedPool, MAXPATHLEN, 0);
	if (path == NULL) {
		ExFreePool(fh);
		free(afilename, M_NDIS_SUBR);
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
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
		ExFreePool(fh);
		printf("NDIS: open file %s failed\n", path);
		ExFreePool(path);
		free(afilename, M_NDIS_SUBR);
		return;
	}
	vfslocked = NDHASGIANT(&nd);

	ExFreePool(path);

	NDFREE(&nd, NDF_ONLY_PNBUF);

	/* Get the file size. */
	VOP_GETATTR(nd.ni_vp, vap, td->td_ucred);
	VOP_UNLOCK(nd.ni_vp, 0);
	VFS_UNLOCK_GIANT(vfslocked);

	fh->vp = nd.ni_vp;
	fh->map = NULL;
	fh->type = NDIS_FH_TYPE_VFS;
	*filehandle = fh;
	*filelength = fh->maplen = vap->va_size & 0xFFFFFFFF;
	*status = NDIS_STATUS_SUCCESS;
}

static void
NdisMapFile(ndis_status *status, void **mappedbuffer, ndis_handle filehandle)
{
	struct vnode *vp;
	struct thread *td = curthread;
	ndis_fh  *fh;
	linker_file_t lf;
	caddr_t kldstart;
	int error, resid, vfslocked;

	if (filehandle == NULL) {
		*status = NDIS_STATUS_FAILURE;
		return;
	}
	fh = (ndis_fh *)filehandle;
	if (fh->vp == NULL) {
		*status = NDIS_STATUS_FAILURE;
		return;
	}
	if (fh->map != NULL) {
		*status = NDIS_STATUS_ALREADY_MAPPED;
		return;
	}
	if (fh->type == NDIS_FH_TYPE_MODULE) {
		lf = fh->vp;
		if (ndis_find_sym(lf, fh->name, "_start", &kldstart)) {
			*status = NDIS_STATUS_FAILURE;
			return;
		}
		fh->map = kldstart;
		*status = NDIS_STATUS_SUCCESS;
		*mappedbuffer = fh->map;
		return;
	}

	fh->map = ExAllocatePoolWithTag(NonPagedPool, fh->maplen, 0);
	if (fh->map == NULL) {
		*status = NDIS_STATUS_INSUFFICIENT_RESOURCES;
		return;
	}

	vp = fh->vp;
	vfslocked = VFS_LOCK_GIANT(vp->v_mount);
	error = vn_rdwr(UIO_READ, vp, fh->map, fh->maplen, 0,
	    UIO_SYSSPACE, 0, td->td_ucred, NOCRED, &resid, td);
	VFS_UNLOCK_GIANT(vfslocked);
	if (error)
		*status = NDIS_STATUS_FAILURE;
	else {
		*status = NDIS_STATUS_SUCCESS;
		*mappedbuffer = fh->map;
	}
}

static void
NdisUnmapFile(ndis_handle filehandle)
{
	ndis_fh *fh;

	fh = (ndis_fh *)filehandle;
	if (fh->map == NULL)
		return;

	if (fh->type == NDIS_FH_TYPE_VFS)
		ExFreePool(fh->map);
	fh->map = NULL;
}

static void
NdisCloseFile(ndis_handle filehandle)
{
	struct vnode *vp;
	struct thread *td = curthread;
	ndis_fh *fh;
	int vfslocked;

	if (filehandle == NULL)
		return;
	fh = (ndis_fh *)filehandle;
	if (fh->map != NULL) {
		if (fh->type == NDIS_FH_TYPE_VFS)
			ExFreePool(fh->map);
		fh->map = NULL;
	}
	if (fh->vp == NULL)
		return;
	if (fh->type == NDIS_FH_TYPE_VFS) {
		vp = fh->vp;
		vfslocked = VFS_LOCK_GIANT(vp->v_mount);
		vn_close(vp, FREAD, td->td_ucred, td);
		VFS_UNLOCK_GIANT(vfslocked);
	}
	fh->vp = NULL;
	free(fh->name, M_NDIS_SUBR);
	ExFreePool(fh);
}

static uint8_t
NdisSystemProcessorCount(void)
{
	return (mp_ncpus);
}

typedef void (*ndis_status_func)(ndis_handle, ndis_status,
    void *, uint32_t);
typedef void (*ndis_status_done_func)(ndis_handle);

static void
NdisMIndicateStatusComplete(ndis_handle adapter)
{
	ndis_miniport_block *block;

	block = (ndis_miniport_block *)adapter;
	KASSERT(adapter != NULL, ("no adapter"));
	KASSERT(block->status_done_func != NULL, ("no status_done"));
	MSCALL1(block->status_done_func, adapter);
}

static void
NdisMIndicateStatus(ndis_handle adapter, ndis_status status, void *sbuf,
    uint32_t slen)
{
	ndis_miniport_block *block;

	block = (ndis_miniport_block *)adapter;
	KASSERT(adapter != NULL, ("no adapter"));
	KASSERT(block->status_func != NULL, ("no status"));
	MSCALL4(block->status_func, adapter, status, sbuf, slen);
}

/*
 * The DDK documentation says that you should use IoQueueWorkItem()
 * instead of ExQueueWorkItem(). The problem is, IoQueueWorkItem()
 * is fundamentally incompatible with NdisScheduleWorkItem(), which
 * depends on the API semantics of ExQueueWorkItem(). In our world,
 * ExQueueWorkItem() is implemented on top of IoAllocateQueueItem()
 * anyway.
 *
 * There are actually three distinct APIs here. NdisScheduleWorkItem()
 * takes a pointer to an NDIS_WORK_ITEM. ExQueueWorkItem() takes a pointer
 * to a WORK_QUEUE_ITEM. And finally, IoQueueWorkItem() takes a pointer
 * to an opaque work item thingie which you get from IoAllocateWorkItem().
 * An NDIS_WORK_ITEM is not the same as a WORK_QUEUE_ITEM. However,
 * the NDIS_WORK_ITEM has some opaque storage at the end of it, and we
 * (ab)use this storage as a WORK_QUEUE_ITEM, which is what we submit
 * to ExQueueWorkItem().
 *
 * Got all that? (Sheesh.)
 */
static ndis_status
NdisScheduleWorkItem(ndis_work_item *work)
{
	work_queue_item *wqi;

	wqi = (work_queue_item *)work->nwi_wraprsvd;
	ExInitializeWorkItem(wqi,
	    (work_item_func)work->nwi_func, work->nwi_ctx);
	ExQueueWorkItem(wqi, WORKQUEUE_DELAYED);

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisCopyFromPacketToPacket(ndis_packet *dpkt, uint32_t doff, uint32_t reqlen,
    ndis_packet *spkt, uint32_t soff, uint32_t *cpylen)
{
	ndis_buffer *src, *dst;
	char *sptr, *dptr;
	int resid, copied, len, scnt, dcnt;

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
		src = src->mdl_next;
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
		dst = dst->mdl_next;
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
			dst = dst->mdl_next;
			if (dst == NULL)
				break;
			dptr = MmGetMdlVirtualAddress(dst);
			dcnt = MmGetMdlByteCount(dst);
		}

		scnt -= len;
		if (scnt == 0) {
			src = src->mdl_next;
			if (src == NULL)
				break;
			sptr = MmGetMdlVirtualAddress(src);
			scnt = MmGetMdlByteCount(src);
		}
	}

	*cpylen = copied;
}

static void
NdisCopyFromPacketToPacketSafe(ndis_packet *dpkt, uint32_t doff,
    uint32_t reqlen, ndis_packet *spkt, uint32_t soff, uint32_t *cpylen,
    uint32_t prio)
{
	NdisCopyFromPacketToPacket(dpkt, doff, reqlen, spkt, soff, cpylen);
}

static void
NdisIMCopySendPerPacketInfo(ndis_packet *dpkt, ndis_packet *spkt)
{
	memcpy(&dpkt->ext, &spkt->ext, sizeof(ndis_packet_extension));
}

static ndis_status
NdisMRegisterDevice(ndis_handle handle, unicode_string *devname,
    unicode_string *symname, driver_dispatch *majorfuncs[],
    void **devobj, ndis_handle *devhandle)
{
	uint32_t status;
	device_object *dobj;

	status = IoCreateDevice(handle, 0, devname,
	    FILE_DEVICE_NETWORK, 0, FALSE, &dobj);
	if (status == NDIS_STATUS_SUCCESS) {
		*devobj = dobj;
		*devhandle = dobj;
	}

	return (status);
}

static ndis_status
NdisMDeregisterDevice(ndis_handle handle)
{
	IoDeleteDevice(handle);

	return (NDIS_STATUS_SUCCESS);
}

static ndis_status
NdisMQueryAdapterInstanceName(unicode_string *name, ndis_handle handle)
{
	ndis_miniport_block *block;
	device_t dev;
	ansi_string as;

	block = (ndis_miniport_block *)handle;
	dev = block->physdeviceobj->devext;

	RtlInitAnsiString(&as, __DECONST(char *, device_get_nameunit(dev)));
	if (RtlAnsiStringToUnicodeString(name, &as, TRUE))
		return (NDIS_STATUS_INSUFFICIENT_RESOURCES);

	return (NDIS_STATUS_SUCCESS);
}

static void
NdisMRegisterUnloadHandler(ndis_handle handle, void *func)
{
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
image_patch_table ndis_functbl[] = {
	IMPORT_SFUNC(NdisCopyFromPacketToPacket, 6),
	IMPORT_SFUNC(NdisCopyFromPacketToPacketSafe, 7),
	IMPORT_SFUNC(NdisIMCopySendPerPacketInfo, 2),
	IMPORT_SFUNC(NdisScheduleWorkItem, 1),
	IMPORT_SFUNC(NdisMIndicateStatusComplete, 1),
	IMPORT_SFUNC(NdisMIndicateStatus, 4),
	IMPORT_SFUNC(NdisSystemProcessorCount, 0),
	IMPORT_SFUNC(NdisUnchainBufferAtBack, 2),
	IMPORT_SFUNC(NdisGetFirstBufferFromPacket, 5),
	IMPORT_SFUNC(NdisGetFirstBufferFromPacketSafe, 6),
	IMPORT_SFUNC(NdisGetBufferPhysicalArraySize, 2),
	IMPORT_SFUNC(NdisMGetDeviceProperty, 6),
	IMPORT_SFUNC(NdisInitAnsiString, 2),
	IMPORT_SFUNC(NdisInitUnicodeString, 2),
	IMPORT_SFUNC(NdisWriteConfiguration, 4),
	IMPORT_SFUNC(NdisAnsiStringToUnicodeString, 2),
	IMPORT_SFUNC(NdisTerminateWrapper, 2),
	IMPORT_SFUNC(NdisOpenConfigurationKeyByName, 4),
	IMPORT_SFUNC(NdisOpenConfigurationKeyByIndex, 5),
	IMPORT_SFUNC(NdisMRemoveMiniport, 1),
	IMPORT_SFUNC(NdisInitializeString, 2),
	IMPORT_SFUNC(NdisFreeString, 1),
	IMPORT_SFUNC(NdisGetCurrentSystemTime, 1),
	IMPORT_SFUNC(NdisGetSystemUpTime, 1),
	IMPORT_SFUNC(NdisMSynchronizeWithInterrupt, 3),
	IMPORT_SFUNC(NdisMAllocateSharedMemoryAsync, 4),
	IMPORT_SFUNC(NdisInterlockedInsertHeadList, 3),
	IMPORT_SFUNC(NdisInterlockedInsertTailList, 3),
	IMPORT_SFUNC(NdisInterlockedRemoveHeadList, 2),
	IMPORT_SFUNC(NdisInitializeWrapper, 4),
	IMPORT_SFUNC(NdisMRegisterMiniport, 3),
	IMPORT_SFUNC(NdisAllocateMemoryWithTag, 3),
	IMPORT_SFUNC(NdisAllocateMemory, 4 + 1),
	IMPORT_SFUNC(NdisMSetAttributesEx, 5),
	IMPORT_SFUNC(NdisCloseConfiguration, 1),
	IMPORT_SFUNC(NdisReadConfiguration, 5),
	IMPORT_SFUNC(NdisOpenConfiguration, 3),
	IMPORT_SFUNC(NdisAcquireSpinLock, 1),
	IMPORT_SFUNC(NdisReleaseSpinLock, 1),
	IMPORT_SFUNC(NdisDprAcquireSpinLock, 1),
	IMPORT_SFUNC(NdisDprReleaseSpinLock, 1),
	IMPORT_SFUNC(NdisAllocateSpinLock, 1),
	IMPORT_SFUNC(NdisInitializeReadWriteLock, 1),
	IMPORT_SFUNC(NdisAcquireReadWriteLock, 3),
	IMPORT_SFUNC(NdisReleaseReadWriteLock, 2),
	IMPORT_SFUNC(NdisFreeSpinLock, 1),
	IMPORT_SFUNC(NdisFreeMemory, 3),
	IMPORT_SFUNC(NdisReadPciSlotInformation, 5),
	IMPORT_SFUNC(NdisWritePciSlotInformation, 5),
	IMPORT_SFUNC_MAP(NdisImmediateReadPciSlotInformation,
	    NdisReadPciSlotInformation, 5),
	IMPORT_SFUNC_MAP(NdisImmediateWritePciSlotInformation,
	    NdisWritePciSlotInformation, 5),
	IMPORT_CFUNC(NdisWriteErrorLogEntry, 0),
	IMPORT_SFUNC(NdisMStartBufferPhysicalMapping, 6),
	IMPORT_SFUNC(NdisMCompleteBufferPhysicalMapping, 3),
	IMPORT_SFUNC(NdisMInitializeTimer, 4),
	IMPORT_SFUNC(NdisInitializeTimer, 3),
	IMPORT_SFUNC(NdisSetTimer, 2),
	IMPORT_SFUNC(NdisMCancelTimer, 2),
	IMPORT_SFUNC_MAP(NdisCancelTimer, NdisMCancelTimer, 2),
	IMPORT_SFUNC(NdisMSetPeriodicTimer, 2),
	IMPORT_SFUNC(NdisMQueryAdapterResources, 4),
	IMPORT_SFUNC(NdisMRegisterIoPortRange, 4),
	IMPORT_SFUNC(NdisMDeregisterIoPortRange, 4),
	IMPORT_SFUNC(NdisReadNetworkAddress, 4),
	IMPORT_SFUNC(NdisQueryMapRegisterCount, 2),
	IMPORT_SFUNC(NdisMAllocateMapRegisters, 5),
	IMPORT_SFUNC(NdisMFreeMapRegisters, 1),
	IMPORT_SFUNC(NdisMAllocateSharedMemory, 5),
	IMPORT_SFUNC(NdisMMapIoSpace, 4 + 1),
	IMPORT_SFUNC(NdisMUnmapIoSpace, 3),
	IMPORT_SFUNC(NdisGetCacheFillSize, 0),
	IMPORT_SFUNC(NdisMGetDmaAlignment, 1),
	IMPORT_SFUNC(NdisMInitializeScatterGatherDma, 3),
	IMPORT_SFUNC(NdisAllocatePacketPool, 4),
	IMPORT_SFUNC(NdisAllocatePacketPoolEx, 5),
	IMPORT_SFUNC(NdisAllocatePacket, 3),
	IMPORT_SFUNC(NdisFreePacket, 1),
	IMPORT_SFUNC(NdisFreePacketPool, 1),
	IMPORT_SFUNC_MAP(NdisDprAllocatePacket, NdisAllocatePacket, 3),
	IMPORT_SFUNC_MAP(NdisDprFreePacket, NdisFreePacket, 1),
	IMPORT_SFUNC(NdisAllocateBufferPool, 3),
	IMPORT_SFUNC(NdisAllocateBuffer, 5),
	IMPORT_SFUNC(NdisQueryBuffer, 3),
	IMPORT_SFUNC(NdisQueryBufferSafe, 4),
	IMPORT_SFUNC(NdisBufferVirtualAddress, 1),
	IMPORT_SFUNC(NdisBufferVirtualAddressSafe, 2),
	IMPORT_SFUNC(NdisBufferLength, 1),
	IMPORT_SFUNC(NdisFreeBuffer, 1),
	IMPORT_SFUNC(NdisFreeBufferPool, 1),
	IMPORT_SFUNC(NdisInterlockedIncrement, 1),
	IMPORT_SFUNC(NdisInterlockedDecrement, 1),
	IMPORT_SFUNC(NdisInitializeEvent, 1),
	IMPORT_SFUNC(NdisSetEvent, 1),
	IMPORT_SFUNC(NdisResetEvent, 1),
	IMPORT_SFUNC(NdisWaitEvent, 2),
	IMPORT_SFUNC(NdisUnicodeStringToAnsiString, 2),
	IMPORT_SFUNC(NdisMPciAssignResources, 3),
	IMPORT_SFUNC(NdisMFreeSharedMemory, 5 + 1),
	IMPORT_SFUNC(NdisMRegisterInterrupt, 7),
	IMPORT_SFUNC(NdisMDeregisterInterrupt, 1),
	IMPORT_SFUNC(NdisMRegisterAdapterShutdownHandler, 3),
	IMPORT_SFUNC(NdisMDeregisterAdapterShutdownHandler, 1),
	IMPORT_SFUNC(NDIS_BUFFER_TO_SPAN_PAGES, 1),
	IMPORT_SFUNC(NdisQueryBufferOffset, 3),
	IMPORT_SFUNC(NdisAdjustBufferLength, 2),
	IMPORT_SFUNC(NdisPacketPoolUsage, 1),
	IMPORT_SFUNC(NdisMSleep, 1),
	IMPORT_SFUNC(NdisUnchainBufferAtFront, 2),
	IMPORT_SFUNC(NdisReadPcmciaAttributeMemory, 4),
	IMPORT_SFUNC(NdisWritePcmciaAttributeMemory, 4),
	IMPORT_SFUNC(NdisOpenFile, 5 + 1),
	IMPORT_SFUNC(NdisMapFile, 3),
	IMPORT_SFUNC(NdisUnmapFile, 1),
	IMPORT_SFUNC(NdisCloseFile, 1),
	IMPORT_SFUNC(NdisMRegisterDevice, 6),
	IMPORT_SFUNC(NdisMDeregisterDevice, 1),
	IMPORT_SFUNC(NdisMQueryAdapterInstanceName, 2),
	IMPORT_SFUNC(NdisMRegisterUnloadHandler, 2),
	IMPORT_SFUNC(ndis_timercall, 4),
	IMPORT_SFUNC(ndis_asyncmem_complete, 2),
	IMPORT_SFUNC(ndis_interrupt_nic, 2),
	IMPORT_SFUNC(ndis_intrhand, 4),

	/*
	 * This last entry is a catch-all for any function we haven't
	 * implemented yet. The PE import list patching routine will
	 * use it for any function that doesn't have an explicit match
	 * in this table.
	 */
	{ NULL, (FUNC)dummy, NULL, 0, WINDRV_WRAP_STDCALL },

	/* End of list. */
	{ NULL, NULL, NULL }
};
