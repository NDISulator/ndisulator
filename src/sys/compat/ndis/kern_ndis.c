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
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/errno.h>
#include <sys/callout.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/conf.h>

#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/kthread.h>
#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/ndis_var.h>
#include <compat/ndis/hal_var.h>
#include <compat/ndis/usbd_var.h>
#include <dev/if_ndis/if_ndisvar.h>

#ifdef NDIS_DEBUG
int ndis_debug = 0;
SYSCTL_INT(_debug, OID_AUTO, ndis, CTLFLAG_RW, &ndis_debug,
	    0, "control debugging printfs");
#endif

static void	ndis_create_sysctls(struct ndis_softc *);
static void	ndis_flush_sysctls(struct ndis_softc *);
static void	ndis_free_bufs(struct mdl *);
static void	NdisMIndicateStatus(struct ndis_miniport_block *, int32_t,
		    void *, uint32_t);
static void	NdisMIndicateStatusComplete(struct ndis_miniport_block *);
static void	NdisMSetInformationComplete(struct ndis_miniport_block *,
		    int32_t);
static void	NdisMQueryInformationComplete(struct ndis_miniport_block *,
		    int32_t);
static void	NdisMResetComplete(struct ndis_miniport_block *, int32_t,
		    uint8_t);
static void	NdisMSendResourcesAvailable(struct ndis_miniport_block *);
static void	ndis_interrupt_setup(kdpc *, struct device_object *, irp *,
		    struct ndis_softc *);
static void	ndis_return_packet_nic(struct device_object *,
		    struct ndis_miniport_block *);

static struct image_patch_table kernndis_functbl[] = {
	IMPORT_SFUNC(NdisMIndicateStatus, 4),
	IMPORT_SFUNC(NdisMIndicateStatusComplete, 1),
	IMPORT_SFUNC(NdisMSetInformationComplete, 2),
	IMPORT_SFUNC(NdisMQueryInformationComplete, 2),
	IMPORT_SFUNC(NdisMResetComplete, 3),
	IMPORT_SFUNC(NdisMSendResourcesAvailable, 1),
	IMPORT_SFUNC(ndis_interrupt_setup, 4),
	IMPORT_SFUNC(ndis_return_packet_nic, 1),
	{ NULL, NULL, NULL }
};

static struct nd_head ndis_devhead;

MALLOC_DEFINE(M_NDIS_KERN, "ndis_kern", "ndis_kern buffers");

/*
 * This allows us to export our symbols to other modules.
 * Note that we call ourselves 'ndisapi' to avoid a namespace
 * collision with if_ndis.ko, which internally calls itself
 * 'ndis.'
 *
 * Note: some of the subsystems depend on each other, so the
 * order in which they're started is important. The order of
 * importance is:
 *
 * HAL - spinlocks and IRQL manipulation
 * ntoskrnl - DPC and workitem threads, object waiting
 * windrv - driver/device registration
 *
 * The HAL should also be the last thing shut down, since
 * the ntoskrnl subsystem will use spinlocks right up until
 * the DPC and workitem threads are terminated.
 */
static int
ndis_modevent(module_t mod, int cmd, void *arg)
{

	switch (cmd) {
	case MOD_LOAD:
		hal_libinit();
		ntoskrnl_libinit();
		windrv_libinit();
		ndis_libinit();
		usbd_libinit();

		windrv_wrap_table(kernndis_functbl);

		TAILQ_INIT(&ndis_devhead);
		break;
	case MOD_SHUTDOWN:
		if (TAILQ_FIRST(&ndis_devhead) == NULL) {
			usbd_libfini();
			ndis_libfini();
			windrv_libfini();
			ntoskrnl_libfini();
			hal_libfini();

			windrv_unwrap_table(kernndis_functbl);
		}
		break;
	case MOD_UNLOAD:
		usbd_libfini();
		ndis_libfini();
		windrv_libfini();
		ntoskrnl_libfini();
		hal_libfini();

		windrv_unwrap_table(kernndis_functbl);
		break;
	default:
		return (EINVAL);
	}

	return (0);
}
DEV_MODULE(ndisapi, ndis_modevent, NULL);
MODULE_VERSION(ndisapi, 2);

static void
NdisMSendResourcesAvailable(struct ndis_miniport_block *block)
{
}

static void
NdisMIndicateStatus(struct ndis_miniport_block *block, int32_t status,
    void *sbuf, uint32_t slen)
{
}

static void
NdisMIndicateStatusComplete(struct ndis_miniport_block *block)
{
}

static void
NdisMSetInformationComplete(struct ndis_miniport_block *block, int32_t status)
{
	block->setstat = status;
	KeSetEvent(&block->setevent, IO_NO_INCREMENT, FALSE);
}

static void
NdisMQueryInformationComplete(struct ndis_miniport_block *block, int32_t status)
{
	block->getstat = status;
	KeSetEvent(&block->getevent, IO_NO_INCREMENT, FALSE);
}

static void
NdisMResetComplete(struct ndis_miniport_block *block, int32_t status,
    uint8_t addressingreset)
{
	block->resetstat = status;
	KeSetEvent(&block->resetevent, IO_NO_INCREMENT, FALSE);
}

static void
ndis_create_sysctls(struct ndis_softc *sc)
{
	struct ndis_cfg *cfg = sc->ndis_regvals;
	char buf[32];
	struct sysctl_oid *oidp;
	struct sysctl_ctx_entry *e;

	TAILQ_INIT(&sc->ndis_cfglist_head);

	/* Add the driver-specific registry keys. */
	for (;;) {
		if (cfg->key == NULL)
			break;
		if (cfg->idx != sc->ndis_devidx) {
			cfg++;
			continue;
		}

		/* See if we already have a sysctl with this name */
		oidp = NULL;
		TAILQ_FOREACH(e, device_get_sysctl_ctx(sc->ndis_dev), link) {
			oidp = e->entry;
			if (strcasecmp(oidp->oid_name, cfg->key) == 0)
				break;
			oidp = NULL;
		}
		if (oidp != NULL) {
			cfg++;
			continue;
		}

		ndis_add_sysctl(sc, cfg->key, cfg->desc, cfg->val, CTLFLAG_RW);
		cfg++;
	}

	/* Now add a couple of builtin keys. */
	/*
	 * Environment can be either Windows (0) or WindowsNT (1).
	 * We qualify as the latter.
	 */
	ndis_add_sysctl(sc, "Environment", "Environment", "1", CTLFLAG_RD);
	/* NDIS version should be 5.1. */
	ndis_add_sysctl(sc, "NdisVersion", "NDIS API Version",
	    "0x00050001", CTLFLAG_RD);
	ndis_add_sysctl(sc, "SlotNumber", "Slot Number", "01", CTLFLAG_RD);
	ndis_add_sysctl(sc, "NetCfgInstanceId", "NetCfgInstanceId",
	    "{12345678-1234-5678-CAFE0-123456789ABC}", CTLFLAG_RD);
	ndis_add_sysctl(sc, "DriverDesc", "Driver Description",
	    "NDIS Network Adapter", CTLFLAG_RD);
	/* Bus type (PCI, PCMCIA, etc...) */
	sprintf(buf, "%d", sc->ndis_bus_type);
	ndis_add_sysctl(sc, "BusType", "Bus Type", buf, CTLFLAG_RD);
	if (sc->ndis_res_io != NULL) {
		sprintf(buf, "0x%lx", rman_get_start(sc->ndis_res_io));
		ndis_add_sysctl(sc, "IOBaseAddress",
		    "Base I/O Address", buf, CTLFLAG_RD);
	}
	if (sc->ndis_irq != NULL) {
		sprintf(buf, "%lu", rman_get_start(sc->ndis_irq));
		ndis_add_sysctl(sc, "InterruptNumber",
		    "Interrupt Number", buf, CTLFLAG_RD);
	}
}

int
ndis_add_sysctl(struct ndis_softc *sc, char *key, char *desc, char *val,
    int flag)
{
	struct ndis_cfglist *cfg;

	cfg = malloc(sizeof(struct ndis_cfglist), M_NDIS_KERN, M_NOWAIT|M_ZERO);
	if (cfg == NULL)
		return (ENOMEM);
	cfg->ndis_cfg.key = strdup(key, M_NDIS_KERN);
	if (desc == NULL) {
		cfg->ndis_cfg.desc = NULL;
	} else
		cfg->ndis_cfg.desc = strdup(desc, M_NDIS_KERN);
	cfg->ndis_cfg.val = strdup(val, M_NDIS_KERN);

	TAILQ_INSERT_TAIL(&sc->ndis_cfglist_head, cfg, link);

	cfg->ndis_oid = SYSCTL_ADD_STRING(device_get_sysctl_ctx(sc->ndis_dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(sc->ndis_dev)),
	    OID_AUTO, cfg->ndis_cfg.key, flag, cfg->ndis_cfg.val,
	    sizeof(cfg->ndis_cfg.val), cfg->ndis_cfg.desc);

	return (0);
}

static void
ndis_flush_sysctls(struct ndis_softc *sc)
{
	struct ndis_cfglist *cfg;
	struct sysctl_ctx_list *clist;

	clist = device_get_sysctl_ctx(sc->ndis_dev);

	while (!TAILQ_EMPTY(&sc->ndis_cfglist_head)) {
		cfg = TAILQ_FIRST(&sc->ndis_cfglist_head);
		TAILQ_REMOVE(&sc->ndis_cfglist_head, cfg, link);
		sysctl_ctx_entry_del(clist, cfg->ndis_oid);
		sysctl_remove_oid(cfg->ndis_oid, 1, 0);
		free(cfg->ndis_cfg.key, M_NDIS_KERN);
		free(cfg->ndis_cfg.desc, M_NDIS_KERN);
		free(cfg->ndis_cfg.val, M_NDIS_KERN);
		free(cfg, M_NDIS_KERN);
	}
}

void *
ndis_get_routine_address(struct image_patch_table *functbl, char *name)
{
	int i;

	for (i = 0; functbl[i].name != NULL; i++)
		if (strcmp(name, functbl[i].name) == 0)
			return (functbl[i].wrap);
	return (NULL);
}

static void
ndis_return_packet_nic(struct device_object *dobj,
    struct ndis_miniport_block *block)
{
	struct ndis_miniport_characteristics *ch;
	struct ndis_packet *p;
	uint8_t irql;
	struct list_entry *l;

	KASSERT(block != NULL, ("no block"));
	KASSERT(block->miniport_adapter_ctx != NULL, ("no adapter"));
	ch = IoGetDriverObjectExtension(dobj->drvobj, (void *)1);
	KASSERT(ch->return_packet_func != NULL, ("no return_packet"));
	KeAcquireSpinLock(&block->returnlock, &irql);
	while (!IsListEmpty(&block->returnlist)) {
		l = RemoveHeadList((&block->returnlist));
		p = CONTAINING_RECORD(l, struct ndis_packet, list);
		InitializeListHead((&p->list));
		KeReleaseSpinLock(&block->returnlock, irql);
		MSCALL2(ch->return_packet_func, block->miniport_adapter_ctx, p);
		KeAcquireSpinLock(&block->returnlock, &irql);
	}
	KeReleaseSpinLock(&block->returnlock, irql);
}

void
ndis_return_packet(void *buf, void *arg)
{
	struct ndis_packet *p = arg;
	struct ndis_miniport_block *block;

	p->refcnt--;
	if (p->refcnt)
		return;

	block = ((struct ndis_softc *)p->softc)->ndis_block;
	KeAcquireSpinLockAtDpcLevel(&block->returnlock);
	InitializeListHead((&p->list));
	InsertHeadList((&block->returnlist), (&p->list));
	KeReleaseSpinLockFromDpcLevel(&block->returnlock);

	IoQueueWorkItem(block->returnitem,
	    (io_workitem_func)kernndis_functbl[7].wrap,
	    WORKQUEUE_CRITICAL, block);
}

static void
ndis_free_bufs(struct mdl *b0)
{
	struct mdl *next;

	while (b0 != NULL) {
		next = b0->mdl_next;
		IoFreeMdl(b0);
		b0 = next;
	}
}

void
ndis_free_packet(struct ndis_packet *p)
{
	KASSERT(p != NULL, ("no packet"));
	ndis_free_bufs(p->private.head);
	NdisFreePacket(p);
}

int
ndis_convert_res(struct ndis_softc *sc)
{
	struct cm_partial_resource_list *rl = NULL;
	struct cm_partial_resource_desc *prd = NULL;
	struct resource_list *brl;
	struct resource_list_entry *brle;

	rl = malloc(sizeof(struct cm_partial_resource_list) +
	    (sizeof(struct cm_partial_resource_desc) * (sc->ndis_rescnt - 1)),
	    M_NDIS_KERN, M_NOWAIT|M_ZERO);
	if (rl == NULL)
		return (ENOMEM);

	rl->version = 1;
	rl->revision = 1;
	rl->count = sc->ndis_rescnt;
	prd = rl->partial_descs;

	brl = BUS_GET_RESOURCE_LIST(sc->ndis_dev, sc->ndis_dev);
	if (brl != NULL) {
		STAILQ_FOREACH(brle, brl, link) {
			switch (brle->type) {
			case SYS_RES_IOPORT:
				prd->type = CmResourceTypePort;
				prd->flags = CM_RESOURCE_PORT_IO;
				prd->sharedisp =
				    CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE;
				prd->u.port.start = brle->start;
				prd->u.port.len = brle->count;
				break;
			case SYS_RES_MEMORY:
				prd->type = CmResourceTypeMemory;
				prd->flags = CM_RESOURCE_MEMORY_READ_WRITE;
				prd->sharedisp =
				    CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE;
				prd->u.mem.start = brle->start;
				prd->u.mem.len = brle->count;
				break;
			case SYS_RES_IRQ:
				prd->type = CmResourceTypeInterrupt;
				prd->flags = 0;
				/*
				 * Always mark interrupt resources as
				 * shared, since in our implementation,
				 * they will be.
				 */
				prd->sharedisp = CM_RESOURCE_SHARE_SHARED;
				prd->u.intr.level = brle->start;
				prd->u.intr.vector = brle->start;
				prd->u.intr.affinity = 0;
				break;
			default:
				break;
			}
			prd++;
		}
	}

	sc->ndis_block->rlist = rl;

	return (0);
}

/*
 * Map an NDIS packet to an mbuf list. When an NDIS driver receives a
 * packet, it will hand it to us in the form of an ndis_packet,
 * which we need to convert to an mbuf that is then handed off
 * to the stack. Note: we configure the mbuf list so that it uses
 * the memory regions specified by the mdl structures in
 * the ndis_packet as external storage. In most cases, this will
 * point to a memory region allocated by the driver (either by
 * ndis_malloc_withtag() or ndis_alloc_sharedmem()). We expect
 * the driver to handle free()ing this region for us, so we set up
 * a dummy no-op free handler for it.
 */
int
ndis_ptom(struct mbuf **m0, struct ndis_packet *p)
{
	struct mbuf *m = NULL, *prev = NULL;
	struct mdl *buf;
	struct ndis_packet_private *priv;
	uint32_t totlen = 0;
	struct ifnet *ifp;
	struct ether_header *eh;
	int diff;

	KASSERT(p != NULL, ("no packet"));
	priv = &p->private;
	buf = priv->head;
	p->refcnt = 0;

	for (buf = priv->head; buf != NULL; buf = buf->mdl_next) {
		if (buf == priv->head)
			MGETHDR(m, M_DONTWAIT, MT_HEADER);
		else
			MGET(m, M_DONTWAIT, MT_DATA);
		if (m == NULL) {
			m_freem(*m0);
			*m0 = NULL;
			return (ENOBUFS);
		}
		m->m_len = MmGetMdlByteCount(buf);
		m->m_data = MmGetMdlVirtualAddress(buf);
		MEXTADD(m, m->m_data, m->m_len, ndis_return_packet,
		    m->m_data, p, 0, EXT_NET_DRV);
		p->refcnt++;

		totlen += m->m_len;
		if (m->m_flags & M_PKTHDR)
			*m0 = m;
		else
			prev->m_next = m;
		prev = m;
	}

	/*
	 * This is a hack to deal with the Marvell 8335 driver
	 * which, when associated with an AP in WPA-PSK mode,
	 * seems to overpad its frames by 8 bytes. I don't know
	 * that the extra 8 bytes are for, and they're not there
	 * in open mode, so for now clamp the frame size at 1514
	 * until I can figure out how to deal with this properly,
	 * otherwise if_ethersubr() will spank us by discarding
	 * the 'oversize' frames.
	 */
	eh = mtod((*m0), struct ether_header *);
	ifp = ((struct ndis_softc *)p->softc)->ndis_ifp;
	if (totlen > ETHER_MAX_FRAME(ifp, eh->ether_type, FALSE)) {
		diff = totlen - ETHER_MAX_FRAME(ifp, eh->ether_type, FALSE);
		totlen -= diff;
		m->m_len -= diff;
	}
	(*m0)->m_pkthdr.len = totlen;

	return (0);
}

/*
 * Create an NDIS packet from an mbuf chain.
 * This is used mainly when transmitting packets, where we need
 * to turn an mbuf off an interface's send queue and transform it
 * into an NDIS packet which will be fed into the NDIS driver's
 * send routine.
 *
 * NDIS packets consist of two parts: an ndis_packet structure,
 * which is vaguely analagous to the pkthdr portion of an mbuf,
 * and one or more mdl structures, which define the
 * actual memory segments in which the packet data resides.
 * We need to allocate one mdl for each mbuf in a chain,
 * plus one ndis_packet as the header.
 */
int
ndis_mtop(struct mbuf *m0, struct ndis_packet **p)
{
	struct mbuf *m;
	struct mdl *buf = NULL, *prev = NULL;
	struct ndis_packet_private *priv;

	KASSERT(*p != NULL, ("no packet"));
	priv = &(*p)->private;
	priv->totlen = m0->m_pkthdr.len;

	for (m = m0; m != NULL; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		buf = IoAllocateMdl(m->m_data, m->m_len, FALSE, FALSE, NULL);
		if (buf == NULL) {
			ndis_free_packet(*p);
			*p = NULL;
			return (ENOMEM);
		}
		MmBuildMdlForNonPagedPool(buf);

		if (priv->head == NULL)
			priv->head = buf;
		else
			prev->mdl_next = buf;
		prev = buf;
	}

	priv->tail = buf;

	return (0);
}

static int
ndis_request_info(uint32_t req, struct ndis_softc *sc, uint32_t oid,
    void *buf, uint32_t buflen, uint32_t *written, uint32_t *needed)
{
	uint64_t duetime;
	int32_t rval, w = 0, n = 0;
	uint8_t irql;

	if (!written)
		written = &w;
	if (!needed)
		needed = &n;
	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	KASSERT(sc->ndis_chars->query_info_func != NULL, ("no query_info"));
	KASSERT(sc->ndis_chars->set_info_func != NULL, ("no set_info"));
	/*
	 * According to the NDIS spec, MiniportQueryInformation()
	 * and MiniportSetInformation() requests are handled serially:
	 * once one request has been issued, we must wait for it to
	 * finish before allowing another request to proceed.
	 */
	if (req == NDIS_REQUEST_QUERY_INFORMATION) {
		KeResetEvent(&sc->ndis_block->getevent);
		KeAcquireSpinLock(&sc->ndis_block->lock, &irql);
		rval = MSCALL6(sc->ndis_chars->query_info_func,
		    sc->ndis_block->miniport_adapter_ctx,
		    oid, buf, buflen, written, needed);
		KeReleaseSpinLock(&sc->ndis_block->lock, irql);
		if (rval == NDIS_STATUS_PENDING) {
			duetime = (5 * 1000000) * -10;
			KeWaitForSingleObject(&sc->ndis_block->getevent,
			    0, 0, FALSE, &duetime);
			rval = sc->ndis_block->getstat;
		}
		TRACE(NDBG_GET, "req %u sc %p oid %08X buf %p buflen %u "
		    "written %u needed %u rval %08X\n",
		    req, sc, oid, buf, buflen, *written, *needed, rval);
	} else if (req == NDIS_REQUEST_SET_INFORMATION) {
		KeResetEvent(&sc->ndis_block->setevent);
		KeAcquireSpinLock(&sc->ndis_block->lock, &irql);
		rval = MSCALL6(sc->ndis_chars->set_info_func,
		    sc->ndis_block->miniport_adapter_ctx,
		    oid, buf, buflen, written, needed);
		KeReleaseSpinLock(&sc->ndis_block->lock, irql);
		if (rval == NDIS_STATUS_PENDING) {
			duetime = (5 * 1000000) * -10;
			KeWaitForSingleObject(&sc->ndis_block->setevent,
			    0, 0, FALSE, &duetime);
			rval = sc->ndis_block->setstat;
		}
		TRACE(NDBG_SET, "req %u sc %p oid %08X buf %p buflen %u "
		    "written %u needed %u rval %08X\n",
		    req, sc, oid, buf, buflen, *written, *needed, rval);
	} else
		return (NDIS_STATUS_NOT_SUPPORTED);
	return (rval);
}

inline int
ndis_get(struct ndis_softc *sc, uint32_t oid, void *val, uint32_t len)
{
	return (ndis_request_info(NDIS_REQUEST_QUERY_INFORMATION,
	    sc, oid, val, len, NULL, NULL));
}

inline int
ndis_get_int(struct ndis_softc *sc, uint32_t oid, uint32_t *val)
{
	return (ndis_request_info(NDIS_REQUEST_QUERY_INFORMATION,
	    sc, oid, val, sizeof(uint32_t), NULL, NULL));
}

inline int
ndis_get_info(struct ndis_softc *sc, uint32_t oid, void *buf, uint32_t buflen,
    uint32_t *written, uint32_t *needed)
{
	return (ndis_request_info(NDIS_REQUEST_QUERY_INFORMATION,
	    sc, oid, buf, buflen, written, needed));
}

inline int
ndis_set(struct ndis_softc *sc, uint32_t oid, void *val, uint32_t len)
{
	return (ndis_request_info(NDIS_REQUEST_SET_INFORMATION,
	    sc, oid, val, len, NULL, NULL));
}

inline int
ndis_set_int(struct ndis_softc *sc, uint32_t oid, uint32_t val)
{
	return (ndis_request_info(NDIS_REQUEST_SET_INFORMATION,
	    sc, oid, &val, sizeof(uint32_t), NULL, NULL));
}

inline int
ndis_set_info(struct ndis_softc *sc, uint32_t oid, void *buf, uint32_t buflen,
    uint32_t *written, uint32_t *needed)
{
	return (ndis_request_info(NDIS_REQUEST_SET_INFORMATION,
	    sc, oid, buf, buflen, written, needed));
}

typedef void (*ndis_send_done_func) (void *, struct ndis_packet *, int32_t);

void
ndis_send_packets(struct ndis_softc *sc, struct ndis_packet **packets, int cnt)
{
	int i;
	struct ndis_packet *p;
	uint8_t irql = 0;

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	KASSERT(sc->ndis_block->send_done_func != NULL, ("no send_done"));
	KASSERT(sc->ndis_chars->send_packets_func != NULL, ("no send_packets"));
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeAcquireSpinLock(&sc->ndis_block->lock, &irql);
	MSCALL3(sc->ndis_chars->send_packets_func,
	    sc->ndis_block->miniport_adapter_ctx, packets, cnt);
	for (i = 0; i < cnt; i++) {
		p = packets[i];
		/*
		 * Either the driver already handed the packet to
		 * ndis_txeof() due to a failure, or it wants to keep
		 * it and release it asynchronously later. Skip to the
		 * next one.
		 */
		if (p == NULL || p->oob.status == NDIS_STATUS_PENDING)
			continue;
		MSCALL3(sc->ndis_block->send_done_func,
		    sc->ndis_block, p, p->oob.status);
	}
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeReleaseSpinLock(&sc->ndis_block->lock, irql);
}

int32_t
ndis_send_packet(struct ndis_softc *sc, struct ndis_packet *packet)
{
	int32_t status;
	uint8_t irql = 0;

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	KASSERT(sc->ndis_block->send_done_func != NULL, ("no send_done"));
	KASSERT(sc->ndis_chars->send_func != NULL, ("no send"));
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeAcquireSpinLock(&sc->ndis_block->lock, &irql);
	status = MSCALL3(sc->ndis_chars->send_func,
	    sc->ndis_block->miniport_adapter_ctx, packet,
	    packet->private.flags);
	if (status == NDIS_STATUS_PENDING) {
		if (NDIS_SERIALIZED(sc->ndis_block))
			KeReleaseSpinLock(&sc->ndis_block->lock, irql);
		return (0);
	}
	MSCALL3(sc->ndis_block->send_done_func,
	    sc->ndis_block, packet, status);
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeReleaseSpinLock(&sc->ndis_block->lock, irql);
	return (status);
}

int
ndis_init_dma(struct ndis_softc *sc)
{
	int i;

	sc->ndis_tmaps = malloc(sizeof(bus_dmamap_t) * sc->ndis_maxpkts,
	    M_NDIS_KERN, M_NOWAIT|M_ZERO);
	if (sc->ndis_tmaps == NULL)
		return (ENOMEM);
	for (i = 0; i < sc->ndis_maxpkts; i++) {
		if (bus_dmamap_create(sc->ndis_ttag, 0,
		    &sc->ndis_tmaps[i]) != 0) {
			free(sc->ndis_tmaps, M_NDIS_KERN);
			return (ENODEV);
		}
	}
	return (0);
}

void
ndis_destroy_dma(struct ndis_softc *sc)
{
	int i;

	for (i = 0; i < sc->ndis_maxpkts; i++) {
		if (sc->ndis_txarray[i] != NULL)
			ndis_free_packet(sc->ndis_txarray[i]);
		bus_dmamap_destroy(sc->ndis_ttag, sc->ndis_tmaps[i]);
	}
	free(sc->ndis_tmaps, M_NDIS_KERN);
	bus_dma_tag_destroy(sc->ndis_ttag);
}

int32_t
ndis_reset_nic(struct ndis_softc *sc)
{
	int32_t rval;
	uint8_t addressing_reset;
	uint8_t irql = 0;

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	KASSERT(sc->ndis_chars->reset_func != NULL, ("no reset"));
	KeResetEvent(&sc->ndis_block->resetevent);
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeAcquireSpinLock(&sc->ndis_block->lock, &irql);
	rval = MSCALL2(sc->ndis_chars->reset_func,
	    &addressing_reset, sc->ndis_block->miniport_adapter_ctx);
	if (NDIS_SERIALIZED(sc->ndis_block))
		KeReleaseSpinLock(&sc->ndis_block->lock, irql);
	if (rval == NDIS_STATUS_PENDING) {
		KeWaitForSingleObject(&sc->ndis_block->resetevent, 0, 0,
		    FALSE, NULL);
		rval = sc->ndis_block->resetstat;
	}
	if (rval)
		device_printf(sc->ndis_dev, "failed to reset device; "
		    "status: 0x%08X\n", rval);
	return (rval);
}

uint8_t
ndis_check_for_hang_nic(struct ndis_softc *sc)
{

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	if (sc->ndis_chars->check_hang_func == NULL)
		return (FALSE);
	return (MSCALL1(sc->ndis_chars->check_hang_func,
	    sc->ndis_block->miniport_adapter_ctx));
}

void
ndis_disable_interrupts_nic(struct ndis_softc *sc)
{

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	if (sc->ndis_chars->disable_interrupts_func != NULL)
		MSCALL1(sc->ndis_chars->disable_interrupts_func,
		    sc->ndis_block->miniport_adapter_ctx);
}

void
ndis_enable_interrupts_nic(struct ndis_softc *sc)
{

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	if (sc->ndis_chars->enable_interrupts_func != NULL)
		MSCALL1(sc->ndis_chars->enable_interrupts_func,
		    sc->ndis_block->miniport_adapter_ctx);
}

void
ndis_halt_nic(struct ndis_softc *sc)
{

	if (!cold)
		KeFlushQueuedDpcs();
	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	KASSERT(sc->ndis_chars->halt_func != NULL, ("no halt"));
	KASSERT(sc->ndis_block->device_ctx != NULL, ("already halted"));
	NDIS_LOCK(sc);
	sc->ndis_block->device_ctx = NULL;
	NDIS_UNLOCK(sc);
	MSCALL1(sc->ndis_chars->halt_func,
	    sc->ndis_block->miniport_adapter_ctx);
}

void
ndis_shutdown_nic(struct ndis_softc *sc)
{

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	KASSERT(sc->ndis_chars->shutdown_func != NULL, ("no shutdown"));
	if (sc->ndis_chars->reserved0 == NULL)
		MSCALL1(sc->ndis_chars->shutdown_func,
		    sc->ndis_block->miniport_adapter_ctx);
	else
		MSCALL1(sc->ndis_chars->shutdown_func,
		    sc->ndis_chars->reserved0);
}

void
ndis_pnp_event_nic(struct ndis_softc *sc, uint32_t event, uint32_t profile)
{

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->miniport_adapter_ctx != NULL, ("no adapter"));
	if (sc->ndis_chars->pnp_event_notify_func == NULL)
		return;
	switch (event) {
	case NDIS_DEVICE_PNP_EVENT_SURPRISE_REMOVED:
		if (sc->ndis_block->flags & NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK)
			MSCALL4(sc->ndis_chars->pnp_event_notify_func,
			    sc->ndis_block->miniport_adapter_ctx,
			    event, NULL, 0);
		break;
	case NDIS_DEVICE_PNP_EVENT_POWER_PROFILE_CHANGED:
		MSCALL4(sc->ndis_chars->pnp_event_notify_func,
		    sc->ndis_block->miniport_adapter_ctx,
		    event, &profile, sizeof(profile));
		break;
	default:
		break;
	}
}

int32_t
ndis_init_nic(struct ndis_softc *sc)
{
	int32_t rval, status = 0;
	enum ndis_medium medium_array[] = { NDIS_MEDIUM_802_3 };
	uint32_t chosen_medium = 0;

	KASSERT(sc->ndis_chars != NULL, ("no chars"));
	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_chars->init_func != NULL, ("no init"));
	KASSERT(sc->ndis_block->device_ctx == NULL, ("already initialized"));
	rval = MSCALL6(sc->ndis_chars->init_func, &status, &chosen_medium,
	    medium_array, sizeof(medium_array) / sizeof(medium_array[0]),
	    sc->ndis_block, sc->ndis_block);
	NDIS_LOCK(sc);
	if (rval == NDIS_STATUS_SUCCESS)
		sc->ndis_block->device_ctx = sc;
	else {
		device_printf(sc->ndis_dev, "failed to initialize device; "
		    "status: 0x%08X\n", rval);
	}
	NDIS_UNLOCK(sc);
	return (rval);
}

static void
ndis_interrupt_setup(kdpc *dpc, struct device_object *dobj, irp *ip,
    struct ndis_softc *sc)
{
	struct ndis_miniport_interrupt *intr;

	KASSERT(sc->ndis_block != NULL, ("no block"));
	KASSERT(sc->ndis_block->interrupt != NULL, ("no interrupt"));
	intr = sc->ndis_block->interrupt;
	KeAcquireSpinLockAtDpcLevel(&intr->dpc_count_lock);
	KeResetEvent(&intr->dpcs_completed_event);
	if (KeInsertQueueDpc(&intr->interrupt_dpc, NULL, NULL) == TRUE)
		intr->dpc_count++;
	KeReleaseSpinLockFromDpcLevel(&intr->dpc_count_lock);
}

int32_t
ndis_load_driver(struct driver_object *drv, struct device_object *pdo)
{
	struct device_object *fdo;
	struct ndis_miniport_block *block;
	struct ndis_softc *sc;
	int32_t status;

	sc = device_get_softc(pdo->devext);
	ndis_create_sysctls(sc);
	if (sc->ndis_bus_type == NDIS_PCMCIABUS ||
	    sc->ndis_bus_type == NDIS_PCIBUS) {
		status = bus_setup_intr(sc->ndis_dev, sc->ndis_irq,
		    INTR_TYPE_NET|INTR_MPSAFE, NULL, ntoskrnl_intr, NULL,
		    &sc->ndis_intrhand);
		if (status) {
			device_printf(sc->ndis_dev, "couldn't setup"
			    "interrupt; (%d)\n", status);
			return (NDIS_STATUS_FAILURE);
		}
	}

	status = IoCreateDevice(drv, sizeof(struct ndis_miniport_block), NULL,
	    FILE_DEVICE_UNKNOWN, 0, FALSE, &fdo);
	if (status != NDIS_STATUS_SUCCESS)
		return (status);

	block = fdo->devext;
	block->filter_dbs.ethdb = block;
	block->filter_dbs.trdb = block;
	block->filter_dbs.fddidb = block;
	block->filter_dbs.arcdb = block;
	block->deviceobj = fdo;
	block->physdeviceobj = pdo;
	block->nextdeviceobj = IoAttachDeviceToDeviceStack(fdo, pdo);
	KeInitializeSpinLock(&block->lock);
	KeInitializeSpinLock(&block->returnlock);
	KeInitializeEvent(&block->getevent, EVENT_TYPE_NOTIFY, TRUE);
	KeInitializeEvent(&block->setevent, EVENT_TYPE_NOTIFY, TRUE);
	KeInitializeEvent(&block->resetevent, EVENT_TYPE_NOTIFY, TRUE);
	InitializeListHead(&block->parmlist);
	InitializeListHead(&block->returnlist);
	block->returnitem = IoAllocateWorkItem(fdo);

	/*
	 * Stash pointers to the miniport block and miniport
	 * characteristics info in the if_ndis softc so the
	 * UNIX wrapper driver can get to them later.
	 */
	sc->ndis_block = block;
	sc->ndis_chars = IoGetDriverObjectExtension(drv, (void *)1);

	/*
	 * If the driver has a MiniportTransferData() function,
	 * we should allocate a private RX packet pool.
	 */
	if (sc->ndis_chars->transfer_data_func != NULL) {
		NdisAllocatePacketPool(&status, &block->rxpool,
		    32, PROTOCOL_RESERVED_SIZE_IN_PACKET);
		if (status != NDIS_STATUS_SUCCESS) {
			IoDetachDevice(block->nextdeviceobj);
			IoDeleteDevice(fdo);
			return (status);
		}
		InitializeListHead((&block->packet_list));
	}

	/* Give interrupt handling priority over timers. */
	IoInitializeDpcRequest(fdo, kernndis_functbl[6].wrap);
	KeSetImportanceDpc(&fdo->dpc, KDPC_IMPORTANCE_HIGH);

	/* Finish up BSD-specific setup. */
	block->status_func = kernndis_functbl[0].wrap;
	block->status_done_func = kernndis_functbl[1].wrap;
	block->set_done_func = kernndis_functbl[2].wrap;
	block->query_done_func = kernndis_functbl[3].wrap;
	block->reset_done_func = kernndis_functbl[4].wrap;
	block->send_rsrc_func = kernndis_functbl[5].wrap;

	TAILQ_INSERT_TAIL(&ndis_devhead, block, link);

	return (NDIS_STATUS_SUCCESS);
}

void
ndis_unload_driver(struct ndis_softc *sc)
{
	KASSERT(sc->ndis_block->device_ctx == NULL, ("device present"));
	if (sc->ndis_intrhand) /* FIXME: doesn't belong here */
		bus_teardown_intr(sc->ndis_dev,
		    sc->ndis_irq, sc->ndis_intrhand);

	if (sc->ndis_block->rlist != NULL)
		free(sc->ndis_block->rlist, M_NDIS_KERN);

	TAILQ_REMOVE(&ndis_devhead, sc->ndis_block, link);
	if (sc->ndis_chars->transfer_data_func != NULL)
		NdisFreePacketPool(sc->ndis_block->rxpool);
	IoFreeWorkItem(sc->ndis_block->returnitem);
	IoDetachDevice(sc->ndis_block->nextdeviceobj);
	IoDeleteDevice(sc->ndis_block->deviceobj);
	ndis_flush_sysctls(sc);
}
