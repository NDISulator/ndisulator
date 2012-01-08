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
 *
 * $FreeBSD$
 */

#ifndef _IF_NDISVAR_H_
#define	_IF_NDISVAR_H_

#include <net80211/ieee80211_var.h>

extern devclass_t ndis_devclass;

int	ndis_attach(device_t);
int	ndis_detach(device_t);
int	ndis_resume(device_t);
int	ndis_shutdown(device_t);
int	ndis_suspend(device_t);
int	ndisdrv_modevent(module_t, int, void *);
void	ndis_free_amem(void *);

struct ndis_oid_data {		/* For setting/getting OIDs from userspace. */
	uint32_t	oid;
	uint32_t	len;
};

struct ndis_shmem {
	struct list_entry	ndis_list;
	bus_dma_tag_t		ndis_stag;
	bus_dmamap_t		ndis_smap;
	void			*ndis_saddr;
	uint64_t		ndis_paddr;
};

struct ndis_cfglist {
	struct ndis_cfg		ndis_cfg;
	struct sysctl_oid	*ndis_oid;
        TAILQ_ENTRY(ndis_cfglist)	link;
};
TAILQ_HEAD(nch, ndis_cfglist);

#define	NDIS_INITIALIZED(sc)	(sc->ndis_block->device_ctx != NULL)
#define	NDIS_80211(sc)		\
	(sc->ndis_physical_medium == NDIS_PHYSICAL_MEDIUM_WIRELESS_LAN)

#define	NDIS_EVENTS	4
#define	NDIS_EVTINC(x)	(x) = ((x) + 1) % NDIS_EVENTS

struct ndis_evt {
	uint32_t	ne_sts;
	uint32_t	ne_len;
	char		*ne_buf;
};

struct ndis_vap {
	struct ieee80211vap	vap;
	int	(*newstate)(struct ieee80211vap *, enum ieee80211_state, int);
};

#define	NDIS_VAP(vap)	((struct ndis_vap *)(vap))

#define	NDISUSB_CONFIG_NO			0
#define	NDISUSB_IFACE_INDEX			0

struct ndisusb_ep {
	struct usb_xfer		*ne_xfer[1];
	struct list_entry	ne_active;
	struct list_entry	ne_pending;
	unsigned long		ne_lock;
	uint8_t			ne_dirin;
};

struct ndisusb_xfer {
	struct ndisusb_ep	*nx_ep;
	void			*nx_priv;
	uint8_t			*nx_urbbuf;
	uint32_t		nx_urbactlen;
	uint32_t		nx_urblen;
	uint8_t			nx_shortxfer;
	struct list_entry	nx_next;
};

struct ndisusb_xferdone {
	struct ndisusb_xfer	*nd_xfer;
	usb_error_t		nd_status;
	struct list_entry	nd_donelist;
};

struct ndisusb_task {
	unsigned		nt_type;
#define	NDISUSB_TASK_TSTART	0
#define	NDISUSB_TASK_IRPCANCEL	1
#define	NDISUSB_TASK_VENDOR	2
	void			*nt_ctx;
	struct list_entry	nt_tasklist;
};

struct ndis_softc {
	struct ifnet			*ndis_ifp;
	struct ifmedia			ifmedia;	/* media info */
	u_long				ndis_hwassist;
	uint32_t			ndis_v4tx;
	uint32_t			ndis_v4rx;
	bus_space_handle_t		ndis_bhandle;
	bus_space_tag_t			ndis_btag;
	void				*ndis_intrhand;
	struct resource			*ndis_irq;
	struct resource			*ndis_res;
	struct resource			*ndis_res_io;
	int				ndis_io_rid;
	struct resource			*ndis_res_mem;
	int				ndis_mem_rid;
	struct resource			*ndis_res_altmem;
	int				ndis_altmem_rid;
	struct resource			*ndis_res_am;
	int				ndis_am_rid;
	struct resource			*ndis_res_cm;
	struct resource_list		ndis_rl;
	uint32_t			ndis_rescnt;
	struct mtx			ndis_mtx;
	device_t			ndis_dev;
	struct ndis_miniport_block	*ndis_block;
	struct ndis_miniport_characteristics *ndis_chars;
	struct callout			ndis_scan_callout;
	struct callout			ndis_stat_callout;
	uint32_t			ndis_maxpkts;
	uint32_t			ndis_txidx;
	uint32_t			ndis_txpending;
	struct ndis_packet		**ndis_txarray;
	struct ndis_packet_pool		*ndis_txpool;
	uint8_t				ndis_sc;
	struct ndis_cfg			*ndis_regvals;
	struct nch			ndis_cfglist_head;
	enum ndis_physical_medium	ndis_physical_medium;
	uint32_t			ndis_devidx;
	enum ndis_bus_type		ndis_bus_type;
	struct driver_object		*ndis_dobj;
	struct io_workitem		*ndis_tickitem;
	struct io_workitem		*ndis_startitem;
	struct io_workitem		*ndis_resetitem;
	struct io_workitem		*ndis_inputitem;
	struct nt_kdpc			ndis_rxdpc;
	bus_dma_tag_t			ndis_parent_tag;
	struct list_entry		ndis_shlist;
	bus_dma_tag_t			ndis_mtag;
	bus_dma_tag_t			ndis_ttag;
	bus_dmamap_t			*ndis_mmaps;
	bus_dmamap_t			*ndis_tmaps;
	uint32_t			ndis_mmapcnt;
	struct ndis_evt			ndis_evt[NDIS_EVENTS];
	uint32_t			ndis_evtpidx;
	uint32_t			ndis_evtcidx;
	struct ifqueue			ndis_rxqueue;
	unsigned long			ndis_rxlock;

	int			(*ndis_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
	uint8_t				ndis_tx_timer;
	uint32_t			ndis_hang_timer;

	struct usb_device		*ndisusb_dev;
	struct mtx			ndisusb_mtx;
	struct ndisusb_ep		ndisusb_dread_ep;
	struct ndisusb_ep		ndisusb_dwrite_ep;
#define	NDISUSB_GET_ENDPT(addr) \
	((UE_GET_DIR(addr) >> 7) | (UE_GET_ADDR(addr) << 1))
#define	NDISUSB_ENDPT_MAX	((UE_ADDR + 1) * 2)
	struct ndisusb_ep		ndisusb_ep[NDISUSB_ENDPT_MAX];
	struct io_workitem		*ndisusb_xferdoneitem;
	struct list_entry		ndisusb_xferdonelist;
	unsigned long			ndisusb_xferdonelock;
	struct io_workitem		*ndisusb_taskitem;
	struct list_entry		ndisusb_tasklist;
	unsigned long			ndisusb_tasklock;
	int				ndisusb_status;
#define	NDISUSB_STATUS_DETACH	0x1
#define	NDISUSB_STATUS_SETUP_EP	0x2
};

#define	NDIS_LOCK(_sc)			mtx_lock(&(_sc)->ndis_mtx)
#define	NDIS_UNLOCK(_sc)		mtx_unlock(&(_sc)->ndis_mtx)
#define	NDIS_LOCK_ASSERT(_sc, t)	mtx_assert(&(_sc)->ndis_mtx, t)
#define	NDISUSB_LOCK(_sc)		mtx_lock(&(_sc)->ndisusb_mtx)
#define	NDISUSB_UNLOCK(_sc)		mtx_unlock(&(_sc)->ndisusb_mtx)
#define	NDISUSB_LOCK_ASSERT(_sc, t)	mtx_assert(&(_sc)->ndisusb_mtx, t)

#endif /* _IF_NDISVAR_H_ */
