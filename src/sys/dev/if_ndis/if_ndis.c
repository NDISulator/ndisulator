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
 * WPA support originally contributed by Arvind Srinivasan <arvind@celar.us>
 * then hacked upon mercilessly by my.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/sockio.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/module.h>
#include <sys/priv.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/cfg_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/hal_var.h>
#include <compat/ndis/ndis_var.h>
#include <compat/ndis/usbd_var.h>
#include <dev/if_ndis/if_ndisvar.h>
#include <net80211/ieee80211_regdomain.h>

#define	NDIS_DEBUG
#ifdef NDIS_DEBUG
#define	DPRINTF(...)	do { if (ndis_debug > 0) device_printf(sc->ndis_dev, __VA_ARGS__); } while (0)
static int ndis_debug = 0;
SYSCTL_INT(_debug, OID_AUTO, ndis, CTLFLAG_RW, &ndis_debug, 0,
    "if_ndis debug level");
#else
#define	DPRINTF(x)
#endif

SYSCTL_DECL(_hw_ndisusb);
static int ndisusb_halt = 1;
SYSCTL_INT(_hw_ndisusb, OID_AUTO, halt, CTLFLAG_RW, &ndisusb_halt, 0,
    "Halt NDIS USB driver when it's attached");

/* 0 - 30 dBm to mW conversion table */
static const uint16_t dBm2mW[] = {
	1, 1, 1, 1, 2, 2, 2, 2, 3, 3,
	3, 4, 4, 4, 5, 6, 6, 7, 8, 9,
	10, 11, 13, 14, 16, 18, 20, 22, 25, 28,
	32, 35, 40, 45, 50, 56, 63, 71, 79, 89,
	100, 112, 126, 141, 158, 178, 200, 224, 251, 282,
	316, 355, 398, 447, 501, 562, 631, 708, 794, 891,
	1000
};

MODULE_DEPEND(ndis, ether, 1, 1, 1);
MODULE_DEPEND(ndis, wlan, 1, 1, 1);
MODULE_DEPEND(ndis, ndisapi, 1, 1, 1);
MODULE_VERSION(ndis, 1);

int		ndis_attach(device_t);
int		ndis_detach(device_t);
int		ndis_suspend(device_t);
int		ndis_resume(device_t);
void		ndis_shutdown(device_t);
int		ndisdrv_modevent(module_t, int, void *);
static void	ndis_txeof(ndis_handle, ndis_packet *, ndis_status);
static void	ndis_rxeof(ndis_handle, ndis_packet **, uint32_t);
static void	ndis_rxeof_eth(ndis_handle, ndis_handle, char *, void *,
			uint32_t, void *, uint32_t, uint32_t);
static void	ndis_rxeof_done(ndis_handle);
static void	ndis_rxeof_xfr(kdpc *, ndis_handle, void *, void *);
static void	ndis_rxeof_xfr_done(ndis_handle, ndis_packet *, uint32_t,
			uint32_t);
static void	ndis_linksts(ndis_handle, ndis_status, void *, uint32_t);
static void	ndis_linksts_done(ndis_handle);

/* We need to wrap these functions for amd64. */
static funcptr ndis_txeof_wrap;
static funcptr ndis_rxeof_wrap;
static funcptr ndis_rxeof_eth_wrap;
static funcptr ndis_rxeof_done_wrap;
static funcptr ndis_rxeof_xfr_wrap;
static funcptr ndis_rxeof_xfr_done_wrap;
static funcptr ndis_linksts_wrap;
static funcptr ndis_linksts_done_wrap;
static funcptr ndis_ticktask_wrap;
static funcptr ndis_starttask_wrap;
static funcptr ndis_resettask_wrap;
static funcptr ndis_inputtask_wrap;

static struct ieee80211vap *ndis_vap_create(struct ieee80211com *,
		    const char name[IFNAMSIZ], int unit, int opmode,
		    int flags, const uint8_t bssid[IEEE80211_ADDR_LEN],
		    const uint8_t mac[IEEE80211_ADDR_LEN]);
static void	ndis_vap_delete(struct ieee80211vap *);
static int	ndis_reset_vap(struct ieee80211vap *, u_long);
static int	ndis_auth_mode(uint32_t);
static void	ndis_auth(struct ndis_softc *, struct ieee80211vap *);
static void	ndis_assoc(struct ndis_softc *, struct ieee80211vap *);
static void	ndis_disassociate(struct ndis_softc *, struct ieee80211vap *);
static int	ndis_get_bssid_list(struct ndis_softc *,
			ndis_80211_bssid_list_ex **);
static int	ndis_get_oids(struct ndis_softc *, ndis_oid **, uint32_t *);
static void	ndis_getstate_80211(struct ndis_softc *, struct ieee80211vap *);
static void	ndis_ifmedia_sts(struct ifnet *, struct ifmediareq *);
static int	ndis_ifmedia_upd(struct ifnet *);
static void	ndis_init(void *);
static int	ndis_ioctl(struct ifnet *, u_long, caddr_t);
static int	ndis_ioctl_80211(struct ifnet *, u_long, caddr_t);
static void	ndis_inputtask(device_object *, void *);
static int	ndis_key_set(struct ieee80211vap *,
			const struct ieee80211_key *, const u_int8_t []);
static int	ndis_key_delete(struct ieee80211vap *,
			const struct ieee80211_key *);
static void	ndis_map_sclist(void *, bus_dma_segment_t *, int, bus_size_t,
			int);
static void	ndis_media_status(struct ifnet *, struct ifmediareq *);
static int	ndis_nettype_chan(uint32_t);
static int	ndis_nettype_mode(uint32_t);
static int	ndis_newstate(struct ieee80211vap *, enum ieee80211_state, int);
static int	ndis_get_physical_medium(struct ndis_softc *, uint32_t *);
static int	ndis_probe_task_offload(struct ndis_softc *);
static int	ndis_raw_xmit(struct ieee80211_node *, struct mbuf *,
			const struct ieee80211_bpf_params *);
static void	ndis_resettask(device_object *, void *);
static void	ndis_scan(void *);
static void	ndis_scan_end(struct ieee80211com *);
static void	ndis_scan_curchan(struct ieee80211_scan_state *, unsigned long);
static void	ndis_scan_mindwell(struct ieee80211_scan_state *);
static void	ndis_scan_start(struct ieee80211com *);
static int	ndis_send_mgmt(struct ieee80211_node *, int, int);
static int	ndis_set_authmode(struct ndis_softc *, uint32_t);
static void	ndis_set_bssid(struct ndis_softc *, ndis_80211_macaddr);
static void	ndis_set_channel(struct ieee80211com *);
static int	ndis_set_cipher(struct ndis_softc *, int);
static int	ndis_set_encryption(struct ndis_softc *, uint32_t);
static int	ndis_set_filter(struct ndis_softc *, uint32_t);
static int	ndis_set_fragthreshold(struct ndis_softc *, uint16_t);
static int	ndis_set_infra(struct ndis_softc *, int);
static int	ndis_set_multi(struct ndis_softc *);
static int	ndis_set_task_offload(struct ndis_softc *);
static int	ndis_set_powersave(struct ndis_softc *, uint32_t);
static int	ndis_get_powerstate(struct ndis_softc *, uint32_t *);
static int	ndis_set_powerstate(struct ndis_softc *, uint32_t);
static void	ndis_set_privacy_filter(struct ndis_softc *, uint32_t);
static int	ndis_set_rtsthreshold(struct ndis_softc *, uint16_t);
static void	ndis_set_ssid(struct ndis_softc *, uint8_t *, uint8_t);
static int	ndis_set_txpower(struct ndis_softc *);
static int	ndis_set_wpa(struct ndis_softc *, void *, int);
static void	ndis_setstate_80211(struct ndis_softc *, struct ieee80211vap *);
static void	ndis_start(struct ifnet *);
static void	ndis_starttask(device_object *, void *);
static void	ndis_stop(struct ndis_softc *);
static void	ndis_tick(void *);
static void	ndis_ticktask(device_object *, void *);
static void	ndis_update_mcast(struct ifnet *ifp);
static void	ndis_update_promisc(struct ifnet *ifp);

static int ndisdrv_loaded = 0;

MALLOC_DEFINE(M_NDIS_DEV, "ndis_dev", "if_ndis buffers");

/*
 * This routine should call windrv_load() once for each driver image.
 * This will do the relocation and dynalinking for the image, and create
 * a Windows driver object which will be saved in our driver database.
 */
int
ndisdrv_modevent(module_t mod, int cmd, void *arg)
{
	switch (cmd) {
	case MOD_LOAD:
		if (ndisdrv_loaded == 1)
			break;
		ndisdrv_loaded = 1;
		windrv_wrap((funcptr)ndis_rxeof, &ndis_rxeof_wrap,
		    3, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_rxeof_eth, &ndis_rxeof_eth_wrap,
		    8, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_rxeof_done, &ndis_rxeof_done_wrap,
		    1, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_rxeof_xfr, &ndis_rxeof_xfr_wrap,
		    4, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_rxeof_xfr_done,
		    &ndis_rxeof_xfr_done_wrap, 4, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_txeof, &ndis_txeof_wrap,
		    3, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_linksts, &ndis_linksts_wrap,
		    4, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_linksts_done,
		    &ndis_linksts_done_wrap, 1, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_ticktask, &ndis_ticktask_wrap,
		    2, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_starttask, &ndis_starttask_wrap,
		    2, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_resettask, &ndis_resettask_wrap,
		    2, WINDRV_WRAP_STDCALL);
		windrv_wrap((funcptr)ndis_inputtask, &ndis_inputtask_wrap,
		    2, WINDRV_WRAP_STDCALL);
		break;
	case MOD_UNLOAD:
		if (ndisdrv_loaded == 0)
			break;
		ndisdrv_loaded = 0;
		/* fallthrough */
	case MOD_SHUTDOWN:
		windrv_unwrap(ndis_rxeof_wrap);
		windrv_unwrap(ndis_rxeof_eth_wrap);
		windrv_unwrap(ndis_rxeof_done_wrap);
		windrv_unwrap(ndis_rxeof_xfr_wrap);
		windrv_unwrap(ndis_rxeof_xfr_done_wrap);
		windrv_unwrap(ndis_txeof_wrap);
		windrv_unwrap(ndis_linksts_wrap);
		windrv_unwrap(ndis_linksts_done_wrap);
		windrv_unwrap(ndis_ticktask_wrap);
		windrv_unwrap(ndis_starttask_wrap);
		windrv_unwrap(ndis_resettask_wrap);
		windrv_unwrap(ndis_inputtask_wrap);
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}

static int
ndis_get_oids(struct ndis_softc *sc, ndis_oid **oids, uint32_t *oidcnt)
{
	uint32_t len;

	*oidcnt = 0;
	ndis_get_info(sc, OID_GEN_SUPPORTED_LIST, NULL, 0, NULL, &len);
	*oids = malloc(len, M_NDIS_DEV, M_NOWAIT|M_ZERO);
	if (*oids == NULL)
		return (ENOMEM);
	if (ndis_get(sc, OID_GEN_SUPPORTED_LIST, *oids, len)) {
		free(*oids, M_NDIS_DEV);
		return (ENXIO);
	}
	*oidcnt = len / 4;
	return (0);
}

static int
ndis_get_physical_medium(struct ndis_softc *sc, uint32_t *medium)
{
	return (ndis_get_int(sc, OID_GEN_PHYSICAL_MEDIUM, medium));
}

static int
ndis_set_txpower(struct ndis_softc *sc)
{
	struct ieee80211com *ic = sc->ndis_ifp->if_l2com;
	ndis_80211_power power;

	power = dBm2mW[ic->ic_txpowlimit];
	if (ndis_set_int(sc, OID_802_11_TX_POWER_LEVEL, power))
		return (EINVAL);
	return (0);
}

static int
ndis_set_powersave(struct ndis_softc *sc, uint32_t flags)
{
	uint32_t arg;

	if (flags & IEEE80211_F_PMGTON)
		arg = NDIS_802_11_POWERMODE_FAST_PSP;
	else
		arg = NDIS_802_11_POWERMODE_CAM;
	return (ndis_set_int(sc, OID_802_11_POWER_MODE, arg));
}

static int
ndis_get_powerstate(struct ndis_softc *sc, uint32_t *state)
{
	return (ndis_get_int(sc, OID_PNP_QUERY_POWER, state));
}

static int
ndis_set_powerstate(struct ndis_softc *sc, uint32_t nstate)
{
	int error;
	uint32_t ostate;

	error = ndis_get_powerstate(sc, &ostate);
	if (error)
		return (error);
	if (ostate == nstate)
		return (0);
	return (ndis_set_int(sc, OID_PNP_SET_POWER, nstate));
}

static int
ndis_set_rtsthreshold(struct ndis_softc *sc, uint16_t nrts)
{
	ndis_80211_rtsthresh rts = nrts;

	return (ndis_set_int(sc, OID_802_11_RTS_THRESHOLD, rts));
}

static int
ndis_set_fragthreshold(struct ndis_softc *sc, uint16_t nfrag)
{
	ndis_80211_fragthresh frag = nfrag;

	return (ndis_set_int(sc, OID_802_11_FRAGMENTATION_THRESHOLD, frag));
}

static int
ndis_set_encryption(struct ndis_softc *sc, uint32_t mode)
{
	return (ndis_set_int(sc, OID_802_11_ENCRYPTION_STATUS, mode));
}

static int
ndis_set_authmode(struct ndis_softc *sc, uint32_t mode)
{
	return (ndis_set_int(sc, OID_802_11_AUTHENTICATION_MODE, mode));
}

static int
ndis_set_filter(struct ndis_softc *sc, uint32_t filter)
{
	return (ndis_set_int(sc, OID_GEN_CURRENT_PACKET_FILTER, filter));
}

static void
ndis_set_privacy_filter(struct ndis_softc *sc, uint32_t filter)
{
	uint32_t arg;

	if (filter & IEEE80211_F_DROPUNENC)
		arg = NDIS_802_11_PRIVFILT_8021XWEP;
	else
		arg = NDIS_802_11_PRIVFILT_ACCEPTALL;
	ndis_set_int(sc, OID_802_11_PRIVACY_FILTER, arg);
}

/*
 * Program the 64-bit multicast hash filter.
 */
static int
ndis_set_multi(struct ndis_softc *sc)
{
	struct ifnet *ifp = sc->ndis_ifp;
	struct ifmultiaddr *ifma;
	uint32_t len = 0, mclistsz;
	uint8_t *mclist;

	if (ifp->if_flags & IFF_ALLMULTI || ifp->if_flags & IFF_PROMISC) {
		sc->ndis_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
		return (ndis_set_filter(sc, sc->ndis_filter));
	}

	if (TAILQ_EMPTY(&ifp->if_multiaddrs))
		return (EINVAL);

	ndis_get_int(sc, OID_802_3_MAXIMUM_LIST_SIZE, &mclistsz);
	mclist = malloc(ETHER_ADDR_LEN * mclistsz, M_NDIS_DEV, M_NOWAIT|M_ZERO);
	if (mclist == NULL) {
		sc->ndis_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
		goto out;
	}

	sc->ndis_filter |= NDIS_PACKET_TYPE_MULTICAST;

	if_maddr_rlock(ifp);
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;
		memcpy(mclist + (ETHER_ADDR_LEN * len),
		    LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    ETHER_ADDR_LEN);
		len++;
		if (len > mclistsz) {
			if_maddr_runlock(ifp);
			sc->ndis_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
			sc->ndis_filter &= ~NDIS_PACKET_TYPE_MULTICAST;
			goto out;
		}
	}
	if_maddr_runlock(ifp);

	len = len * ETHER_ADDR_LEN;
	if (ndis_set(sc, OID_802_3_MULTICAST_LIST, mclist, len)) {
		DPRINTF("set mclist failed\n");
		sc->ndis_filter |= NDIS_PACKET_TYPE_ALL_MULTICAST;
		sc->ndis_filter &= ~NDIS_PACKET_TYPE_MULTICAST;
	}
out:
	free(mclist, M_NDIS_DEV);
	return (ndis_set_filter(sc, sc->ndis_filter));
}

static int
ndis_set_task_offload(struct ndis_softc *sc)
{
	struct ifnet *ifp = sc->ndis_ifp;
	ndis_task_offload *nto;
	ndis_task_offload_hdr *ntoh;
	ndis_task_tcpip_csum *nttc;
	int error;
	uint32_t len;

	if (!NDIS_INITIALIZED(sc))
		return (EINVAL);

	error = ndis_probe_task_offload(sc);
	if (error)
		return (error);

	if (sc->ndis_hwassist == 0 && ifp->if_capabilities == 0)
		return (0);

	len = sizeof(ndis_task_offload_hdr) + sizeof(ndis_task_offload) +
	    sizeof(ndis_task_tcpip_csum);

	ntoh = malloc(len, M_NDIS_DEV, M_NOWAIT|M_ZERO);
	if (ntoh == NULL)
		return (ENOMEM);
	ntoh->vers = NDIS_TASK_OFFLOAD_VERSION;
	ntoh->len = sizeof(ndis_task_offload_hdr);
	ntoh->offset_firsttask = sizeof(ndis_task_offload_hdr);
	ntoh->encapfmt.encaphdrlen = sizeof(struct ether_header);
	ntoh->encapfmt.encap = NDIS_ENCAP_IEEE802_3;
	ntoh->encapfmt.flags = NDIS_ENCAPFLAG_FIXEDHDRLEN;

	nto = (ndis_task_offload *)((char *)ntoh +
	    ntoh->offset_firsttask);
	nto->vers = NDIS_TASK_OFFLOAD_VERSION;
	nto->len = sizeof(ndis_task_offload);
	nto->task = NDIS_TASK_TCPIP_CSUM;
	nto->offset_nexttask = 0;
	nto->taskbuflen = sizeof(ndis_task_tcpip_csum);

	nttc = (ndis_task_tcpip_csum *)nto->taskbuf;

	if (ifp->if_capenable & IFCAP_TXCSUM)
		nttc->v4tx = sc->ndis_v4tx;

	if (ifp->if_capenable & IFCAP_RXCSUM)
		nttc->v4rx = sc->ndis_v4rx;

	error = ndis_set(sc, OID_TCP_TASK_OFFLOAD, ntoh, len);
	free(ntoh, M_NDIS_DEV);
	return (error);
}

static int
ndis_probe_task_offload(struct ndis_softc *sc)
{
	struct ifnet *ifp = sc->ndis_ifp;
	ndis_task_offload *nto;
	ndis_task_offload_hdr *ntoh;
	ndis_task_tcpip_csum *nttc = NULL;
	int error, dummy;
	uint32_t len;

	len = sizeof(dummy);
	error = ndis_get(sc, OID_TCP_TASK_OFFLOAD, &dummy, len);
	if (!(error == NDIS_STATUS_INVALID_LENGTH ||
	    error == NDIS_STATUS_BUFFER_TOO_SHORT))
		return (error);

	ntoh = malloc(len, M_NDIS_DEV, M_NOWAIT|M_ZERO);
	if (ntoh == NULL)
		return (ENOMEM);
	ntoh->vers = NDIS_TASK_OFFLOAD_VERSION;
	ntoh->len = sizeof(ndis_task_offload_hdr);
	ntoh->encapfmt.encaphdrlen = sizeof(struct ether_header);
	ntoh->encapfmt.encap = NDIS_ENCAP_IEEE802_3;
	ntoh->encapfmt.flags = NDIS_ENCAPFLAG_FIXEDHDRLEN;

	error = ndis_get(sc, OID_TCP_TASK_OFFLOAD, ntoh, len);
	if (error) {
		free(ntoh, M_NDIS_DEV);
		return (error);
	}

	if (ntoh->vers != NDIS_TASK_OFFLOAD_VERSION) {
		free(ntoh, M_NDIS_DEV);
		return (EINVAL);
	}

	nto = (ndis_task_offload *)((char *)ntoh +
	    ntoh->offset_firsttask);
	for (;;) {
		switch (nto->task) {
		case NDIS_TASK_TCPIP_CSUM:
			nttc = (ndis_task_tcpip_csum *)nto->taskbuf;
			break;
		/* Don't handle these yet. */
		case NDIS_TASK_IPSEC:
		case NDIS_TASK_TCP_LARGESEND:
		default:
			break;
		}
		if (nto->offset_nexttask == 0)
			break;
		nto = (ndis_task_offload *)((char *)nto +
		    nto->offset_nexttask);
	}

	if (nttc == NULL) {
		free(ntoh, M_NDIS_DEV);
		return (ENOENT);
	}

	sc->ndis_v4tx = nttc->v4tx;
	sc->ndis_v4rx = nttc->v4rx;

	if (nttc->v4tx & NDIS_TCPSUM_FLAGS_IP_CSUM)
		sc->ndis_hwassist |= CSUM_IP;
	if (nttc->v4tx & NDIS_TCPSUM_FLAGS_TCP_CSUM)
		sc->ndis_hwassist |= CSUM_TCP;
	if (nttc->v4tx & NDIS_TCPSUM_FLAGS_UDP_CSUM)
		sc->ndis_hwassist |= CSUM_UDP;
	if (sc->ndis_hwassist)
		ifp->if_capabilities |= IFCAP_TXCSUM;
	if (nttc->v4rx & NDIS_TCPSUM_FLAGS_IP_CSUM)
		ifp->if_capabilities |= IFCAP_RXCSUM;
	if (nttc->v4rx & NDIS_TCPSUM_FLAGS_TCP_CSUM)
		ifp->if_capabilities |= IFCAP_RXCSUM;
	if (nttc->v4rx & NDIS_TCPSUM_FLAGS_UDP_CSUM)
		ifp->if_capabilities |= IFCAP_RXCSUM;

	free(ntoh, M_NDIS_DEV);
	return (0);
}

static int
ndis_nettype_chan(uint32_t type)
{
	switch (type) {
	case NDIS_802_11_NETTYPE_11FH:		return (IEEE80211_CHAN_FHSS);
	case NDIS_802_11_NETTYPE_11DS:		return (IEEE80211_CHAN_B);
	case NDIS_802_11_NETTYPE_11OFDM5:	return (IEEE80211_CHAN_A);
	case NDIS_802_11_NETTYPE_11OFDM24:	return (IEEE80211_CHAN_G);
	}
	return (IEEE80211_CHAN_ANY);
}

static int
ndis_nettype_mode(uint32_t type)
{
	switch (type) {
	case NDIS_802_11_NETTYPE_11FH:		return (IEEE80211_MODE_FH);
	case NDIS_802_11_NETTYPE_11DS:		return (IEEE80211_MODE_11B);
	case NDIS_802_11_NETTYPE_11OFDM5:	return (IEEE80211_MODE_11A);
	case NDIS_802_11_NETTYPE_11OFDM24:	return (IEEE80211_MODE_11G);
	}
	return (IEEE80211_MODE_AUTO);
}

static int
ndis_auth_mode(uint32_t type)
{
	switch (type) {
	case NDIS_802_11_AUTHMODE_OPEN:		return (IEEE80211_AUTH_OPEN);
	case NDIS_802_11_AUTHMODE_SHARED:	return (IEEE80211_AUTH_SHARED);
	case NDIS_802_11_AUTHMODE_AUTO:		return (IEEE80211_AUTH_AUTO);
	case NDIS_802_11_AUTHMODE_WPA:
	case NDIS_802_11_AUTHMODE_WPAPSK:
	case NDIS_802_11_AUTHMODE_WPANONE:
	case NDIS_802_11_AUTHMODE_WPA2:
	case NDIS_802_11_AUTHMODE_WPA2PSK:	return (IEEE80211_AUTH_WPA);
	}
	return (IEEE80211_AUTH_NONE);
}

/*
 * Attach the interface. Allocate softc structures, do ifmedia
 * setup and ethernet/BPF attach.
 */
int
ndis_attach(device_t dev)
{
	u_char eaddr[ETHER_ADDR_LEN];
	struct ndis_softc *sc;
	driver_object *pdrv;
	device_object *pdo;
	struct ifnet *ifp = NULL;
	int mode, i = 0;
	uint32_t rval, len;
	uint8_t bands = 0;

	sc = device_get_softc(dev);
	mtx_init(&sc->ndis_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
	    MTX_DEF);
	KeInitializeSpinLock(&sc->ndis_rxlock);
	KeInitializeSpinLock(&sc->ndisusb_tasklock);
	KeInitializeSpinLock(&sc->ndisusb_xferdonelock);
	InitializeListHead(&sc->ndis_shlist);
	InitializeListHead(&sc->ndisusb_tasklist);
	InitializeListHead(&sc->ndisusb_xferdonelist);
	callout_init(&sc->ndis_stat_callout, CALLOUT_MPSAFE);

	if (sc->ndis_iftype == PCMCIABus) {
		rval = ndis_alloc_amem(sc);
		if (rval) {
			device_printf(dev, "failed to allocate "
			    "attribute memory\n");
			goto fail;
		}
	}
	ndis_create_sysctls(sc);

	/* Find the PDO for this device instance. */
	if (sc->ndis_iftype == PCIBus)
		pdrv = windrv_lookup(0, "PCI Bus");
	else if (sc->ndis_iftype == PCMCIABus)
		pdrv = windrv_lookup(0, "PCCARD Bus");
	else if (sc->ndis_iftype == PNPBus)
		pdrv = windrv_lookup(0, "USB Bus");
	else {
		device_printf(dev, "unsupported interface type\n");
		goto fail;
	}
	if (pdrv == NULL) {
		device_printf(dev, "failed to lookup PDO\n");
		goto fail;
	}
	pdo = windrv_find_pdo(pdrv, dev);
	if (pdo == NULL) {
		device_printf(dev, "failed to find PDO\n");
		goto fail;
	}

	/*
	 * Create a new functional device object for this device.
	 * This is what creates the miniport block for this device instance.
	 */
	if (NdisAddDevice(sc->ndis_dobj, pdo) != NDIS_STATUS_SUCCESS) {
		device_printf(dev, "failed to create FDO\n");
		goto fail;
	}

	/* Do resource conversion. */
	if (sc->ndis_iftype == PCMCIABus || sc->ndis_iftype == PCIBus)
		ndis_convert_res(sc);
	else
		sc->ndis_block->rlist = NULL;

	/* Install our RX and TX interrupt handlers. */
	sc->ndis_block->send_done_func = ndis_txeof_wrap;
	sc->ndis_block->pkt_indicate_func = ndis_rxeof_wrap;
	sc->ndis_block->ethrx_indicate_func = ndis_rxeof_eth_wrap;
	sc->ndis_block->ethrx_done_func = ndis_rxeof_done_wrap;
	sc->ndis_block->tdcond_func = ndis_rxeof_xfr_done_wrap;

	/* Override the status handler so we can detect link changes. */
	sc->ndis_block->status_func = ndis_linksts_wrap;
	sc->ndis_block->status_done_func = ndis_linksts_done_wrap;

	/* Set up work item handlers. */
	sc->ndis_tickitem = IoAllocateWorkItem(sc->ndis_block->deviceobj);
	sc->ndis_startitem = IoAllocateWorkItem(sc->ndis_block->deviceobj);
	sc->ndis_resetitem = IoAllocateWorkItem(sc->ndis_block->deviceobj);
	sc->ndis_inputitem = IoAllocateWorkItem(sc->ndis_block->deviceobj);
	sc->ndisusb_xferdoneitem =
	    IoAllocateWorkItem(sc->ndis_block->deviceobj);
	sc->ndisusb_taskitem =
	    IoAllocateWorkItem(sc->ndis_block->deviceobj);
	KeInitializeDpc(&sc->ndis_rxdpc, ndis_rxeof_xfr_wrap, sc->ndis_block);

	rval = ndis_init_nic(sc);
	if (rval) {
		device_printf(dev, "failed to initialize device; "
		    "status: 0x%0X\n", rval);
		goto fail;
	}

	rval = ndis_get_oids(sc, &sc->ndis_oids, &sc->ndis_oidcnt);
	if (rval) {
		device_printf(dev, "failed to get supported oids; "
		    "status: 0x%0X\n", rval);
		goto fail;
	}
	if (bootverbose) {
		device_printf(dev, "NDIS API %d.%d\n",
		    sc->ndis_chars->version_major,
		    sc->ndis_chars->version_minor);
		device_printf(dev,"supported oids:\n");
		for (i = 0; i < sc->ndis_oidcnt; i++)
			device_printf(dev, "\t\t0x%08X\n", sc->ndis_oids[i]);
		if (!ndis_get_int(sc, OID_GEN_VENDOR_DRIVER_VERSION, &i))
			device_printf(dev, "driver version: 0x%0X\n", i);
		if (!ndis_get_int(sc, OID_GEN_HARDWARE_STATUS, &i))
			device_printf(dev, "hardware status: %d\n", i);
	}

	rval = ndis_get(sc, OID_802_3_CURRENT_ADDRESS, &eaddr, sizeof(eaddr));
	if (rval) {
		device_printf(dev, "get current address failed; "
		     "status: 0x%0X\n", rval);
		goto fail;
	}

	rval = ndis_get_int(sc,
	    OID_GEN_MAXIMUM_SEND_PACKETS, &sc->ndis_maxpkts);
	if (rval) {
		device_printf(dev, "get max TX packets failed; "
		    "status: 0x%0X\n", rval);
		goto fail;
	}

	if (!NDIS_SERIALIZED(sc->ndis_block))
		sc->ndis_maxpkts = NDIS_TXPKTS;

	/* Enforce some sanity, just in case. */
	if (sc->ndis_maxpkts == 0)
		sc->ndis_maxpkts = 1;

	sc->ndis_txarray = malloc(sizeof(ndis_packet *) *
	    sc->ndis_maxpkts, M_NDIS_DEV, M_NOWAIT|M_ZERO);
	if (sc->ndis_txarray == NULL) {
		device_printf(dev, "failed to allocate TX array\n");
		goto fail;
	}

	/* Allocate a pool of ndis_packets for TX encapsulation. */
	NdisAllocatePacketPool(&rval, &sc->ndis_txpool, sc->ndis_maxpkts,
	    PROTOCOL_RESERVED_SIZE_IN_PACKET);
	if (rval) {
		sc->ndis_txpool = NULL;
		device_printf(dev, "failed to allocate TX packet pool\n");
		goto fail;
	}
	sc->ndis_txpending = sc->ndis_maxpkts;

	/* If the NDIS module requested scatter/gather, init maps. */
	if (sc->ndis_sc) {
		rval = ndis_init_dma(sc);
		if (rval) {
			device_printf(dev, "failed to init maps\n");
			goto fail;
		}
	}

	rval = ndis_get_physical_medium(sc, &sc->ndis_physical_medium);
	if (rval) {
		device_printf(dev, "failed to get physical medium; "
		    "status: 0x%0X", rval);
		goto fail;
	}

	if (sc->ndis_physical_medium == NDIS_PHYSICAL_MEDIUM_WIRELESS_LAN)
		sc->ndis_80211 = 1;
	if (sc->ndis_80211)
		ifp = if_alloc(IFT_IEEE80211);
	else
		ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		device_printf(dev, "failed to if_alloc()\n");
		goto fail;
	}
	sc->ndis_ifp = ifp;
	ifp->if_softc = sc;

	ndis_probe_task_offload(sc);

	if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = ndis_ioctl;
	ifp->if_start = ndis_start;
	ifp->if_init = ndis_init;
	ifp->if_baudrate = 10000000;
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);
	ifp->if_snd.ifq_drv_maxlen = IFQ_MAXLEN;
	IFQ_SET_READY(&ifp->if_snd);
	ifp->if_capenable = ifp->if_capabilities;
	ifp->if_hwassist = sc->ndis_hwassist;

	/* Do media setup */
	if (sc->ndis_80211) {
		struct ieee80211com *ic = ifp->if_l2com;
		ndis_80211_rates_ex rates;
		struct ndis_80211_nettype_list *ntl;
		uint32_t arg;

		callout_init(&sc->ndis_scan_callout, CALLOUT_MPSAFE);

		ifp->if_ioctl = ndis_ioctl_80211;
		ic->ic_ifp = ifp;
		ic->ic_caps =
			IEEE80211_C_8023ENCAP |
			IEEE80211_C_STA |
			IEEE80211_C_IBSS;
		setbit(ic->ic_modecaps, IEEE80211_MODE_AUTO);

		if (!ndis_get_int(sc, OID_802_11_NUMBER_OF_ANTENNAS, &arg))
			device_printf(dev, "number of antennas: %d\n", arg);
		if (!ndis_get_int(sc, OID_802_11_RX_ANTENNA_SELECTED, &arg))
			device_printf(dev, "rx antenna: %d\n", arg);
		if (!ndis_get_int(sc, OID_802_11_TX_ANTENNA_SELECTED, &arg))
			device_printf(dev, "tx antenna: %d\n", arg);
		rval = ndis_get_info(sc,
		    OID_802_11_NETWORK_TYPES_SUPPORTED, NULL, 0, NULL, &len);
		if (!(rval == NDIS_STATUS_INVALID_LENGTH ||
		    rval == NDIS_STATUS_BUFFER_TOO_SHORT))
			goto nonettypes;
		ntl = malloc(len, M_NDIS_DEV, M_NOWAIT|M_ZERO);
		rval = ndis_get(sc,
		    OID_802_11_NETWORK_TYPES_SUPPORTED, ntl, len);
		if (rval) {
			DPRINTF("failed to get network types; "
			    "status: 0x%0X\n", rval);
			free(ntl, M_NDIS_DEV);
			rval = 0;
			goto nonettypes;
		}
		for (i = 0; i < ntl->ntl_items; i++) {
			mode = ndis_nettype_mode(ntl->ntl_type[i]);
			if (mode) {
				setbit(ic->ic_modecaps, mode);
				setbit(&bands, mode);
			}
		}
		free(ntl, M_NDIS_DEV);
nonettypes:
		/* Default to 11b channels if the card did not supply any */
		if (bands == 0) {
			setbit(ic->ic_modecaps, IEEE80211_MODE_11B);
			setbit(&bands, IEEE80211_MODE_11B);
		}
		memset(&rates, 0, sizeof(rates));
		rval = ndis_get_info(sc, OID_802_11_SUPPORTED_RATES,
		    rates, sizeof(rates), &len, NULL);
		if (rval)
			DPRINTF("failed to get rates; "
			    "status: 0x%0X\n", rval);
		/*
		 * Since the supported rates only up to 8 can be supported,
		 * if this is not 802.11b we're just going to be faking it
		 * all up to heck.
		 */
#define	TESTSETRATE(x, y)						\
	do {								\
		int i;							\
		for (i = 0; i < ic->ic_sup_rates[x].rs_nrates; i++) {	\
			if (ic->ic_sup_rates[x].rs_rates[i] == (y))	\
				break;					\
		}							\
		if (i == ic->ic_sup_rates[x].rs_nrates) {		\
			ic->ic_sup_rates[x].rs_rates[i] = (y);		\
			ic->ic_sup_rates[x].rs_nrates++;		\
		}							\
	} while (0)

#define	SETRATE(x, y)							\
	ic->ic_sup_rates[x].rs_rates[ic->ic_sup_rates[x].rs_nrates] = (y)
#define	INCRATE(x)							\
	ic->ic_sup_rates[x].rs_nrates++

		if (isset(ic->ic_modecaps, IEEE80211_MODE_11A))
			ic->ic_sup_rates[IEEE80211_MODE_11A].rs_nrates = 0;
		if (isset(ic->ic_modecaps, IEEE80211_MODE_11B))
			ic->ic_sup_rates[IEEE80211_MODE_11B].rs_nrates = 0;
		if (isset(ic->ic_modecaps, IEEE80211_MODE_11G))
			ic->ic_sup_rates[IEEE80211_MODE_11G].rs_nrates = 0;
		for (i = 0; i < len; i++) {
			switch (rates[i] & IEEE80211_RATE_VAL) {
			case 2:
			case 4:
			case 11:
			case 10:
			case 22:
				if (isclr(ic->ic_modecaps, IEEE80211_MODE_11B)) {
					/* Lazy-init 802.11b. */
					setbit(ic->ic_modecaps,
					    IEEE80211_MODE_11B);
					ic->ic_sup_rates[IEEE80211_MODE_11B].
					    rs_nrates = 0;
				}
				SETRATE(IEEE80211_MODE_11B, rates[i]);
				INCRATE(IEEE80211_MODE_11B);
				break;
			default:
				if (isset(ic->ic_modecaps, IEEE80211_MODE_11A)) {
					SETRATE(IEEE80211_MODE_11A, rates[i]);
					INCRATE(IEEE80211_MODE_11A);
				}
				if (isset(ic->ic_modecaps, IEEE80211_MODE_11G)) {
					SETRATE(IEEE80211_MODE_11G, rates[i]);
					INCRATE(IEEE80211_MODE_11G);
				}
				break;
			}
		}

		/*
		 * If the hardware supports 802.11g, it most
		 * likely supports 802.11b and all of the
		 * 802.11b and 802.11g speeds, so maybe we can
		 * just cheat here.  Just how in the heck do
		 * we detect turbo modes, though?
		 */
		if (isset(ic->ic_modecaps, IEEE80211_MODE_11B)) {
			TESTSETRATE(IEEE80211_MODE_11B,
			    IEEE80211_RATE_BASIC|2);
			TESTSETRATE(IEEE80211_MODE_11B,
			    IEEE80211_RATE_BASIC|4);
			TESTSETRATE(IEEE80211_MODE_11B,
			    IEEE80211_RATE_BASIC|11);
			TESTSETRATE(IEEE80211_MODE_11B,
			    IEEE80211_RATE_BASIC|22);
		}
		if (isset(ic->ic_modecaps, IEEE80211_MODE_11G)) {
			TESTSETRATE(IEEE80211_MODE_11G, 48);
			TESTSETRATE(IEEE80211_MODE_11G, 72);
			TESTSETRATE(IEEE80211_MODE_11G, 96);
			TESTSETRATE(IEEE80211_MODE_11G, 108);
		}
		if (isset(ic->ic_modecaps, IEEE80211_MODE_11A)) {
			TESTSETRATE(IEEE80211_MODE_11A, 48);
			TESTSETRATE(IEEE80211_MODE_11A, 72);
			TESTSETRATE(IEEE80211_MODE_11A, 96);
			TESTSETRATE(IEEE80211_MODE_11A, 108);
		}
#undef SETRATE
#undef INCRATE
		ieee80211_init_channels(ic, NULL, &bands);

		/*
		 * To test for WPA support, we need to see if we can
		 * set AUTHENTICATION_MODE to WPA and read it back
		 * successfully.
		 */
		if (!ndis_set_authmode(sc, NDIS_802_11_AUTHMODE_WPA)) {
			if (!ndis_get_int(sc,
			    OID_802_11_AUTHENTICATION_MODE, &arg))
				if (arg == NDIS_802_11_AUTHMODE_WPA)
					ic->ic_caps |= IEEE80211_C_WPA1;
		}
		if (!ndis_set_authmode(sc, NDIS_802_11_AUTHMODE_WPA2)) {
			if (!ndis_get_int(sc,
			    OID_802_11_AUTHENTICATION_MODE, &arg))
				if (arg == NDIS_802_11_AUTHMODE_WPA2)
					ic->ic_caps |= IEEE80211_C_WPA2;
		}

		/*
		 * To test for supported ciphers, we set each
		 * available encryption type in descending order.
		 * If ENC3 works, then we have WEP, TKIP and AES.
		 * If only ENC2 works, then we have WEP and TKIP.
		 * If only ENC1 works, then we have just WEP.
		 */
		if (!ndis_set_encryption(sc, NDIS_802_11_WEPSTAT_ENC3ENABLED)) {
			ic->ic_cryptocaps |= IEEE80211_CRYPTO_WEP
					  |  IEEE80211_CRYPTO_TKIP
					  |  IEEE80211_CRYPTO_AES_CCM;
			goto got_crypto;
		}
		if (!ndis_set_encryption(sc, NDIS_802_11_WEPSTAT_ENC2ENABLED)) {
			ic->ic_cryptocaps |= IEEE80211_CRYPTO_WEP
					  |  IEEE80211_CRYPTO_TKIP;
			goto got_crypto;
		}
		if (!ndis_set_encryption(sc, NDIS_802_11_WEPSTAT_ENC1ENABLED))
			ic->ic_cryptocaps |= IEEE80211_CRYPTO_WEP;
got_crypto:
		if (!ndis_get_int(sc, OID_802_11_FRAGMENTATION_THRESHOLD, &arg))
			ic->ic_caps |= IEEE80211_C_TXFRAG;
		if (!ndis_get_int(sc, OID_802_11_TX_POWER_LEVEL, &arg))
			ic->ic_caps |= IEEE80211_C_TXPMGT;
		if (!ndis_get_int(sc, OID_802_11_POWER_MODE, &arg))
			ic->ic_caps |= IEEE80211_C_PMGT;

		ieee80211_ifattach(ic, eaddr);
		ic->ic_send_mgmt = ndis_send_mgmt;
		ic->ic_raw_xmit = ndis_raw_xmit;
		ic->ic_scan_start = ndis_scan_start;
		ic->ic_scan_end = ndis_scan_end;
		ic->ic_set_channel = ndis_set_channel;
		ic->ic_scan_curchan = ndis_scan_curchan;
		ic->ic_scan_mindwell = ndis_scan_mindwell;
		ic->ic_vap_create = ndis_vap_create;
		ic->ic_vap_delete = ndis_vap_delete;
		ic->ic_update_mcast = ndis_update_mcast;
		ic->ic_update_promisc = ndis_update_promisc;

		if (bootverbose)
			ieee80211_announce(ic);
	} else {
		ifmedia_init(&sc->ifmedia, IFM_IMASK, ndis_ifmedia_upd,
		    ndis_ifmedia_sts);
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_10_T, 0, NULL);
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_10_T|IFM_FDX, 0, NULL);
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_100_TX, 0, NULL);
		ifmedia_add(&sc->ifmedia,
		    IFM_ETHER|IFM_100_TX|IFM_FDX, 0, NULL);
		ifmedia_add(&sc->ifmedia, IFM_ETHER|IFM_AUTO, 0, NULL);
		ifmedia_set(&sc->ifmedia, IFM_ETHER|IFM_AUTO);
		ether_ifattach(ifp, eaddr);
	}
	ndis_stop(sc);
	return (0);
fail:
	ndis_detach(dev);
	return (ENXIO);
}

static struct ieee80211vap *
ndis_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ], int unit,
    int opmode, int flags, const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ndis_softc *sc = ic->ic_ifp->if_softc;
	struct ndis_vap *nvp;
	struct ieee80211vap *vap;

	if (!TAILQ_EMPTY(&ic->ic_vaps))		/* only one at a time */
		return (NULL);

	if (ndis_set_infra(sc, opmode))
		return (NULL);

	nvp = (struct ndis_vap *) malloc(sizeof(struct ndis_vap),
	    M_80211_VAP, M_NOWAIT|M_ZERO);
	if (nvp == NULL)
		return (NULL);
	vap = &nvp->vap;
	ieee80211_vap_setup(ic, vap, name, unit, opmode, flags, bssid, mac);

	/* Override with driver methods */
	nvp->newstate = vap->iv_newstate;
	vap->iv_newstate = ndis_newstate;
	vap->iv_reset = ndis_reset_vap;

	/* Complete setup */
	ieee80211_vap_attach(vap, ieee80211_media_change, ndis_media_status);
	ic->ic_opmode = opmode;

	/* Install key handing routines */
	vap->iv_key_set = ndis_key_set;
	vap->iv_key_delete = ndis_key_delete;
	return (vap);
}

static void
ndis_vap_delete(struct ieee80211vap *vap)
{
	struct ndis_vap *nvp = NDIS_VAP(vap);
	struct ndis_softc *sc = vap->iv_ic->ic_ifp->if_softc;

	ndis_stop(sc);
	ieee80211_vap_detach(vap);
	free(nvp, M_80211_VAP);
}

/*
 * Shutdown hardware and free up resources. This can be called any
 * time after the mutex has been initialized. It is called in both
 * the error case in attach and the normal detach case so it needs
 * to be careful about only freeing resources that have actually been
 * allocated.
 */
int
ndis_detach(device_t dev)
{
	struct ndis_softc *sc;

	sc = device_get_softc(dev);
	if (device_is_attached(dev)) {
		if (sc->ndis_ifp != NULL) {
			ndis_stop(sc);
			if (sc->ndis_80211)
				ieee80211_ifdetach(sc->ndis_ifp->if_l2com);
			else
				ether_ifdetach(sc->ndis_ifp);
		}
	}
	if (NDIS_INITIALIZED(sc))
		ndis_halt_nic(sc);

	if (sc->ndis_tickitem != NULL)
		IoFreeWorkItem(sc->ndis_tickitem);
	if (sc->ndis_startitem != NULL)
		IoFreeWorkItem(sc->ndis_startitem);
	if (sc->ndis_resetitem != NULL)
		IoFreeWorkItem(sc->ndis_resetitem);
	if (sc->ndis_inputitem != NULL)
		IoFreeWorkItem(sc->ndis_inputitem);
	if (sc->ndisusb_xferdoneitem != NULL)
		IoFreeWorkItem(sc->ndisusb_xferdoneitem);
	if (sc->ndisusb_taskitem != NULL)
		IoFreeWorkItem(sc->ndisusb_taskitem);

	ndis_unload_driver(sc);
	bus_generic_detach(dev);

	if (sc->ndis_irq != NULL)
		bus_release_resource(dev, SYS_RES_IRQ, 0, sc->ndis_irq);
	if (sc->ndis_res_io != NULL)
		bus_release_resource(dev, SYS_RES_IOPORT,
		    sc->ndis_io_rid, sc->ndis_res_io);
	if (sc->ndis_res_mem != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    sc->ndis_mem_rid, sc->ndis_res_mem);
	if (sc->ndis_res_altmem != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
		    sc->ndis_altmem_rid, sc->ndis_res_altmem);
	if (sc->ndis_ifp != NULL)
		if_free(sc->ndis_ifp);
	if (sc->ndis_iftype == PCMCIABus)
		ndis_free_amem(sc);
	if (sc->ndis_sc)
		ndis_destroy_dma(sc);
	if (sc->ndis_txarray != NULL)
		free(sc->ndis_txarray, M_NDIS_DEV);
	if (sc->ndis_80211 == 0)
		ifmedia_removeall(&sc->ifmedia);
	if (sc->ndis_txpool != NULL)
		NdisFreePacketPool(sc->ndis_txpool);
	if (sc->ndis_oids != NULL)
		free(sc->ndis_oids, M_NDIS_DEV);
	if (sc->ndis_iftype == PCIBus) {
		windrv_destroy_pdo(windrv_lookup(0, "PCI Bus"), dev);
		bus_dma_tag_destroy(sc->ndis_parent_tag);
	} else if (sc->ndis_iftype == PCMCIABus) {
		windrv_destroy_pdo(windrv_lookup(0, "PCCARD Bus"), dev);
	} else if (sc->ndis_iftype == PNPBus) {
		windrv_destroy_pdo(windrv_lookup(0, "USB Bus"), dev);
	}
	ndis_flush_sysctls(sc);
	mtx_destroy(&sc->ndis_mtx);
	return (0);
}

int
ndis_suspend(device_t dev)
{
	struct ndis_softc *sc;

	sc = device_get_softc(dev);
	if (NDIS_INITIALIZED(sc))
		ndis_stop(sc);
	return (0);
}

int
ndis_resume(device_t dev)
{
	struct ndis_softc *sc;

	sc = device_get_softc(dev);
	if (NDIS_INITIALIZED(sc))
		ndis_init(sc);
	return (0);
}

/*
 * The following bunch of routines are here to support drivers that
 * use the NdisMEthIndicateReceive()/MiniportTransferData() mechanism.
 * The NdisMEthIndicateReceive() handler runs at DISPATCH_LEVEL for
 * serialized miniports, or IRQL <= DISPATCH_LEVEL for deserialized
 * miniports.
 */
static void
ndis_rxeof_eth(ndis_handle adapter, ndis_handle ctx, char *addr, void *hdr,
    uint32_t hdrlen, void *lookahead, uint32_t lookaheadlen, uint32_t pktlen)
{
	ndis_miniport_block *block = adapter;
	uint8_t irql = 0;
	uint32_t status;
	ndis_buffer *b;
	ndis_packet *p;
	struct mbuf *m;
	ndis_ethpriv *priv;

	m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL) {
		NdisFreePacket(p);
		return;
	}

	/* Save the data provided to us so far. */
	m->m_len = lookaheadlen + hdrlen;
	m->m_pkthdr.len = pktlen + hdrlen;
	m->m_next = NULL;
	m_copyback(m, 0, hdrlen, hdr);
	m_copyback(m, hdrlen, lookaheadlen, lookahead);

	/* Now create a fake NDIS_PACKET to hold the data */
	NdisAllocatePacket(&status, &p, block->rxpool);
	if (status != NDIS_STATUS_SUCCESS) {
		m_freem(m);
		return;
	}

	p->np_m0 = m;
	b = IoAllocateMdl(m->m_data, m->m_pkthdr.len, FALSE, FALSE, NULL);
	if (b == NULL) {
		NdisFreePacket(p);
		m_freem(m);
		return;
	}

	p->np_private.head = p->np_private.tail = b;
	p->np_private.totlen = m->m_pkthdr.len;

	/* Save the packet RX context somewhere. */
	priv = (ndis_ethpriv *)&p->np_protocolreserved;
	priv->nep_ctx = ctx;

	if (!NDIS_SERIALIZED(block))
		KeAcquireSpinLock(&block->lock, &irql);

	InsertTailList((&block->packet_list), (&p->np_list));

	if (!NDIS_SERIALIZED(block))
		KeReleaseSpinLock(&block->lock, irql);
}

/*
 * NdisMEthIndicateReceiveComplete() handler, runs at DISPATCH_LEVEL for
 * serialized miniports, or IRQL <= DISPATCH_LEVEL for deserialized miniports.
 */
static void
ndis_rxeof_done(ndis_handle adapter)
{
	ndis_miniport_block *block = adapter;
	struct ndis_softc *sc;

	sc = device_get_softc(block->physdeviceobj->devext);
	if (!NDIS_INITIALIZED(sc))
		return;

	/* Schedule transfer/RX of queued packets. */
	KeInsertQueueDpc(&sc->ndis_rxdpc, NULL, NULL);
}

/*
 * MiniportTransferData() handler, runs at DISPATCH_LEVEL.
 */
static void
ndis_rxeof_xfr(kdpc *dpc, ndis_handle adapter, void *sysarg1, void *sysarg2)
{
	ndis_miniport_block *block = adapter;
	struct ndis_softc *sc;
	ndis_packet *p;
	list_entry *l;
	ndis_status status;
	ndis_ethpriv *priv;
	struct ifnet *ifp;
	struct mbuf *m;

	sc = device_get_softc(block->physdeviceobj->devext);
	if (!NDIS_INITIALIZED(sc))
		return;
	ifp = sc->ndis_ifp;

	KeAcquireSpinLockAtDpcLevel(&block->lock);

	l = block->packet_list.nle_flink;
	while (!IsListEmpty(&block->packet_list)) {
		l = RemoveHeadList((&block->packet_list));
		p = CONTAINING_RECORD(l, ndis_packet, np_list);
		InitializeListHead((&p->np_list));

		priv = (ndis_ethpriv *)&p->np_protocolreserved;
		m = p->np_m0;
		p->np_softc = sc;
		p->np_m0 = NULL;

		KeReleaseSpinLockFromDpcLevel(&block->lock);
		status = MSCALL6(sc->ndis_chars->transfer_data_func,
		    p, &p->np_private.totlen, block, priv->nep_ctx,
		    m->m_len, m->m_pkthdr.len - m->m_len);
		KeAcquireSpinLockAtDpcLevel(&block->lock);

		/*
		 * If status is NDIS_STATUS_PENDING, do nothing and wait
		 * for a callback to the ndis_rxeof_xfr_done() handler.
		 */
		m->m_len = m->m_pkthdr.len;
		m->m_pkthdr.rcvif = ifp;

		if (status == NDIS_STATUS_SUCCESS) {
			IoFreeMdl(p->np_private.head);
			NdisFreePacket(p);
			KeAcquireSpinLockAtDpcLevel(&sc->ndis_rxlock);
			_IF_ENQUEUE(&sc->ndis_rxqueue, m);
			KeReleaseSpinLockFromDpcLevel(&sc->ndis_rxlock);
			IoQueueWorkItem(sc->ndis_inputitem,
			    (io_workitem_func)ndis_inputtask_wrap,
			    WORKQUEUE_CRITICAL, ifp);
		}

		if (status == NDIS_STATUS_FAILURE)
			m_freem(m);

		/* Advance to next packet */
		l = block->packet_list.nle_flink;
	}

	KeReleaseSpinLockFromDpcLevel(&block->lock);
}

/*
 * NdisMTransferDataComplete() handler, runs at DISPATCH_LEVEL.
 */
static void
ndis_rxeof_xfr_done(ndis_handle adapter, ndis_packet *packet,
    uint32_t status, uint32_t len)
{
	ndis_miniport_block *block = adapter;
	struct ndis_softc *sc;
	struct ifnet *ifp;
	struct mbuf *m;

	sc = device_get_softc(block->physdeviceobj->devext);
	if (!NDIS_INITIALIZED(sc))
		return;
	ifp = sc->ndis_ifp;

	m = packet->np_m0;
	IoFreeMdl(packet->np_private.head);
	NdisFreePacket(packet);

	if (status != NDIS_STATUS_SUCCESS) {
		m_freem(m);
		return;
	}

	m->m_len = m->m_pkthdr.len;
	m->m_pkthdr.rcvif = ifp;
	KeAcquireSpinLockAtDpcLevel(&sc->ndis_rxlock);
	_IF_ENQUEUE(&sc->ndis_rxqueue, m);
	KeReleaseSpinLockFromDpcLevel(&sc->ndis_rxlock);
	IoQueueWorkItem(sc->ndis_inputitem,
	    (io_workitem_func)ndis_inputtask_wrap, WORKQUEUE_CRITICAL, ifp);
}

/*
 * A frame has been uploaded: pass the resulting mbuf chain up to
 * the higher level protocols.
 *
 * When handling received NDIS packets, the 'status' field in the out-of-band
 * portion of the ndis_packet has special meaning. In the most common case,
 * the underlying NDIS driver will set this field to NDIS_STATUS_SUCCESS,
 * which indicates that it's ok for us to take posession of it. We then change
 * the status field to NDIS_STATUS_PENDING to tell the driver that we now own
 * the packet, and that we will return it at some point in the future via the
 * return packet handler.
 *
 * If the driver hands us a packet with a status of NDIS_STATUS_RESOURCES,
 * this means the driver is running out of packet/buffer resources and wants
 * to maintain ownership of the packet. In this case, we have to copy the
 * packet data into local storage and let the driver keep the packet.
 */
static void
ndis_rxeof(ndis_handle adapter, ndis_packet **packets, uint32_t pktcnt)
{
	ndis_miniport_block *block = adapter;
	struct ndis_softc *sc;
	ndis_packet *p;
	uint32_t s;
	ndis_tcpip_csum *csum;
	struct ifnet *ifp;
	struct mbuf *m0, *m;
	int i;

	sc = device_get_softc(block->physdeviceobj->devext);
	if (!NDIS_INITIALIZED(sc))
		return;
	ifp = sc->ndis_ifp;

	/*
	 * There's a slim chance the driver may indicate some packets
	 * before we're completely ready to handle them. If we detect this,
	 * we need to return them to the miniport and ignore them.
	 */
	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		for (i = 0; i < pktcnt; i++) {
			p = packets[i];
			if (p->np_oob.npo_status == NDIS_STATUS_SUCCESS) {
				p->np_refcnt++;
				ndis_return_packet(block, p);
			}
		}
		return;
	}

	for (i = 0; i < pktcnt; i++) {
		p = packets[i];
		/* Stash the softc here so ptom can use it. */
		p->np_softc = sc;
		if (ndis_ptom(&m0, p)) {
			device_printf(sc->ndis_dev, "ptom failed\n");
			if (p->np_oob.npo_status == NDIS_STATUS_SUCCESS)
				ndis_return_packet(block, p);
		} else {
#ifdef notdef
			if (p->np_oob.npo_status ==
			    NDIS_STATUS_INSUFFICIENT_RESOURCES) {
				m = m_dup(m0, M_DONTWAIT);
				/*
				 * NOTE: we want to destroy the mbuf here, but
				 * we don't actually want to return it to the
				 * driver via the return packet handler. By
				 * bumping np_refcnt, we can prevent the
				 * ndis_return_packet() routine from actually
				 * doing anything.
				 */
				p->np_refcnt++;
				m_freem(m0);
				if (m == NULL)
					ifp->if_ierrors++;
				else
					m0 = m;
			} else
				p->np_oob.npo_status = NDIS_STATUS_PENDING;
#endif
			m = m_dup(m0, M_DONTWAIT);
			if (p->np_oob.npo_status ==
			    NDIS_STATUS_INSUFFICIENT_RESOURCES)
				p->np_refcnt++;
			else
				p->np_oob.npo_status = NDIS_STATUS_PENDING;
			m_freem(m0);
			if (m == NULL) {
				ifp->if_ierrors++;
				continue;
			}
			m0 = m;
			m0->m_pkthdr.rcvif = ifp;

			/* Deal with checksum offload. */
			if (ifp->if_capenable & IFCAP_RXCSUM &&
			    p->np_ext.info[NDIS_TCPIPCSUM_INFO] != NULL) {
				s = (uintptr_t)
				    p->np_ext.info[NDIS_TCPIPCSUM_INFO];
				csum = (ndis_tcpip_csum *)&s;
				if (csum->u.rxflags & NDIS_RXCSUM_IP_PASSED)
					m0->m_pkthdr.csum_flags |=
					    CSUM_IP_CHECKED|CSUM_IP_VALID;
				if (csum->u.rxflags &
				    (NDIS_RXCSUM_TCP_PASSED |
				    NDIS_RXCSUM_UDP_PASSED)) {
					m0->m_pkthdr.csum_flags |=
					    CSUM_DATA_VALID|CSUM_PSEUDO_HDR;
					m0->m_pkthdr.csum_data = 0xFFFF;
				}
			}

			KeAcquireSpinLockAtDpcLevel(&sc->ndis_rxlock);
			_IF_ENQUEUE(&sc->ndis_rxqueue, m0);
			KeReleaseSpinLockFromDpcLevel(&sc->ndis_rxlock);
			IoQueueWorkItem(sc->ndis_inputitem,
			    (io_workitem_func)ndis_inputtask_wrap,
			    WORKQUEUE_CRITICAL, ifp);
		}
	}
}

/*
 * This routine is run at PASSIVE_LEVEL. We use this routine to pass
 * packets into the stack in order to avoid calling (*ifp->if_input)()
 * with any locks held (at DISPATCH_LEVEL, we'll be holding the
 * 'dispatch level' per-cpu sleep lock).
 */
static void
ndis_inputtask(device_object *dobj, void *arg)
{
	struct ifnet *ifp = arg;
	struct ndis_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = ifp->if_l2com;
	struct ieee80211vap *vap;
	struct mbuf *m;
	uint8_t irql;

	vap = TAILQ_FIRST(&ic->ic_vaps);

	KeAcquireSpinLock(&sc->ndis_rxlock, &irql);
	for (;;) {
		_IF_DEQUEUE(&sc->ndis_rxqueue, m);
		if (m == NULL)
			break;
		KeReleaseSpinLock(&sc->ndis_rxlock, irql);
		if (vap != NULL)
			vap->iv_deliver_data(vap, vap->iv_bss, m);
		else
			(*ifp->if_input)(ifp, m);
		KeAcquireSpinLock(&sc->ndis_rxlock, &irql);
	}
	KeReleaseSpinLock(&sc->ndis_rxlock, irql);
}

/*
 * A frame was downloaded to the chip. It's safe for us to clean up
 * the list buffers.
 */
static void
ndis_txeof(ndis_handle adapter, ndis_packet *packet, ndis_status status)
{
	ndis_miniport_block *block = adapter;
	struct ndis_softc *sc;
	struct ifnet *ifp;
	int idx;
	struct mbuf *m;

	sc = device_get_softc(block->physdeviceobj->devext);
	if (!NDIS_INITIALIZED(sc))
		return;
	ifp = sc->ndis_ifp;

	m = packet->np_m0;
	idx = packet->np_txidx;
	if (sc->ndis_sc)
		bus_dmamap_unload(sc->ndis_ttag, sc->ndis_tmaps[idx]);

	ndis_free_packet(packet);
	m_freem(m);

	NDIS_LOCK(sc);
	sc->ndis_txarray[idx] = NULL;
	sc->ndis_txpending++;

	if (status == NDIS_STATUS_SUCCESS)
		ifp->if_opackets++;
	else
		ifp->if_oerrors++;

	sc->ndis_tx_timer = 0;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
	NDIS_UNLOCK(sc);

	IoQueueWorkItem(sc->ndis_startitem,
	    (io_workitem_func)ndis_starttask_wrap, WORKQUEUE_CRITICAL, ifp);
}

static void
ndis_linksts(ndis_handle adapter, ndis_status status, void *buf, uint32_t len)
{
	ndis_miniport_block *block = adapter;
	struct ndis_softc *sc;
	struct ieee80211com *ic;
	struct ieee80211vap *vap;

	sc = device_get_softc(block->physdeviceobj->devext);
	if (!NDIS_INITIALIZED(sc))
		return;
	if ((sc->ndis_ifp->if_drv_flags & IFF_DRV_RUNNING) == 0)
		return;

	ic = sc->ndis_ifp->if_l2com;
	vap = TAILQ_FIRST(&ic->ic_vaps);

	if (status == NDIS_STATUS_MEDIA_CONNECT) {
		if (vap != NULL)
			ieee80211_new_state(vap, IEEE80211_S_RUN, -1);
		if_link_state_change(sc->ndis_ifp, LINK_STATE_UP);
	} else if (status == NDIS_STATUS_MEDIA_DISCONNECT) {
		if (vap != NULL)
			ieee80211_new_state(vap, IEEE80211_S_SCAN, 0);
		if_link_state_change(sc->ndis_ifp, LINK_STATE_DOWN);
	} else if (status == NDIS_STATUS_MEDIA_SPECIFIC_INDICATION) {
		if (buf != NULL) {
			ndis_80211_status_indication *nsi;

			nsi = buf;
			switch (nsi->nsi_type) {
			case NDIS_802_11_STATUSTYPE_AUTHENTICATION:
				break;
			case NDIS_802_11_STATUSTYPE_MEDIA_STREAM_MODE:
				break;
			case NDIS_802_11_STATUSTYPE_PMKID_CANDIDATE_LIST:
				break;
			case NDIS_802_11_STATUSTYPE_RADIO_STATE:
				break;
			default:
				break;
			}
		}
	}

	/* Event list is all full up, drop this one. */
	if (sc->ndis_evt[sc->ndis_evtpidx].ne_sts)
		return;
	/* Cache the event. */
	if (len) {
		sc->ndis_evt[sc->ndis_evtpidx].ne_buf =
		    malloc(len, M_NDIS_DEV, M_NOWAIT|M_ZERO);
		if (sc->ndis_evt[sc->ndis_evtpidx].ne_buf == NULL)
			return;
		memcpy(sc->ndis_evt[sc->ndis_evtpidx].ne_buf, buf, len);
	}
	sc->ndis_evt[sc->ndis_evtpidx].ne_sts = status;
	sc->ndis_evt[sc->ndis_evtpidx].ne_len = len;
	NDIS_EVTINC(sc->ndis_evtpidx);
}

static void
ndis_linksts_done(ndis_handle adapter)
{
	ndis_miniport_block *block = adapter;
	struct ndis_softc *sc;

	sc = device_get_softc(block->physdeviceobj->devext);
	if (!NDIS_INITIALIZED(sc))
		return;

	if (sc->ndis_ifp->if_link_state == LINK_STATE_UP) {
		IoQueueWorkItem(sc->ndis_tickitem,
		    (io_workitem_func)ndis_ticktask_wrap,
		    WORKQUEUE_CRITICAL, sc);
		IoQueueWorkItem(sc->ndis_startitem,
		    (io_workitem_func)ndis_starttask_wrap,
		    WORKQUEUE_CRITICAL, sc->ndis_ifp);
	} else if (sc->ndis_ifp->if_link_state == LINK_STATE_DOWN) {
		IoQueueWorkItem(sc->ndis_tickitem,
		    (io_workitem_func)ndis_ticktask_wrap,
		    WORKQUEUE_CRITICAL, sc);
	}
}

static void
ndis_tick(void *xsc)
{
	struct ndis_softc *sc = xsc;

	if (sc->ndis_hang_timer && --sc->ndis_hang_timer == 0) {
		IoQueueWorkItem(sc->ndis_tickitem,
		    (io_workitem_func)ndis_ticktask_wrap,
		    WORKQUEUE_CRITICAL, sc);
		sc->ndis_hang_timer = sc->ndis_block->check_for_hang_secs;
	}
	if (sc->ndis_tx_timer && --sc->ndis_tx_timer == 0) {
		sc->ndis_ifp->if_oerrors++;
		device_printf(sc->ndis_dev, "watchdog timeout\n");
		IoQueueWorkItem(sc->ndis_resetitem,
		    (io_workitem_func)ndis_resettask_wrap,
		    WORKQUEUE_CRITICAL, sc);
		IoQueueWorkItem(sc->ndis_startitem,
		    (io_workitem_func)ndis_starttask_wrap,
		    WORKQUEUE_CRITICAL, sc->ndis_ifp);
	}
	callout_reset(&sc->ndis_stat_callout, hz, ndis_tick, sc);
}

static void
ndis_ticktask(device_object *d, void *arg)
{
	struct ndis_softc *sc = arg;

	if (!NDIS_INITIALIZED(sc))
		return;
	if (ndis_check_for_hang_nic(sc))
		ndis_reset_nic(sc);
}

static void
ndis_map_sclist(void *arg, bus_dma_segment_t *segs, int nseg,
    bus_size_t mapsize, int error)
{
	struct ndis_sc_list *sclist;
	int i;

	if (error || arg == NULL)
		return;

	sclist = arg;
	sclist->frags = nseg;

	for (i = 0; i < nseg; i++) {
		sclist->elements[i].addr.np_quad = segs[i].ds_addr;
		sclist->elements[i].len = segs[i].ds_len;
	}
}

static int
ndis_send_mgmt(struct ieee80211_node *ni, int type, int arg)
{
	/* no support; just discard */
	return (0);
}

static int
ndis_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *params)
{
	/* no support; just discard */
	m_freem(m);
	ieee80211_free_node(ni);
	return (0);
}

static void
ndis_update_mcast(struct ifnet *ifp)
{
	struct ndis_softc *sc = ifp->if_softc;

	ndis_set_multi(sc);
}

static void
ndis_update_promisc(struct ifnet *ifp)
{
	/* not supported */
}

static void
ndis_starttask(device_object *d, void *arg)
{
	struct ifnet *ifp = arg;

	if (!IFQ_DRV_IS_EMPTY(&ifp->if_snd))
		ndis_start(ifp);
}

/*
 * Main transmit routine. To make NDIS drivers happy, we need to transform
 * mbuf chains into NDIS packets and feed them to the send packet routines.
 * Most drivers allow you to send several packets at once (up to the maxpkts
 * limit). Unfortunately, rather that accepting them in the form of a linked
 * list, they expect a contiguous array of pointers to packets.
 *
 * For those drivers which use the NDIS scatter/gather DMA mechanism,
 * we need to perform busdma work here. Those that use map registers
 * will do the mapping themselves on a buffer by buffer basis.
 */
static void
ndis_start(struct ifnet *ifp)
{
	struct ndis_softc *sc = ifp->if_softc;
	struct mbuf *m = NULL;
	ndis_packet **p0 = NULL, *p = NULL;
	ndis_tcpip_csum *csum;
	int pcnt = 0, status;

	if (ifp->if_link_state != LINK_STATE_UP ||
	    (ifp->if_drv_flags & IFF_DRV_OACTIVE))
		return;

	NDIS_LOCK(sc);
	p0 = &sc->ndis_txarray[sc->ndis_txidx];

	while (sc->ndis_txpending) {
		IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL)
			break;

		NdisAllocatePacket(&status,
		    &sc->ndis_txarray[sc->ndis_txidx], sc->ndis_txpool);
		if (status != NDIS_STATUS_SUCCESS)
			break;

		if (ndis_mtop(m, &sc->ndis_txarray[sc->ndis_txidx])) {
			IFQ_DRV_PREPEND(&ifp->if_snd, m);
			NDIS_UNLOCK(sc);
			return;
		}

		/*
		 * Save pointer to original mbuf so we can free it later.
		 */
		p = sc->ndis_txarray[sc->ndis_txidx];
		p->np_txidx = sc->ndis_txidx;
		p->np_m0 = m;
		p->np_oob.npo_status = NDIS_STATUS_PENDING;

		/*
		 * Do scatter/gather processing, if driver requested it.
		 */
		if (sc->ndis_sc) {
			bus_dmamap_load_mbuf(sc->ndis_ttag,
			    sc->ndis_tmaps[sc->ndis_txidx], m,
			    ndis_map_sclist, &p->np_sclist, BUS_DMA_NOWAIT);
			bus_dmamap_sync(sc->ndis_ttag,
			    sc->ndis_tmaps[sc->ndis_txidx],
			    BUS_DMASYNC_PREREAD);
			p->np_ext.info[NDIS_SCLIST_INFO] = &p->np_sclist;
		}

		/* Handle checksum offload. */
		if (ifp->if_capenable & IFCAP_TXCSUM &&
		    m->m_pkthdr.csum_flags) {
			csum = (ndis_tcpip_csum *)
				&p->np_ext.info[NDIS_TCPIPCSUM_INFO];
			csum->u.txflags = NDIS_TXCSUM_DO_IPV4;
			if (m->m_pkthdr.csum_flags & CSUM_IP)
				csum->u.txflags |= NDIS_TXCSUM_DO_IP;
			if (m->m_pkthdr.csum_flags & CSUM_TCP)
				csum->u.txflags |= NDIS_TXCSUM_DO_TCP;
			if (m->m_pkthdr.csum_flags & CSUM_UDP)
				csum->u.txflags |= NDIS_TXCSUM_DO_UDP;
			p->np_private.flags = NDIS_PROTOCOL_ID_TCP_IP;
		}

		NDIS_INC(sc);
		sc->ndis_txpending--;

		pcnt++;

		/*
		 * If there's a BPF listener, bounce a copy of this frame
		 * to him.
		 */
		if (sc->ndis_80211 == 0)
			BPF_MTAP(ifp, m);

		/*
		 * The array that p0 points to must appear contiguous,
		 * so we must not wrap past the end of sc->ndis_txarray[].
		 * If it looks like we're about to wrap, break out here
		 * so the this batch of packets can be transmitted, then
		 * wait for txeof to ask us to send the rest.
		 */
		if (sc->ndis_txidx == 0)
			break;
	}

	if (pcnt == 0) {
		NDIS_UNLOCK(sc);
		return;
	}

	if (sc->ndis_txpending == 0)
		ifp->if_drv_flags |= IFF_DRV_OACTIVE;

	/*
	 * Set a timeout in case the chip goes out to lunch.
	 */
	sc->ndis_tx_timer = 5;

	NDIS_UNLOCK(sc);

	/*
	 * According to NDIS documentation, if a driver exports
	 * a MiniportSendPackets() routine, we prefer that over
	 * a MiniportSend() routine (which sends just a single packet).
	 */
	if (sc->ndis_chars->send_multi_func != NULL)
		ndis_send_packets(sc, p0, pcnt);
	else
		ndis_send_packet(sc, p);
}

static void
ndis_init(void *xsc)
{
	struct ndis_softc *sc = xsc;
	struct ifnet *ifp = sc->ndis_ifp;
	struct ieee80211com *ic = ifp->if_l2com;

	/* Program the packet filter */
	sc->ndis_filter = NDIS_PACKET_TYPE_DIRECTED;
	if (ifp->if_flags & IFF_BROADCAST)
		sc->ndis_filter |= NDIS_PACKET_TYPE_BROADCAST;
	if (ifp->if_flags & IFF_PROMISC)
		sc->ndis_filter |= NDIS_PACKET_TYPE_PROMISCUOUS;
	if (ndis_set_filter(sc, sc->ndis_filter) != 0)
		DPRINTF("set filter failed\n");

	/* Set lookahead */
	ndis_set_int(sc, OID_GEN_CURRENT_LOOKAHEAD, ifp->if_mtu);

	/* Program the multicast filter, if necessary */
	ndis_set_multi(sc);

	ndis_set_task_offload(sc);

	NDIS_LOCK(sc);
	sc->ndis_txidx = 0;
	sc->ndis_txpending = sc->ndis_maxpkts;
	if_link_state_change(sc->ndis_ifp, LINK_STATE_UNKNOWN);
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
	sc->ndis_tx_timer = 0;

	/*
	 * Some drivers don't set this value. The NDIS spec says
	 * the default check_for_hang timeout is "approximately 2
	 * seconds." We use 3 seconds, because it seems for some
	 * drivers, exactly 2 seconds is too fast.
	 */
	if (sc->ndis_block->check_for_hang_secs == 0)
		sc->ndis_block->check_for_hang_secs = 3;

	sc->ndis_hang_timer = sc->ndis_block->check_for_hang_secs;
	callout_reset(&sc->ndis_stat_callout, hz, ndis_tick, sc);
	NDIS_UNLOCK(sc);

	ndis_set_powerstate(sc, NDIS_DEVICE_STATE_D0);

	if (sc->ndis_80211)
		ieee80211_start_all(ic);	/* start all vap's */
}

/*
 * Set media options.
 */
static int
ndis_ifmedia_upd(struct ifnet *ifp)
{
	struct ndis_softc *sc = ifp->if_softc;

	if (NDIS_INITIALIZED(sc)) {
		ndis_stop(sc);
		ndis_init(sc);
	}
	return (0);
}

/*
 * Report current media status.
 */
static void
ndis_ifmedia_sts(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct ndis_softc *sc = ifp->if_softc;
	uint32_t media_info;
	ndis_media_state linkstate;

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (!NDIS_INITIALIZED(sc))
		return;

	ndis_get_int(sc, OID_GEN_MEDIA_CONNECT_STATUS, &linkstate);
	if (linkstate == NDIS_MEDIA_STATE_CONNECTED)
		ifmr->ifm_status |= IFM_ACTIVE;

	ndis_get_int(sc, OID_GEN_LINK_SPEED, &media_info);

	switch (media_info) {
	case 100000:
		ifmr->ifm_active |= IFM_10_T;
		break;
	case 1000000:
		ifmr->ifm_active |= IFM_100_TX;
		break;
	case 10000000:
		ifmr->ifm_active |= IFM_1000_T;
		break;
	default:
		DPRINTF("unknown speed: %d\n", media_info);
		break;
	}
}

static int
ndis_set_cipher(struct ndis_softc *sc, int cipher)
{
	uint32_t arg;

	if (cipher == WPA_CSE_WEP40 || cipher == WPA_CSE_WEP104)
		arg = NDIS_802_11_WEPSTAT_ENC1ENABLED;
	else if (cipher == WPA_CSE_TKIP)
		arg = NDIS_802_11_WEPSTAT_ENC2ENABLED;
	else if (cipher == WPA_CSE_CCMP)
		arg = NDIS_802_11_WEPSTAT_ENC3ENABLED;
	else
		arg = NDIS_802_11_WEPSTAT_DISABLED;
	return (ndis_set_encryption(sc, arg));
}

/*
 * First we have to set the authentication mode, _then_ we enable
 * the ciphers. If one of the WPA authentication modes isn't enabled,
 * the driver might not permit the TKIP or AES ciphers to be selected.
 */
static int
ndis_set_wpa(struct ndis_softc *sc, void *ie, int ielen)
{
	uint32_t mode = 0;
	uint8_t *w;
	int n, cipher;

	/*
	 * Apparently, the only way for us to know what ciphers
	 * and key management/authentication mode to use is for
	 * us to inspect the optional information element (IE)
	 * stored in the 802.11 state machine. This IE should be
	 * supplied by the WPA supplicant.
	 */
	w = (uint8_t *)ie;
	if (w[0] == IEEE80211_ELEMID_RSN) {
		/* Group Suite Selector */
		w += 7; 	cipher = w[0];
		/* Pairwise Suite Count */
		n = w[1];	w += 2;
		/* Pairwise Suite List */
		for (; n > 0; n--) {
			w += 4;
			if (cipher < w[0])
				cipher = w[0];
		}
		/* Authentication Key Management Suite Count */
		n = w[1];	w += 2;
		/* Authentication Key Management Suite List */
		for (; n > 0; n--) {
			w += 4;
			if (w[0] == WPA_ASE_8021X_PSK)
				mode = NDIS_802_11_AUTHMODE_WPA2PSK;
			else
				mode = NDIS_802_11_AUTHMODE_WPA2;
		}
	} else if (w[0] == IEEE80211_ELEMID_VENDOR) {
		/* Group Suite Selector */
		w += 11;	cipher = w[0];
		/* Pairwise Suite Count */
		n = w[1];	w += 2;
		/* Pairwise Suite List */
		for (; n > 0; n--) {
			w += 4;
			if (cipher < w[0])
				cipher = w[0];
		}
		/* Authentication Key Management Suite Count */
		n = w[1];	w += 2;
		/* Authentication Key Management Suite List */
		for (; n > 0; n--) {
			w += 4;
			if (w[0] == WPA_ASE_8021X_PSK)
				mode = NDIS_802_11_AUTHMODE_WPAPSK;
			else if (w[0] == WPA_ASE_8021X_UNSPEC)
				mode = NDIS_802_11_AUTHMODE_WPA;
			else
				mode = NDIS_802_11_AUTHMODE_WPANONE;
		}
	} else
		return (EINVAL);

	if (ndis_set_authmode(sc, mode) != 0)
		return (ENOTSUP);
	return (ndis_set_cipher(sc, cipher));
}

static void
ndis_media_status(struct ifnet *ifp, struct ifmediareq *imr)
{
	struct ieee80211vap *vap = ifp->if_softc;
	struct ndis_softc *sc = vap->iv_ic->ic_ifp->if_softc;
	uint32_t txrate;

	if (!NDIS_INITIALIZED(sc))
		return;

	if (!ndis_get_int(sc, OID_GEN_LINK_SPEED, &txrate))
		vap->iv_bss->ni_txrate = txrate / 5000;
	ieee80211_media_status(ifp, imr);
}

static void
ndis_setstate_80211(struct ndis_softc *sc, struct ieee80211vap *vap)
{
	struct ieee80211com *ic = sc->ndis_ifp->if_l2com;
	const struct ieee80211_txparam *tp;
	ndis_80211_rates_ex rates;
	int i;
	uint32_t len;

	ndis_set_encryption(sc, NDIS_802_11_WEPSTAT_DISABLED);
	ndis_set_rtsthreshold(sc, vap->iv_rtsthreshold);
	if (ic->ic_caps & IEEE80211_C_TXFRAG)
		ndis_set_fragthreshold(sc, vap->iv_fragthreshold);
	if (ic->ic_caps & IEEE80211_C_PMGT)
		ndis_set_powersave(sc, vap->iv_flags);
	if (ic->ic_caps & IEEE80211_C_TXPMGT)
		ndis_set_txpower(sc);

	/* Set transmission rate */
	tp = &vap->iv_txparms[ieee80211_chan2mode(ic->ic_curchan)];
	if (tp->ucastrate != IEEE80211_FIXED_RATE_NONE) {
		len = sizeof(rates);
		memset(&rates, 0, len);
		if (!ndis_get(sc, OID_802_11_DESIRED_RATES, &rates, len)) {
			for (i = 0; i < len; i++)
				if (rates[i] > tp->ucastrate)
					rates[i] = 0;
			ndis_set(sc,
			    OID_802_11_DESIRED_RATES, &rates, len);
		}
	}

	ndis_set_privacy_filter(sc, vap->iv_flags);
}

static int
ndis_set_infra(struct ndis_softc *sc, int opmode)
{
	uint32_t mode;

	if (opmode == IEEE80211_M_IBSS)
		mode = NDIS_802_11_NET_INFRA_IBSS;
	else
		mode = NDIS_802_11_NET_INFRA_BSS;
	return (ndis_set_int(sc, OID_802_11_INFRASTRUCTURE_MODE, mode));
}

static void
ndis_set_bssid(struct ndis_softc *sc, ndis_80211_macaddr bssid)
{
	if (ndis_set(sc, OID_802_11_BSSID, bssid, IEEE80211_ADDR_LEN))
		DPRINTF("set bssid failed\n");
}

static void
ndis_set_ssid(struct ndis_softc *sc, uint8_t *essid, uint8_t esslen)
{
	ndis_80211_ssid ssid;

	memset(&ssid, 0, sizeof(ssid));
	memcpy(ssid.ssid, essid, esslen);
	ssid.len = esslen;
	if (ndis_set(sc, OID_802_11_SSID, &ssid, sizeof(ssid)))
		DPRINTF("set ssid failed\n");
}

static void
ndis_assoc(struct ndis_softc *sc, struct ieee80211vap *vap)
{
	ndis_set_bssid(sc, vap->iv_bss->ni_bssid);
	ndis_set_ssid(sc, vap->iv_bss->ni_essid, vap->iv_bss->ni_esslen);
}

static void
ndis_auth(struct ndis_softc *sc, struct ieee80211vap *vap)
{

	if (!(vap->iv_flags & IEEE80211_F_WPA)) {
		if (ndis_set_authmode(sc, NDIS_802_11_AUTHMODE_OPEN) != 0)
			DPRINTF("OPEN authmode failed\n");
	}
	if (!(vap->iv_flags & IEEE80211_F_PRIVACY)) {
		if (ndis_set_encryption(sc, NDIS_802_11_WEPSTAT_DISABLED) != 0)
			DPRINTF("OPEN setup failed\n");
	} else if (!(vap->iv_flags & IEEE80211_F_WPA)) {
		if (ndis_set_encryption(sc, NDIS_802_11_WEPSTAT_ENABLED) != 0)
			DPRINTF("WEP setup failed\n");
	} else if (vap->iv_appie_wpa != NULL) {
		struct ieee80211_appie *ie = vap->iv_appie_wpa;

		if (ndis_set_wpa(sc, ie->ie_data, ie->ie_len) != 0)
			DPRINTF("WPA setup failed\n");
	}
}

/*
 * Disassociate and turn off radio.
 */
static void
ndis_disassociate(struct ndis_softc *sc, struct ieee80211vap *vap)
{
	if (ndis_set(sc, OID_802_11_DISASSOCIATE, NULL, 0))
		DPRINTF("disassociate failed\n");
	if (vap->iv_opmode == IEEE80211_M_STA)
		vap->iv_bss->ni_associd = 0;
}

static int
ndis_get_bssid_list(struct ndis_softc *sc, ndis_80211_bssid_list_ex **bl)
{
	uint32_t len = 0;
	int error;

	*bl = malloc(65535, M_NDIS_DEV, M_NOWAIT|M_ZERO);
	if (*bl == NULL)
		return (ENOMEM);
	error = ndis_get_info(sc, OID_802_11_BSSID_LIST,
	    *bl, 65535, NULL, &len);
	if (error == NDIS_STATUS_INVALID_LENGTH ||
	    error == NDIS_STATUS_BUFFER_TOO_SHORT) {
		free(*bl, M_NDIS_DEV);
		*bl = malloc(len, M_NDIS_DEV, M_NOWAIT|M_ZERO);
		if (*bl == NULL)
			return (ENOMEM);
		error = ndis_get(sc, OID_802_11_BSSID_LIST, *bl, len);
	}
	return (error);
}

static void
ndis_getstate_80211(struct ndis_softc *sc, struct ieee80211vap *vap)
{
	struct ieee80211com *ic = sc->ndis_ifp->if_l2com;
	struct ieee80211_node *ni = vap->iv_bss;
	ndis_80211_config config;
	ndis_80211_ssid ssid;
	int chanflag = 0, i = 0;
	uint32_t arg;

	if (ndis_get(sc, OID_802_11_BSSID, ni->ni_bssid, IEEE80211_ADDR_LEN))
		DPRINTF("get bssid failed\n");

	if (ndis_get(sc, OID_802_11_SSID, &ssid, sizeof(ssid))) {
		DPRINTF("get ssid failed\n");
		return;
	}
	memcpy(ni->ni_essid, ssid.ssid, ssid.len);
	ni->ni_esslen = ssid.len;
	if (vap->iv_opmode == IEEE80211_M_STA)
		ni->ni_associd = 1 | 0xc000; /* fake associd */

	if (!ndis_get_int(sc, OID_802_11_RTS_THRESHOLD, &arg))
		vap->iv_rtsthreshold = arg;
	if (ic->ic_caps & IEEE80211_C_TXFRAG)
		if (!ndis_get_int(sc, OID_802_11_FRAGMENTATION_THRESHOLD, &arg))
			vap->iv_fragthreshold = arg;
	if (ic->ic_caps & IEEE80211_C_PMGT)
		if (!ndis_get_int(sc, OID_802_11_POWER_MODE, &arg)) {
			if (arg == NDIS_802_11_POWERMODE_CAM)
				vap->iv_flags &= ~IEEE80211_F_PMGTON;
			else
				vap->iv_flags |= IEEE80211_F_PMGTON;
		}
	if (ic->ic_caps & IEEE80211_C_TXPMGT)
		if (!ndis_get_int(sc, OID_802_11_TX_POWER_LEVEL, &arg)) {
			for (i = 0; i < (sizeof(dBm2mW) / sizeof(dBm2mW[0]));
			    i++)
				if (dBm2mW[i] >= arg)
					break;
			ic->ic_txpowlimit = i;
		}
	if (!ndis_get_int(sc, OID_802_11_AUTHENTICATION_MODE, &arg))
		ni->ni_authmode = ndis_auth_mode(arg);
	if (!ndis_get_int(sc, OID_802_11_PRIVACY_FILTER, &arg)) {
		if (arg == NDIS_802_11_PRIVFILT_8021XWEP)
			vap->iv_flags |= IEEE80211_F_DROPUNENC;
		else
			vap->iv_flags &= ~IEEE80211_F_DROPUNENC;
	}
	if (!ndis_get_int(sc, OID_802_11_ENCRYPTION_STATUS, &arg)) {
		switch (arg) {
		case NDIS_802_11_WEPSTAT_ENC1ENABLED:
		case NDIS_802_11_WEPSTAT_ENC2ENABLED:
		case NDIS_802_11_WEPSTAT_ENC3ENABLED:
			vap->iv_flags |= IEEE80211_F_PRIVACY;
			break;
		default:
			vap->iv_flags &= ~IEEE80211_F_PRIVACY;
			break;
		}
	}
	if (!ndis_get_int(sc, OID_802_11_NETWORK_TYPE_IN_USE, &arg))
		chanflag = ndis_nettype_chan(arg);

	memset(&config, 0, sizeof(config));
	if (!ndis_get(sc, OID_802_11_CONFIGURATION, &config, sizeof(config))) {
		ic->ic_curchan = ieee80211_find_channel(ic,
		    config.dsconfig / 1000, chanflag);
		if (ic->ic_curchan == NULL)
			ic->ic_curchan = &ic->ic_channels[0];
		ni->ni_chan = ic->ic_curchan;
		ic->ic_bsschan = ic->ic_curchan;
		ni->ni_intval = config.beaconperiod;
	}
}

static int
ndis_reset_vap(struct ieee80211vap *vap, u_long cmd)
{
	struct ndis_softc *sc = vap->iv_ic->ic_ifp->if_softc;

	switch (cmd) {
	case IEEE80211_IOC_TXPOWER:
		return (ndis_set_txpower(sc));
	case IEEE80211_IOC_POWERSAVE:
		return (ndis_set_powersave(sc, vap->iv_flags));
	case IEEE80211_IOC_RTSTHRESHOLD:
		return (ndis_set_rtsthreshold(sc, vap->iv_rtsthreshold));
	case IEEE80211_IOC_FRAGTHRESHOLD:
		return (ndis_set_fragthreshold(sc, vap->iv_fragthreshold));
	}
	return (ENETRESET);
}

static int
ndis_ioctl(struct ifnet *ifp, u_long command, caddr_t data)
{
	struct ndis_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *) data;
	int error = 0;

	switch (command) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (ifp->if_drv_flags & IFF_DRV_RUNNING &&
			    ifp->if_flags & IFF_PROMISC &&
			    !(sc->ndis_if_flags & IFF_PROMISC)) {
				sc->ndis_filter |=
				    NDIS_PACKET_TYPE_PROMISCUOUS;
				error = ndis_set_filter(sc, sc->ndis_filter);
			} else if (ifp->if_drv_flags & IFF_DRV_RUNNING &&
			    !(ifp->if_flags & IFF_PROMISC) &&
			    sc->ndis_if_flags & IFF_PROMISC) {
				sc->ndis_filter &=
				    ~NDIS_PACKET_TYPE_PROMISCUOUS;
				error = ndis_set_filter(sc, sc->ndis_filter);
			} else
				ndis_init(sc);
		} else {
			if (ifp->if_drv_flags & IFF_DRV_RUNNING)
				ndis_stop(sc);
		}
		sc->ndis_if_flags = ifp->if_flags;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = ndis_set_multi(sc);
		break;
	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->ifmedia, command);
		break;
	case SIOCSIFCAP:
		ifp->if_capenable = ifr->ifr_reqcap;
		if (ifp->if_capenable & IFCAP_TXCSUM)
			ifp->if_hwassist = sc->ndis_hwassist;
		else
			ifp->if_hwassist = 0;
		error = ndis_set_task_offload(sc);
		break;
	default:
		error = ether_ioctl(ifp, command, data);
		break;
	}
	return (error);
}

static int
ndis_ioctl_80211(struct ifnet *ifp, u_long command, caddr_t data)
{
	struct ndis_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = ifp->if_l2com;
	struct ifreq *ifr = (struct ifreq *) data;
	struct ndis_oid_data oid;
	struct ndis_evt evt;
	void *oidbuf;
	int error = 0;

	switch (command) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (!(ifp->if_drv_flags & IFF_DRV_RUNNING))
				ndis_init(sc);
		} else {
			if (ifp->if_drv_flags & IFF_DRV_RUNNING)
				ndis_stop(sc);
		}
		break;
	case SIOCGDRVSPEC:
		if ((error = priv_check(curthread, PRIV_DRIVER)))
			break;
		error = copyin(ifr->ifr_data, &oid, sizeof(oid));
		if (error)
			break;
		oidbuf = malloc(oid.len, M_NDIS_DEV, M_NOWAIT|M_ZERO);
		if (oidbuf == NULL) {
			error = ENOMEM;
			break;
		}
		error = copyin(ifr->ifr_data + sizeof(oid), oidbuf, oid.len);
		if (error) {
			free(oidbuf, M_NDIS_DEV);
			break;
		}
		error = ndis_get(sc, oid.oid, oidbuf, oid.len);
		if (error) {
			free(oidbuf, M_NDIS_DEV);
			break;
		}
		error = copyout(&oid, ifr->ifr_data, sizeof(oid));
		if (error) {
			free(oidbuf, M_NDIS_DEV);
			break;
		}
		error = copyout(oidbuf, ifr->ifr_data + sizeof(oid), oid.len);
		free(oidbuf, M_NDIS_DEV);
		break;
	case SIOCSDRVSPEC:
		if ((error = priv_check(curthread, PRIV_DRIVER)))
			break;
		error = copyin(ifr->ifr_data, &oid, sizeof(oid));
		if (error)
			break;
		oidbuf = malloc(oid.len, M_NDIS_DEV, M_NOWAIT|M_ZERO);
		if (oidbuf == NULL) {
			error = ENOMEM;
			break;
		}
		error = copyin(ifr->ifr_data + sizeof(oid), oidbuf, oid.len);
		if (error) {
			free(oidbuf, M_NDIS_DEV);
			break;
		}
		error = ndis_set(sc, oid.oid, oidbuf, oid.len);
		if (error) {
			free(oidbuf, M_NDIS_DEV);
			break;
		}
		error = copyout(&oid, ifr->ifr_data, sizeof(oid));
		if (error) {
			free(oidbuf, M_NDIS_DEV);
			break;
		}
		error = copyout(oidbuf, ifr->ifr_data + sizeof(oid), oid.len);
		free(oidbuf, M_NDIS_DEV);
		break;
	case SIOCGPRIVATE_0:
		if ((error = priv_check(curthread, PRIV_DRIVER)))
			break;
		NDIS_LOCK(sc);
		if (sc->ndis_evt[sc->ndis_evtcidx].ne_sts == 0) {
			error = ENOENT;
			NDIS_UNLOCK(sc);
			break;
		}
		error = copyin(ifr->ifr_data, &evt, sizeof(evt));
		if (error) {
			NDIS_UNLOCK(sc);
			break;
		}
		if (evt.ne_len < sc->ndis_evt[sc->ndis_evtcidx].ne_len) {
			error = ENOSPC;
			NDIS_UNLOCK(sc);
			break;
		}
		error = copyout(&sc->ndis_evt[sc->ndis_evtcidx],
		    ifr->ifr_data, sizeof(uint32_t) * 2);
		if (error) {
			NDIS_UNLOCK(sc);
			break;
		}
		if (sc->ndis_evt[sc->ndis_evtcidx].ne_len) {
			error = copyout(sc->ndis_evt[sc->ndis_evtcidx].ne_buf,
			    ifr->ifr_data + (sizeof(uint32_t) * 2),
			    sc->ndis_evt[sc->ndis_evtcidx].ne_len);
			if (error) {
				NDIS_UNLOCK(sc);
				break;
			}
			free(sc->ndis_evt[sc->ndis_evtcidx].ne_buf, M_NDIS_DEV);
			sc->ndis_evt[sc->ndis_evtcidx].ne_buf = NULL;
		}
		sc->ndis_evt[sc->ndis_evtcidx].ne_len = 0;
		sc->ndis_evt[sc->ndis_evtcidx].ne_sts = 0;
		NDIS_EVTINC(sc->ndis_evtcidx);
		NDIS_UNLOCK(sc);
		break;
	case SIOCGIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &ic->ic_media, command);
		break;
	case SIOCGIFADDR:
		error = ether_ioctl(ifp, command, data);
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

static int
ndis_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *key)
{
	struct ndis_softc *sc = vap->iv_ic->ic_ifp->if_softc;
	const struct ieee80211_cipher *cip = key->wk_cipher;

	if (cip->ic_cipher == IEEE80211_CIPHER_WEP) {
		uint32_t idx = key->wk_keyix;

		if (ndis_set_int(sc, OID_802_11_REMOVE_WEP, idx))
			return (0);
	} else {
		ndis_80211_remove_key rkey;

		memset(&rkey, 0, sizeof(rkey));
		rkey.nk_len = sizeof(rkey);
		rkey.nk_keyidx = key->wk_keyix;
		if (!(key->wk_flags & IEEE80211_KEY_GROUP))
			rkey.nk_keyidx |= 1 << 30;
		memcpy(rkey.nk_bssid, key->wk_macaddr, IEEE80211_ADDR_LEN);
		if (ndis_set(sc, OID_802_11_REMOVE_KEY, &rkey, sizeof(rkey)))
			return (0);
	}
	return (1);
}

static int
ndis_key_set(struct ieee80211vap *vap, const struct ieee80211_key *key,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ifnet *ifp = vap->iv_ic->ic_ifp;
	struct ndis_softc *sc = ifp->if_softc;
	ndis_80211_wep wep;
	ndis_80211_key nkey;
	int error = 0;

	switch (key->wk_cipher->ic_cipher) {
	case IEEE80211_CIPHER_AES_CCM:
	case IEEE80211_CIPHER_TKIP:
		memset(&nkey, 0, sizeof(nkey));
		nkey.nk_keylen = key->wk_keylen;
		nkey.nk_len =
		    sizeof(nkey) - sizeof(nkey.nk_keydata) + nkey.nk_keylen;
		memcpy(nkey.nk_bssid, key->wk_macaddr, IEEE80211_ADDR_LEN);
		if (key->wk_keyix != IEEE80211_KEYIX_NONE)
			nkey.nk_keyidx = key->wk_keyix;
		else
			nkey.nk_keyidx = 0;
		if (key->wk_flags & IEEE80211_KEY_XMIT)
			nkey.nk_keyidx |= 1 << 31;
		if (!(key->wk_flags & IEEE80211_KEY_GROUP))
			nkey.nk_keyidx |= 1 << 30;

		nkey.nk_keyrsc = key->wk_keyrsc[IEEE80211_NONQOS_TID];
		if (nkey.nk_keyrsc)
			nkey.nk_keyidx |= 1 << 29;
		if (key->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP &&
		    key->wk_keylen == 32) {
			memcpy(nkey.nk_keydata, key->wk_key, 16);
			memcpy(nkey.nk_keydata + 24, key->wk_key + 16, 8);
			memcpy(nkey.nk_keydata + 16, key->wk_key + 24, 8);
		} else
			memcpy(nkey.nk_keydata, key->wk_key, key->wk_keylen);
		error = ndis_set(sc, OID_802_11_ADD_KEY, &nkey, nkey.nk_len);
		break;
	case IEEE80211_CIPHER_WEP:
		memset(&wep, 0, sizeof(wep));
		wep.nw_keylen = key->wk_keylen;
		wep.nw_keyidx = key->wk_keyix;
		wep.nw_len =
		    sizeof(wep) - sizeof(wep.nw_keydata) + wep.nw_keylen;
		if (key->wk_flags & IEEE80211_KEY_XMIT)
			wep.nw_keyidx |= 1 << 31;
		memcpy(wep.nw_keydata, key->wk_key, wep.nw_keylen);
		error = ndis_set(sc, OID_802_11_ADD_WEP, &wep, wep.nw_len);
		break;
	default:
		error = ENOTSUP;
		break;
	}
	if (error)
		return (0);
	return (1);
}

static void
ndis_resettask(device_object *d, void *arg)
{
	struct ndis_softc *sc = arg;

	ndis_reset_nic(sc);
}

/*
 * Stop the adapter and free any mbufs allocated to the RX and TX lists.
 */
static void
ndis_stop(struct ndis_softc *sc)
{
	int i;

	callout_drain(&sc->ndis_stat_callout);
	if (sc->ndis_80211 == 1)
		callout_drain(&sc->ndis_scan_callout);

	NDIS_LOCK(sc);
	sc->ndis_tx_timer = 0;
	if_link_state_change(sc->ndis_ifp, LINK_STATE_UNKNOWN);
	sc->ndis_ifp->if_drv_flags &= ~(IFF_DRV_RUNNING|IFF_DRV_OACTIVE);
	for (i = 0; i < NDIS_EVENTS; i++) {
		if (sc->ndis_evt[i].ne_sts && sc->ndis_evt[i].ne_buf != NULL) {
			free(sc->ndis_evt[i].ne_buf, M_NDIS_DEV);
			sc->ndis_evt[i].ne_buf = NULL;
		}
		sc->ndis_evt[i].ne_sts = 0;
		sc->ndis_evt[i].ne_len = 0;
	}
	sc->ndis_evtcidx = 0;
	sc->ndis_evtpidx = 0;
	NDIS_UNLOCK(sc);

	ndis_set_powerstate(sc, NDIS_DEVICE_STATE_D3);
}

/*
 * Stop all chip I/O so that the kernel's probe routines don't
 * get confused by errant DMAs when rebooting.
 */
void
ndis_shutdown(device_t dev)
{
	ndis_shutdown_nic(device_get_softc(dev));
}

static int
ndis_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct ndis_vap *nvp = NDIS_VAP(vap);
	struct ieee80211com *ic = vap->iv_ic;
	struct ndis_softc *sc = ic->ic_ifp->if_softc;

	DPRINTF("%s: %s -> %s\n", __func__,
		ieee80211_state_name[vap->iv_state],
		ieee80211_state_name[nstate]);

	vap->iv_state = nstate;

	IEEE80211_UNLOCK(ic);
	switch (nstate) {
	case IEEE80211_S_INIT:
		if (vap->iv_state != IEEE80211_S_INIT)
			ndis_disassociate(sc, vap);
		break;
	case IEEE80211_S_SCAN:
		if (vap->iv_state == IEEE80211_S_RUN)
			ndis_disassociate(sc, vap);
		if (vap->iv_flags & IEEE80211_F_DESBSSID)
			ndis_set_bssid(sc, vap->iv_des_bssid);
		else
			ndis_set_bssid(sc, "\xff\xff\xff\xff\xff\xff");
		if (vap->iv_des_nssid)
			ndis_set_ssid(sc,
			    vap->iv_des_ssid[0].ssid, vap->iv_des_ssid[0].len);
		else
			ndis_set_ssid(sc, NULL, 0);
		ndis_setstate_80211(sc, vap);
		break;
	case IEEE80211_S_RUN:
		if (vap->iv_opmode == IEEE80211_M_IBSS) {
			ndis_auth(sc, vap);
			ndis_assoc(sc, vap);
		}
		ndis_getstate_80211(sc, vap);
		break;
	case IEEE80211_S_AUTH:
		ndis_auth(sc, vap);
		ieee80211_new_state(vap, IEEE80211_S_ASSOC, 0);
		break;
	case IEEE80211_S_ASSOC:
		ndis_assoc(sc, vap);
		break;
	default:
		break;
	}
	IEEE80211_LOCK(ic);
	return (nvp->newstate(vap, nstate, arg));
}

static void
ndis_scan(void *arg)
{
	struct ieee80211vap *vap = arg;

	ieee80211_scan_done(vap);
}

static void
ndis_scan_start(struct ieee80211com *ic)
{
	struct ndis_softc *sc = ic->ic_ifp->if_softc;
	struct ieee80211vap *vap;

	vap = TAILQ_FIRST(&ic->ic_vaps);

	if (ndis_set(sc, OID_802_11_BSSID_LIST_SCAN, NULL, 0)) {
		DPRINTF("bssid list scan failed\n");
		ieee80211_cancel_scan(vap);
		return;
	}
	/* Set a timer to collect the results */
	callout_reset(&sc->ndis_scan_callout, hz + 200, ndis_scan, vap);
}

static void
ndis_set_channel(struct ieee80211com *ic)
{
	struct ndis_softc *sc = ic->ic_ifp->if_softc;
	struct ieee80211vap *vap;
	ndis_80211_config config;

	if (sc->ndis_ifp->if_link_state == LINK_STATE_UP ||
	    ic->ic_bsschan == IEEE80211_CHAN_ANYC)
		return;

	vap = TAILQ_FIRST(&ic->ic_vaps);

	memset(&config, 0, sizeof(config));
	config.len = sizeof(config);
	config.fhconfig.len = sizeof(ndis_80211_config_fh);
	if (ndis_get(sc, OID_802_11_CONFIGURATION, &config, sizeof(config)))
		return;

	config.beaconperiod = ic->ic_bintval;
	if (config.atimwin == 0)
		config.atimwin = 100;
	if (config.fhconfig.dwelltime == 0)
		config.fhconfig.dwelltime = 100;
	config.dsconfig = ic->ic_bsschan->ic_freq * 1000;
	config.len = sizeof(config);
	config.fhconfig.len = sizeof(ndis_80211_config_fh);
	DPRINTF("Setting channel to %ukHz\n", config.dsconfig);
	ndis_set(sc, OID_802_11_CONFIGURATION, &config, sizeof(config));
}

static void
ndis_scan_curchan(struct ieee80211_scan_state *ss, unsigned long maxdwell)
{
	/* ignore */
}

static void
ndis_scan_mindwell(struct ieee80211_scan_state *ss)
{
	/* NB: don't try to abort scan; wait for firmware to finish */
}

static void
ndis_scan_end(struct ieee80211com *ic)
{
	struct ndis_softc *sc = ic->ic_ifp->if_softc;
	struct ieee80211vap *vap;
	struct ieee80211_scanparams sp;
	struct ieee80211_frame wh;
	struct ieee80211_channel *saved_chan;
	ndis_80211_bssid_list_ex *bl = NULL;
	ndis_wlan_bssid_ex *wb;
	int i, j, rssi, freq, chanflag;
	uint8_t ssid[2+IEEE80211_NWID_LEN], rates[2+IEEE80211_RATE_MAXSIZE];
	uint8_t *frm, *efrm;

	vap = TAILQ_FIRST(&ic->ic_vaps);
	saved_chan = ic->ic_curchan;

	ndis_get_bssid_list(sc, &bl);
	if (bl == NULL) {
		device_printf(sc->ndis_dev, "failed to get bssid list\n");
		return;
	}

	DPRINTF("%d scan results\n", bl->items);
	wb = &bl->bssid[0];
	for (i = 0; i < bl->items; i++) {
		memset(&sp, 0, sizeof(sp));
		memcpy(wh.i_addr2, wb->macaddr, sizeof(wh.i_addr2));
		memcpy(wh.i_addr3, wb->macaddr, sizeof(wh.i_addr3));
		rssi = 100 * (wb->rssi - -96) / (-32 - -96);
		rssi = max(0, min(rssi, 100));	/* limit 0 <= rssi <= 100 */
		if (wb->privacy)
			sp.capinfo |= IEEE80211_CAPINFO_PRIVACY;
		sp.bintval = wb->config.beaconperiod;
		if (wb->config.fhconfig.len != 0)
			sp.fhdwell = wb->config.fhconfig.dwelltime;
		switch (wb->netinfra) {
			case NDIS_802_11_NET_INFRA_IBSS:
				sp.capinfo |= IEEE80211_CAPINFO_IBSS;
				break;
			case NDIS_802_11_NET_INFRA_BSS:
				sp.capinfo |= IEEE80211_CAPINFO_ESS;
				break;
		}
		sp.rates = &rates[0];
		for (j = 0; j < IEEE80211_RATE_MAXSIZE; j++) {
			/* XXX - check units */
			if (wb->supportedrates[j] == 0)
				break;
			rates[2 + j] =
			wb->supportedrates[j] & 0x7f;
		}
		rates[1] = j;
		sp.ssid = (uint8_t *)&ssid[0];
		memcpy(sp.ssid + 2, &wb->ssid.ssid,
		    wb->ssid.len);
		sp.ssid[1] = wb->ssid.len;

		chanflag = ndis_nettype_chan(wb->nettype);
		freq = wb->config.dsconfig / 1000;
		sp.chan = sp.bchan = ieee80211_mhz2ieee(freq, chanflag);
		/* Hack ic->ic_curchan to be in sync with the scan result */
		ic->ic_curchan = ieee80211_find_channel(ic, freq, chanflag);
		if (ic->ic_curchan == NULL)
			ic->ic_curchan = &ic->ic_channels[0];

		/* Process extended info from AP */
		if (wb->len > sizeof(ndis_wlan_bssid)) {
			frm = (uint8_t *)&wb->ies;
			efrm = frm + wb->ielen;
			if (efrm - frm < 12)
				goto done;
			sp.tstamp = frm;			frm += 8;
			sp.bintval = le16toh(*(uint16_t *)frm);	frm += 2;
			sp.capinfo = le16toh(*(uint16_t *)frm);	frm += 2;
			sp.ies = frm;
			sp.ies_len = efrm - frm;
		}
done:
		DPRINTF("scan: bssid %s chan %dMHz (%d/%d) rssi %d\n",
		    ether_sprintf(wb->macaddr), freq, sp.bchan, chanflag,
		    rssi);
		ieee80211_add_scan(vap, &sp, &wh, 0, rssi, -96);
		wb = (ndis_wlan_bssid_ex *)((char *)wb + wb->len);
	}
	free(bl, M_NDIS_DEV);
	/* Restore the channel after messing with it */
	ic->ic_curchan = saved_chan;
}
