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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <net/bpf.h>

#include <sys/bus.h>
#include <machine/bus.h>
#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/ndis_var.h>
#include <compat/ndis/usbd_var.h>
#include <dev/if_ndis/if_ndisvar.h>

MODULE_DEPEND(ndis, usb, 1, 1, 1);

static int	ndis_attach_usb(device_t);
static int	ndis_detach_usb(device_t);
static int	ndis_devcompare_usb(enum ndis_bus_type,
		    struct ndis_usb_type *, device_t);
static int	ndis_probe_usb(device_t);
static struct resource_list *ndis_get_resource_list(device_t, device_t);

static device_method_t ndis_methods[] = {
	DEVMETHOD(device_probe,		ndis_probe_usb),
	DEVMETHOD(device_attach,	ndis_attach_usb),
	DEVMETHOD(device_detach,	ndis_detach_usb),
	DEVMETHOD(device_shutdown,	ndis_shutdown),
	DEVMETHOD(bus_get_resource_list, ndis_get_resource_list),
	DEVMETHOD_END
};

static driver_t ndis_driver = {
	"ndis",
	ndis_methods,
	sizeof(struct ndis_softc)
};

static devclass_t ndis_devclass;

DRIVER_MODULE(ndis, uhub, ndis_driver, ndis_devclass, ndisdrv_modevent, 0);

static int
ndis_devcompare_usb(enum ndis_bus_type bustype,
    struct ndis_usb_type *t, device_t dev)
{
	struct usb_attach_arg *uaa;

	if (bustype != NDIS_PNPBUS)
		return (FALSE);

	uaa = device_get_ivars(dev);
	for (; t->name != NULL; t++) {
		if ((uaa->info.idVendor == t->vendor) &&
		    (uaa->info.idProduct == t->device)) {
			device_set_desc(dev, t->name);
			return (TRUE);
		}
	}

	return (FALSE);
}

static int
ndis_probe_usb(device_t dev)
{
	struct usb_attach_arg *uaa;
	struct drvdb_ent *db;

	uaa = device_get_ivars(dev);
	if (uaa->usb_mode != USB_MODE_HOST ||
	    uaa->info.bConfigIndex != NDISUSB_CONFIG_NO ||
	    uaa->info.bIfaceIndex != NDISUSB_IFACE_INDEX ||
	    windrv_lookup(0, "USB Bus") == NULL)
		return (ENXIO);

	db = windrv_match((matchfuncptr)ndis_devcompare_usb, dev);
	if (db == NULL)
		return (ENXIO);
	uaa->driver_ivar = db;

	return (0);
}

static int
ndis_attach_usb(device_t dev)
{
	const struct drvdb_ent *db;
	struct ndisusb_softc *dummy;
	struct usb_attach_arg *uaa;
	struct ndis_softc *sc;
	struct ndis_usb_type *t;
	struct driver_object *drv;
	int devidx = 0;

	device_set_usb_desc(dev);
	dummy = device_get_softc(dev);
	uaa = device_get_ivars(dev);
	db = uaa->driver_ivar;
	sc = (struct ndis_softc *)dummy;
	sc->ndis_dev = dev;
	mtx_init(&sc->ndisusb_mtx, "NDIS USB", MTX_NETWORK_LOCK, MTX_DEF);
	sc->ndis_dobj = db->windrv_object;
	sc->ndis_regvals = db->windrv_regvals;
	sc->ndis_bus_type = NDIS_PNPBUS;
	sc->ndisusb_dev = uaa->device;

	drv = windrv_lookup(0, "USB Bus");
	windrv_create_pdo(drv, dev);

	/* Figure out exactly which device we matched. */
	for (t = db->windrv_devlist; t->name != NULL; t++, devidx++) {
		if ((uaa->info.idVendor == t->vendor) &&
		    (uaa->info.idProduct == t->device)) {
			sc->ndis_devidx = devidx;
			break;
		}
	}

	if (ndis_attach(dev) != 0)
		return (ENXIO);

	return (0);
}

static int
ndis_detach_usb(device_t dev)
{
	struct ndis_softc *sc;
	struct ndisusb_ep *ne;
	int i;

	sc = device_get_softc(dev);
	sc->ndisusb_status |= NDISUSB_STATUS_DETACH;

	ndis_pnp_event_nic(sc, NDIS_DEVICE_PNP_EVENT_SURPRISE_REMOVED, 0);

	if (sc->ndisusb_status & NDISUSB_STATUS_SETUP_EP) {
		usbd_transfer_unsetup(sc->ndisusb_dread_ep.ne_xfer, 1);
		usbd_transfer_unsetup(sc->ndisusb_dwrite_ep.ne_xfer, 1);
	}
	for (i = 0; i < NDISUSB_ENDPT_MAX; i++) {
		ne = &sc->ndisusb_ep[i];
		usbd_transfer_unsetup(ne->ne_xfer, 1);
	}

	ndis_detach(dev);

	mtx_destroy(&sc->ndisusb_mtx);
	return (0);
}

static struct resource_list *
ndis_get_resource_list(device_t dev, device_t child)
{
	struct ndis_softc *sc;

	sc = device_get_softc(dev);
	return (BUS_GET_RESOURCE_LIST(device_get_parent(sc->ndis_dev), dev));
}
