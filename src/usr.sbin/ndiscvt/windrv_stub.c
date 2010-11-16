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
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/cfg_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/ndis_var.h>
#include "windrv.h"

struct ndis_pci_type {
	uint16_t	ndis_vid;
	uint16_t	ndis_did;
	uint32_t	ndis_subsys;
	char		*ndis_name;
};

struct ndis_pccard_type {
	const char	*ndis_vid;
	const char	*ndis_did;
	char		*ndis_name;
};

struct ndis_usb_type {
	uint16_t	ndis_vid;
	uint16_t	ndis_did;
	char		*ndis_name;
};

#ifdef NDIS_PCI_DEV_TABLE
static struct ndis_pci_type ndis_devs_pci[] = {
	NDIS_PCI_DEV_TABLE
	{ 0, 0, 0, NULL }
};
#endif

#ifdef NDIS_PCMCIA_DEV_TABLE
static struct ndis_pccard_type ndis_devs_pccard[] = {
	NDIS_PCMCIA_DEV_TABLE
	{ NULL, NULL, NULL }
};
#endif

#ifdef NDIS_USB_DEV_TABLE
static struct ndis_usb_type ndis_devs_usb[] = {
	NDIS_USB_DEV_TABLE
	{ 0, 0, NULL }
};
#endif

#ifndef DRV_DATA_START
#define	DRV_DATA_START UNDEF_START
#endif

#ifndef DRV_DATA_END
#define	DRV_DATA_END UNDEF_END
#endif

#ifndef DRV_NAME
#define	DRV_NAME UNDEF_NAME
#endif

extern uint8_t DRV_DATA_START;
extern uint8_t DRV_DATA_END;

/*
 * The following is stub code that makes it look as though we want
 * to be a child device of all the buses that our supported devices
 * might want to attach to. Our probe routine always fails. The
 * reason we need this code is so that loading an ELF-ified Windows
 * driver module will trigger a bus reprobe.
 */
#define	MODULE_DECL(x)				\
	MODULE_DEPEND(x, ndisapi, 1, 1, 1);	\
	MODULE_DEPEND(x, ndis, 1, 1, 1)

MODULE_DECL(DRV_NAME);

static int	windrv_modevent(module_t, int, void *);
static int	windrv_probe(device_t);

static int windrv_loaded = 0;

static device_method_t windrv_methods[] = {
	DEVMETHOD(device_probe, windrv_probe),
	{ 0, 0 }
};

static driver_t windrv_driver = {
	"windrv_stub",
	windrv_methods,
	0
};

static devclass_t windrv_devclass;

#define	DRIVER_DECL(x)					\
	DRIVER_MODULE(x, pci, windrv_driver,		\
	    windrv_devclass, windrv_modevent, NULL);	\
	DRIVER_MODULE(x, cardbus, windrv_driver,	\
	    windrv_devclass, windrv_modevent, NULL);	\
	DRIVER_MODULE(x, pccard, windrv_driver,		\
	    windrv_devclass, windrv_modevent, NULL);	\
	DRIVER_MODULE(x, uhub, windrv_driver,		\
	    windrv_devclass, windrv_modevent, NULL);	\
	MODULE_VERSION(x, 1)

DRIVER_DECL(DRV_NAME);

static int
windrv_probe(device_t dev)
{

	return (ENXIO);
}

static int
windrv_modevent(module_t mod, int cmd, void *arg)
{
	vm_offset_t drv_data_start, drv_data_end;
	size_t drv_data_len;

	drv_data_start = (vm_offset_t)&DRV_DATA_START;
	drv_data_end = (vm_offset_t)&DRV_DATA_END;
	drv_data_len = drv_data_end - drv_data_start;

	switch (cmd) {
	case MOD_LOAD:
		if (windrv_loaded == 1)
			break;
		windrv_loaded = 1;
#ifdef NDIS_PCI_DEV_TABLE
		windrv_load(mod, drv_data_start, drv_data_len, NDIS_PCIBUS,
		    ndis_devs_pci, &ndis_regvals);
#endif
#ifdef NDIS_PCMCIA_DEV_TABLE
		windrv_load(mod, drv_data_start, drv_data_len, NDIS_PCMCIABUS,
		    ndis_devs_pccard, &ndis_regvals);
#endif
#ifdef NDIS_USB_DEV_TABLE
		windrv_load(mod, drv_data_start, drv_data_len, NDIS_PNPBUS,
		   ndis_devs_usb, &ndis_regvals);
#endif
		break;
	case MOD_UNLOAD:
		if (windrv_loaded == 0)
			break;
		windrv_loaded = 0;
#ifdef NDIS_PCI_DEV_TABLE
		windrv_unload(mod, drv_data_start);
#endif
#ifdef NDIS_PCMCIA_DEV_TABLE
		windrv_unload(mod, drv_data_start);
#endif
#ifdef NDIS_USB_DEV_TABLE
		windrv_unload(mod, drv_data_start);
#endif
		break;
	case MOD_SHUTDOWN:
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}
