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
#include <sys/unistd.h>
#include <sys/types.h>

#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <machine/bus.h>
#include <sys/bus.h>

#include <net/if.h>
#include <net/if_media.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usb_busdma.h>
#include <dev/usb/usb_device.h>
#include <dev/usb/usb_request.h>

#include <compat/ndis/pe_var.h>
#include <compat/ndis/resource_var.h>
#include <compat/ndis/ntoskrnl_var.h>
#include <compat/ndis/ndis_var.h>
#include <compat/ndis/hal_var.h>
#include <compat/ndis/usbd_var.h>
#include <dev/if_ndis/if_ndisvar.h>

static struct driver_object usbd_driver;
static usb_callback_t usbd_non_isoc_callback;
static usb_callback_t usbd_ctrl_callback;

#define	USBD_CTRL_READ_PIPE		0
#define	USBD_CTRL_WRITE_PIPE		1
#define	USBD_CTRL_MAX_PIPE		2
#define	USBD_CTRL_READ_BUFFER_SP	256
#define	USBD_CTRL_WRITE_BUFFER_SP	256
#define	USBD_CTRL_READ_BUFFER_SIZE	\
	(sizeof(struct usb_device_request) + USBD_CTRL_READ_BUFFER_SP)
#define	USBD_CTRL_WRITE_BUFFER_SIZE	\
	(sizeof(struct usb_device_request) + USBD_CTRL_WRITE_BUFFER_SP)
static struct usb_config usbd_default_epconfig[USBD_CTRL_MAX_PIPE] = {
	[USBD_CTRL_READ_PIPE] = {
		.type =		UE_CONTROL,
		.endpoint =	0x00,	/* control pipe */
		.direction =	UE_DIR_ANY,
		.if_index =	0,
		.bufsize =	USBD_CTRL_READ_BUFFER_SIZE,
		.flags =	{ .short_xfer_ok = 1, },
		.callback =	&usbd_ctrl_callback,
		.timeout =	5000,	/* 5 seconds */
	},
	[USBD_CTRL_WRITE_PIPE] = {
		.type =		UE_CONTROL,
		.endpoint =	0x00,	/* control pipe */
		.direction =	UE_DIR_ANY,
		.if_index =	0,
		.bufsize =	USBD_CTRL_WRITE_BUFFER_SIZE,
		.flags =	{ .proxy_buffer = 1, },
		.callback =	&usbd_ctrl_callback,
		.timeout =	5000,	/* 5 seconds */
	}
};

static int32_t usbd_func_bulkintr(struct irp *);
static int32_t usbd_func_vendorclass(struct irp *);
static int32_t usbd_func_selconf(struct irp *);
static int32_t usbd_func_abort_pipe(struct irp *);
static usb_error_t usbd_setup_endpoint(struct irp *, uint8_t,
    struct usb_endpoint_descriptor *);
static usb_error_t usbd_setup_endpoint_default(struct irp *, uint8_t);
static usb_error_t usbd_setup_endpoint_one(struct irp *, uint8_t,
    struct ndisusb_ep *, struct usb_config *);
static int32_t usbd_func_getdesc(struct irp *);
static union usbd_urb *usbd_geturb(struct irp *);
static struct ndisusb_ep*usbd_get_ndisep(struct irp *,
    usb_endpoint_descriptor_t *);
static int32_t usbd_iodispatch(struct device_object *, struct irp *);
static int32_t usbd_ioinvalid(struct device_object *, struct irp *);
static int32_t usbd_pnp(struct device_object *, struct irp *);
static int32_t usbd_power(struct device_object *, struct irp *);
static void usbd_irpcancel(struct device_object *, struct irp *);
static int32_t usbd_submit_urb(struct irp *);
static int32_t usbd_urb2nt(int32_t);
static void usbd_task(struct device_object *, struct ndis_softc *);
static int32_t usbd_taskadd(struct irp *, unsigned);
static void usbd_xfertask(struct device_object *, struct ndis_softc *);
static void dummy(void);

static union usbd_urb *USBD_CreateConfigurationRequest(
    usb_config_descriptor_t *, uint16_t *);
static union usbd_urb *USBD_CreateConfigurationRequestEx(
    usb_config_descriptor_t *, struct usbd_interface_list_entry *);
static void USBD_GetUSBDIVersion(struct usbd_version_info *);
static usb_interface_descriptor_t *USBD_ParseConfigurationDescriptor(
    usb_config_descriptor_t *, uint8_t, uint8_t);
static usb_interface_descriptor_t *USBD_ParseConfigurationDescriptorEx(
    usb_config_descriptor_t *, void *, int32_t, int32_t, int32_t, int32_t,
    int32_t);

/*
 * We need to wrap these functions because these need `context switch' from
 * Windows to UNIX before it's called.
 */
static funcptr usbd_iodispatch_wrap;
static funcptr usbd_ioinvalid_wrap;
static funcptr usbd_pnp_wrap;
static funcptr usbd_power_wrap;
static funcptr usbd_irpcancel_wrap;
static funcptr usbd_task_wrap;
static funcptr usbd_xfertask_wrap;

void
usbd_libinit(void)
{
	int i;

	windrv_wrap_table(usbd_functbl);
	windrv_wrap((funcptr)usbd_ioinvalid, &usbd_ioinvalid_wrap, 2, STDCALL);
	windrv_wrap((funcptr)usbd_iodispatch, &usbd_iodispatch_wrap, 2, STDCALL);
	windrv_wrap((funcptr)usbd_pnp, &usbd_pnp_wrap, 2, STDCALL);
	windrv_wrap((funcptr)usbd_power, &usbd_power_wrap, 2, STDCALL);
	windrv_wrap((funcptr)usbd_irpcancel, &usbd_irpcancel_wrap, 2, STDCALL);
	windrv_wrap((funcptr)usbd_task, &usbd_task_wrap, 2, STDCALL);
	windrv_wrap((funcptr)usbd_xfertask, &usbd_xfertask_wrap, 2, STDCALL);

	/* Create a fake USB driver instance. */
	windrv_bus_attach(&usbd_driver, "USB Bus");

	/* Set up our dipatch routine. */
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		usbd_driver.dispatch[i] = (driver_dispatch)usbd_ioinvalid_wrap;

	usbd_driver.dispatch[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
	    (driver_dispatch)usbd_iodispatch_wrap;
	usbd_driver.dispatch[IRP_MJ_DEVICE_CONTROL] =
	    (driver_dispatch)usbd_iodispatch_wrap;
	usbd_driver.dispatch[IRP_MJ_POWER] = (driver_dispatch)usbd_power_wrap;
	usbd_driver.dispatch[IRP_MJ_PNP] = (driver_dispatch)usbd_pnp_wrap;
}

void
usbd_libfini(void)
{

	windrv_unwrap_table(usbd_functbl);
	windrv_unwrap(usbd_xfertask_wrap);
	windrv_unwrap(usbd_task_wrap);
	windrv_unwrap(usbd_irpcancel_wrap);
	windrv_unwrap(usbd_power_wrap);
	windrv_unwrap(usbd_pnp_wrap);
	windrv_unwrap(usbd_iodispatch_wrap);
	windrv_unwrap(usbd_ioinvalid_wrap);

	RtlFreeUnicodeString(&usbd_driver.driver_name);
}

static int32_t
usbd_iodispatch(struct device_object *dobj, struct irp *ip)
{
	struct io_stack_location *sl;
	device_t dev = dobj->devext;
	int32_t status;

	sl = IoGetCurrentIrpStackLocation(ip);
	switch (sl->parameters.ioctl.iocode) {
	case IOCTL_INTERNAL_USB_SUBMIT_URB:
		IRP_NDIS_DEV(ip) = dev;
		status = usbd_submit_urb(ip);
		break;
	default:
		device_printf(dev, "ioctl 0x%x isn't supported\n",
		    sl->parameters.ioctl.iocode);
		status = USBD_STATUS_NOT_SUPPORTED;
		break;
	}
	if (status == USBD_STATUS_PENDING)
		return (NDIS_STATUS_PENDING);

	ip->iostat.u.status = usbd_urb2nt(status);
	if (status != USBD_STATUS_SUCCESS)
		ip->iostat.info = 0;
	return (ip->iostat.u.status);
}

static int32_t
usbd_ioinvalid(struct device_object *dobj, struct irp *ip)
{
	struct io_stack_location *sl;
	device_t dev = dobj->devext;

	sl = IoGetCurrentIrpStackLocation(ip);
	device_printf(dev, "invalid I/O dispatch %d:%d\n", sl->major,
	    sl->minor);

	ip->iostat.u.status = NDIS_STATUS_FAILURE;
	ip->iostat.info = 0;

	IoCompleteRequest(ip, IO_NO_INCREMENT);

	return (NDIS_STATUS_FAILURE);
}

static int32_t
usbd_pnp(struct device_object *dobj, struct irp *ip)
{
	struct io_stack_location *sl;
	device_t dev = dobj->devext;

	sl = IoGetCurrentIrpStackLocation(ip);
	device_printf(dev, "%s: unsupported I/O dispatch %d:%d\n",
	    __func__, sl->major, sl->minor);

	ip->iostat.u.status = NDIS_STATUS_FAILURE;
	ip->iostat.info = 0;

	IoCompleteRequest(ip, IO_NO_INCREMENT);

	return (NDIS_STATUS_FAILURE);
}

static int32_t
usbd_power(struct device_object *dobj, struct irp *ip)
{
	struct io_stack_location *sl;
	device_t dev = dobj->devext;

	sl = IoGetCurrentIrpStackLocation(ip);
	device_printf(dev, "%s: unsupported I/O dispatch %d:%d\n",
	    __func__, sl->major, sl->minor);

	ip->iostat.u.status = NDIS_STATUS_FAILURE;
	ip->iostat.info = 0;

	IoCompleteRequest(ip, IO_NO_INCREMENT);

	return (NDIS_STATUS_FAILURE);
}

/* Convert USBD_STATUS to NTSTATUS  */
static int32_t
usbd_urb2nt(int32_t status)
{
	switch (status) {
	case USBD_STATUS_SUCCESS:
		return (NDIS_STATUS_SUCCESS);
	case USBD_STATUS_DEVICE_GONE:
		return (NDIS_STATUS_DEVICE_NOT_CONNECTED);
	case USBD_STATUS_PENDING:
		return (NDIS_STATUS_PENDING);
	case USBD_STATUS_NOT_SUPPORTED:
		return (NDIS_STATUS_NOT_IMPLEMENTED);
	case USBD_STATUS_NO_MEMORY:
		return (NDIS_STATUS_NO_MEMORY);
	case USBD_STATUS_REQUEST_FAILED:
		return (NDIS_STATUS_NOT_SUPPORTED);
	case USBD_STATUS_CANCELED:
		return (NDIS_STATUS_CANCELLED);
	default:
		break;
	}
	return (NDIS_STATUS_FAILURE);
}

/* Convert FreeBSD's usb_error_t to USBD_STATUS  */
static int32_t
usbd_usb2urb(int status)
{
	switch (status) {
	case USB_ERR_NORMAL_COMPLETION:
		return (USBD_STATUS_SUCCESS);
	case USB_ERR_PENDING_REQUESTS:
		return (USBD_STATUS_PENDING);
	case USB_ERR_TIMEOUT:
		return (USBD_STATUS_TIMEOUT);
	case USB_ERR_SHORT_XFER:
		return (USBD_STATUS_ERROR_SHORT_TRANSFER);
	case USB_ERR_IOERROR:
		return (USBD_STATUS_XACT_ERROR);
	case USB_ERR_NOMEM:
		return (USBD_STATUS_NO_MEMORY);
	case USB_ERR_INVAL:
		return (USBD_STATUS_REQUEST_FAILED);
	case USB_ERR_NOT_STARTED:
	case USB_ERR_TOO_DEEP:
	case USB_ERR_NO_POWER:
		return (USBD_STATUS_DEVICE_GONE);
	case USB_ERR_CANCELLED:
		return (USBD_STATUS_CANCELED);
	default:
		break;
	}
	return (USBD_STATUS_NOT_SUPPORTED);
}

static union usbd_urb *
usbd_geturb(struct irp *ip)
{
	struct io_stack_location *sl;

	sl = IoGetCurrentIrpStackLocation(ip);

	return (sl->parameters.others.arg1);
}

static int32_t
usbd_submit_urb(struct irp *ip)
{
	device_t dev;
	int32_t status;
	union usbd_urb *urb;

	dev = IRP_NDIS_DEV(ip);
	urb = usbd_geturb(ip);
	/*
	 * In a case of URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER,
	 * USBD_URB_STATUS(urb) would be set at callback functions like
	 * usbd_intr() or usbd_xfereof().
	 */
	switch (urb->uu_hdr.uuh_func) {
	case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
		status = usbd_func_bulkintr(ip);
		if (status != USBD_STATUS_SUCCESS &&
		    status != USBD_STATUS_PENDING)
			USBD_URB_STATUS(urb) = status;
		break;
	case URB_FUNCTION_VENDOR_DEVICE:
	case URB_FUNCTION_VENDOR_INTERFACE:
	case URB_FUNCTION_VENDOR_ENDPOINT:
	case URB_FUNCTION_VENDOR_OTHER:
	case URB_FUNCTION_CLASS_DEVICE:
	case URB_FUNCTION_CLASS_INTERFACE:
	case URB_FUNCTION_CLASS_ENDPOINT:
	case URB_FUNCTION_CLASS_OTHER:
		status = usbd_func_vendorclass(ip);
		USBD_URB_STATUS(urb) = status;
		break;
	case URB_FUNCTION_SELECT_CONFIGURATION:
		status = usbd_func_selconf(ip);
		USBD_URB_STATUS(urb) = status;
		break;
	case URB_FUNCTION_ABORT_PIPE:
		status = usbd_func_abort_pipe(ip);
		USBD_URB_STATUS(urb) = status;
		break;
	case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
		status = usbd_func_getdesc(ip);
		USBD_URB_STATUS(urb) = status;
		break;
	default:
		device_printf(dev, "func 0x%x isn't supported\n",
		    urb->uu_hdr.uuh_func);
		USBD_URB_STATUS(urb) = status = USBD_STATUS_NOT_SUPPORTED;
		break;
	}

	return (status);
}

static int32_t
usbd_func_getdesc(struct irp *ip)
{
#define	NDISUSB_GETDESC_MAXRETRIES 3
	device_t dev;
	struct ndis_softc *sc;
	struct usbd_urb_control_descriptor_request *ctldesc;
	usb_config_descriptor_t *cdp;
	usb_error_t status;
	uint32_t len;
	uint16_t actlen;
	union usbd_urb *urb;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);
	urb = usbd_geturb(ip);
	ctldesc = &urb->uu_ctldesc;
	if (ctldesc->ucd_desctype == UDESC_CONFIG) {
		/*
		 * The NDIS driver is not allowed to change the
		 * config! There is only one choice!
		 */
		cdp = usbd_get_config_descriptor(sc->ndisusb_dev);
		if (cdp == NULL) {
			status = USB_ERR_INVAL;
			goto exit;
		}
		if (cdp->bDescriptorType != UDESC_CONFIG) {
			device_printf(dev, "bad desc %d\n",
			    cdp->bDescriptorType);
			status = USB_ERR_INVAL;
			goto exit;
		}
		/* Get minimum length */
		len = min(UGETW(cdp->wTotalLength), ctldesc->ucd_trans_buflen);
		/* Copy out config descriptor */
		memcpy(ctldesc->ucd_trans_buf, cdp, len);
		/* Set actual length */
		actlen = len;
		status = USB_ERR_NORMAL_COMPLETION;
	} else {
		NDISUSB_LOCK(sc);
		status = usbd_req_get_desc(sc->ndisusb_dev, &sc->ndisusb_mtx,
		    &actlen, ctldesc->ucd_trans_buf, 2,
		    ctldesc->ucd_trans_buflen, ctldesc->ucd_langid,
		    ctldesc->ucd_desctype, ctldesc->ucd_idx,
		    NDISUSB_GETDESC_MAXRETRIES);
		NDISUSB_UNLOCK(sc);
	}
exit:
	if (status != USB_ERR_NORMAL_COMPLETION) {
		ctldesc->ucd_trans_buflen = 0;
		return (usbd_usb2urb(status));
	}
	ctldesc->ucd_trans_buflen = actlen;
	ip->iostat.info = actlen;

	return (USBD_STATUS_SUCCESS);
#undef NDISUSB_GETDESC_MAXRETRIES
}

static int32_t
usbd_func_selconf(struct irp *ip)
{
	device_t dev;
	struct ndis_softc *sc;
	struct usb_device *udev;
	struct usb_endpoint *ep = NULL;
	struct usbd_interface_information *intf;
	struct usbd_pipe_information *pipe;
	struct usbd_urb_select_configuration *selconf;
	union usbd_urb *urb;
	usb_config_descriptor_t *conf;
	usb_endpoint_descriptor_t *edesc;
	usb_error_t ret;
	int i, j;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);
	udev = sc->ndisusb_dev;
	urb = usbd_geturb(ip);

	selconf = &urb->uu_selconf;
	conf = selconf->usc_conf;
	if (conf == NULL) {
		device_printf(dev, "select configuration is NULL\n");
		return (usbd_usb2urb(USB_ERR_NORMAL_COMPLETION));
	}

	intf = &selconf->usc_intf;
	for (i = 0; i < conf->bNumInterface && intf->uii_len > 0; i++) {
		ret = usbd_set_alt_interface_index(udev,
		    intf->uii_intfnum, intf->uii_altset);
		if (ret != USB_ERR_NORMAL_COMPLETION && ret != USB_ERR_IN_USE) {
			device_printf(dev,
			    "setting alternate interface failed: %s\n",
			    usbd_errstr(ret));
			return (usbd_usb2urb(ret));
		}

		for (j = 0; (ep = usb_endpoint_foreach(udev, ep)); j++) {
			if (j >= intf->uii_numeps) {
				device_printf(dev,
				    "endpoint %d and above are ignored",
				    intf->uii_numeps);
				break;
			}
			edesc = ep->edesc;
			pipe = &intf->uii_pipes[j];
			pipe->upi_handle = edesc;
			pipe->upi_epaddr = edesc->bEndpointAddress;
			pipe->upi_maxpktsize = UGETW(edesc->wMaxPacketSize);
			pipe->upi_type = UE_GET_XFERTYPE(edesc->bmAttributes);

			ret = usbd_setup_endpoint(ip, intf->uii_intfnum, edesc);
			if (ret != USB_ERR_NORMAL_COMPLETION)
				return (usbd_usb2urb(ret));

			if (pipe->upi_type != UE_INTERRUPT)
				continue;

			/* XXX We're following linux USB's interval policy. */
			if (udev->speed == USB_SPEED_LOW)
				pipe->upi_interval = edesc->bInterval + 5;
			else if (udev->speed == USB_SPEED_FULL)
				pipe->upi_interval = edesc->bInterval;
			else {
				int k0 = 0, k1 = 1;
				do {
					k1 = k1 * 2;
					k0 = k0 + 1;
				} while (k1 < edesc->bInterval);
				pipe->upi_interval = k0;
			}
		}

		intf = (struct usbd_interface_information *)(((char *)intf) +
		    intf->uii_len);
	}

	return (USBD_STATUS_SUCCESS);
}

static usb_error_t
usbd_setup_endpoint_one(struct irp *ip, uint8_t ifidx, struct ndisusb_ep *ne,
    struct usb_config *epconf)
{
	device_t dev;
	struct ndis_softc *sc;
	struct usb_xfer *xfer;
	usb_error_t status;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);

	InitializeListHead(&ne->ne_active);
	InitializeListHead(&ne->ne_pending);
	KeInitializeSpinLock(&ne->ne_lock);

	status = usbd_transfer_setup(sc->ndisusb_dev, &ifidx, ne->ne_xfer,
	    epconf, 1, sc, &sc->ndisusb_mtx);
	if (status != USB_ERR_NORMAL_COMPLETION) {
		device_printf(dev, "couldn't setup xfer: %s\n",
		    usbd_errstr(status));
		return (status);
	}
	xfer = ne->ne_xfer[0];
	usbd_xfer_set_priv(xfer, ne);

	return (status);
}

static usb_error_t
usbd_setup_endpoint_default(struct irp *ip, uint8_t ifidx)
{
	device_t dev;
	struct ndis_softc *sc;
	usb_error_t status;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);

	if (ifidx > 0)
		device_printf(dev, "warning: ifidx > 0 isn't supported.\n");

	status = usbd_setup_endpoint_one(ip, ifidx, &sc->ndisusb_dread_ep,
	    &usbd_default_epconfig[USBD_CTRL_READ_PIPE]);
	if (status != USB_ERR_NORMAL_COMPLETION)
		return (status);

	status = usbd_setup_endpoint_one(ip, ifidx, &sc->ndisusb_dwrite_ep,
	    &usbd_default_epconfig[USBD_CTRL_WRITE_PIPE]);

	return (status);
}

static usb_error_t
usbd_setup_endpoint(struct irp *ip, uint8_t ifidx,
    struct usb_endpoint_descriptor *ep)
{
	device_t dev;
	struct ndis_softc *sc;
	struct ndisusb_ep *ne;
	struct usb_config cfg;
	struct usb_xfer *xfer;
	usb_error_t status;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);

	/* Check for non-supported transfer types */
	if (UE_GET_XFERTYPE(ep->bmAttributes) == UE_CONTROL ||
	    UE_GET_XFERTYPE(ep->bmAttributes) == UE_ISOCHRONOUS) {
		device_printf(dev, "%s: unsuppotted transfer types %#x\n",
		    __func__, UE_GET_XFERTYPE(ep->bmAttributes));
		return (USB_ERR_INVAL);
	}

	ne = &sc->ndisusb_ep[NDISUSB_GET_ENDPT(ep->bEndpointAddress)];
	InitializeListHead(&ne->ne_active);
	InitializeListHead(&ne->ne_pending);
	KeInitializeSpinLock(&ne->ne_lock);
	ne->ne_dirin = UE_GET_DIR(ep->bEndpointAddress) >> 7;

	memset(&cfg, 0, sizeof(struct usb_config));
	cfg.type	= UE_GET_XFERTYPE(ep->bmAttributes);
	cfg.endpoint	= UE_GET_ADDR(ep->bEndpointAddress);
	cfg.direction	= UE_GET_DIR(ep->bEndpointAddress);
	cfg.callback	= &usbd_non_isoc_callback;
	cfg.bufsize	= UGETW(ep->wMaxPacketSize);
	cfg.flags.proxy_buffer = 1;
	if (UE_GET_DIR(ep->bEndpointAddress) == UE_DIR_IN)
		cfg.flags.short_xfer_ok = 1;

	status = usbd_transfer_setup(sc->ndisusb_dev, &ifidx, ne->ne_xfer,
	    &cfg, 1, sc, &sc->ndisusb_mtx);
	if (status != USB_ERR_NORMAL_COMPLETION) {
		device_printf(dev, "couldn't setup xfer: %s\n",
		    usbd_errstr(status));
		return (status);
	}
	xfer = ne->ne_xfer[0];
	usbd_xfer_set_priv(xfer, ne);
	if (UE_GET_DIR(ep->bEndpointAddress) == UE_DIR_IN)
		usbd_xfer_set_timeout(xfer, NDISUSB_NO_TIMEOUT);
	else {
		if (UE_GET_XFERTYPE(ep->bmAttributes) == UE_BULK)
			usbd_xfer_set_timeout(xfer, NDISUSB_TX_TIMEOUT);
		else
			usbd_xfer_set_timeout(xfer, NDISUSB_INTR_TIMEOUT);
	}

	return (status);
}

static int32_t
usbd_func_abort_pipe(struct irp *ip)
{
	device_t dev;
	struct ndis_softc *sc;
	struct ndisusb_ep *ne;
	union usbd_urb *urb;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);

	urb = usbd_geturb(ip);
	ne = usbd_get_ndisep(ip, urb->uu_pipe.upr_handle);
	if (ne == NULL) {
		device_printf(IRP_NDIS_DEV(ip), "get NULL endpoint info.\n");
		return (USBD_STATUS_INVALID_PIPE_HANDLE);
	}

	NDISUSB_LOCK(sc);
	usbd_transfer_stop(ne->ne_xfer[0]);
	usbd_transfer_start(ne->ne_xfer[0]);
	NDISUSB_UNLOCK(sc);

	return (USBD_STATUS_SUCCESS);
}

static int32_t
usbd_func_vendorclass(struct irp *ip)
{
	device_t dev;
	struct ndis_softc *sc;
	struct ndisusb_ep *ne;
	struct ndisusb_xfer *nx;
	struct usbd_urb_vendor_or_class_request *vcreq;
	int32_t error;
	union usbd_urb *urb;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);
	if (!(sc->ndisusb_status & NDISUSB_STATUS_SETUP_EP)) {
		/*
		 * XXX In some cases the interface number isn't 0.  However
		 * some driver (eg. RTL8187L NDIS driver) calls this function
		 * before calling URB_FUNCTION_SELECT_CONFIGURATION.
		 */
		error = usbd_setup_endpoint_default(ip, 0);
		if (error != USB_ERR_NORMAL_COMPLETION)
			return (usbd_usb2urb(error));
		sc->ndisusb_status |= NDISUSB_STATUS_SETUP_EP;
	}

	urb = usbd_geturb(ip);
	vcreq = &urb->uu_vcreq;
	ne = (vcreq->uvc_trans_flags & USBD_TRANSFER_DIRECTION_IN) ?
	    &sc->ndisusb_dread_ep : &sc->ndisusb_dwrite_ep;
	IRP_NDISUSB_EP(ip) = ne;
	ip->cancelfunc = (cancel_func)usbd_irpcancel_wrap;

	nx = malloc(sizeof(struct ndisusb_xfer), M_USBDEV, M_NOWAIT|M_ZERO);
	if (nx == NULL) {
		device_printf(IRP_NDIS_DEV(ip), "out of memory\n");
		return (USBD_STATUS_NO_MEMORY);
	}
	nx->nx_ep = ne;
	nx->nx_priv = ip;
	KeAcquireSpinLockAtDpcLevel(&ne->ne_lock);
	InsertTailList((&ne->ne_pending), (&nx->nx_next));
	KeReleaseSpinLockFromDpcLevel(&ne->ne_lock);

	/* We've done to setup xfer.  Let's transfer it.  */
	ip->iostat.u.status = NDIS_STATUS_PENDING;
	ip->iostat.info = 0;
	USBD_URB_STATUS(urb) = USBD_STATUS_PENDING;
	IoMarkIrpPending(ip);

	error = usbd_taskadd(ip, NDISUSB_TASK_VENDOR);
	if (error != USBD_STATUS_SUCCESS)
		return (error);

	return (USBD_STATUS_PENDING);
}

static void
usbd_irpcancel(struct device_object *dobj, struct irp *ip)
{
	device_t dev;
	struct ndis_softc *sc;
	struct ndisusb_ep *ne;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);

	ne = IRP_NDISUSB_EP(ip);
	if (ne == NULL) {
		ip->cancel = TRUE;
		IoReleaseCancelSpinLock(ip->cancelirql);
		return;
	}

	/*
	 * Make sure that the current USB transfer proxy is
	 * cancelled and then restarted.
	 */
	NDISUSB_LOCK(sc);
	usbd_transfer_stop(ne->ne_xfer[0]);
	usbd_transfer_start(ne->ne_xfer[0]);
	NDISUSB_UNLOCK(sc);

	ip->cancel = TRUE;
	IoReleaseCancelSpinLock(ip->cancelirql);
}

static void
usbd_xfer_complete(struct ndis_softc *sc, struct ndisusb_ep *ne,
    struct ndisusb_xfer *nx, usb_error_t status)
{
	struct ndisusb_xferdone *nd;
	uint8_t irql;

	nd = malloc(sizeof(struct ndisusb_xferdone),
	    M_USBDEV, M_NOWAIT|M_ZERO);
	if (nd == NULL) {
		device_printf(sc->ndis_dev, "out of memory\n");
		return;
	}
	nd->nd_xfer = nx;
	nd->nd_status = status;

	KeAcquireSpinLock(&sc->ndisusb_xferdonelock, &irql);
	InsertTailList((&sc->ndisusb_xferdonelist), (&nd->nd_donelist));
	KeReleaseSpinLock(&sc->ndisusb_xferdonelock, irql);

	IoQueueWorkItem(sc->ndisusb_xferdoneitem,
	    (io_workitem_func)usbd_xfertask_wrap, CRITICAL, sc);
}

static struct ndisusb_xfer *
usbd_aq_getfirst(struct ndis_softc *sc, struct ndisusb_ep *ne)
{
	struct ndisusb_xfer *nx;

	KeAcquireSpinLockAtDpcLevel(&ne->ne_lock);
	if (IsListEmpty(&ne->ne_active)) {
		device_printf(sc->ndis_dev,
		    "%s: the active queue can't be empty.\n", __func__);
		KeReleaseSpinLockFromDpcLevel(&ne->ne_lock);
		return (NULL);
	}
	nx = CONTAINING_RECORD(ne->ne_active.flink, struct ndisusb_xfer,
	    nx_next);
	RemoveEntryList(&nx->nx_next);
	KeReleaseSpinLockFromDpcLevel(&ne->ne_lock);

	return (nx);
}

static void
usbd_non_isoc_callback(struct usb_xfer *xfer, usb_error_t error)
{
	struct ndis_softc *sc;
	struct ndisusb_ep *ne;
	struct ndisusb_xfer *nx;
	struct usbd_urb_bulk_or_intr_transfer *ubi;
	struct usb_page_cache *pc;
	struct irp *ip;
	usb_endpoint_descriptor_t *ep;
	uint32_t len;
	uint8_t irql;
	union usbd_urb *urb;
	int actlen, sumlen;

	sc = usbd_xfer_softc(xfer);
	ne = usbd_xfer_get_priv(xfer);
	usbd_xfer_status(xfer, &actlen, &sumlen, NULL, NULL);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		nx = usbd_aq_getfirst(sc, ne);
		pc = usbd_xfer_get_frame(xfer, 0);
		if (nx == NULL)
			return;

		/* Copy in data with regard to the URB */
		if (ne->ne_dirin != 0)
			usbd_copy_out(pc, 0, nx->nx_urbbuf, actlen);
		nx->nx_urbbuf += actlen;
		nx->nx_urbactlen += actlen;
		nx->nx_urblen -= actlen;

		/* Check for short transfer */
		if (actlen < sumlen)
			nx->nx_urblen = 0;
		else {
			/* Check remainder */
			if (nx->nx_urblen > 0) {
				KeAcquireSpinLock(&ne->ne_lock, &irql);
				InsertHeadList((&ne->ne_active), (&nx->nx_next));
				KeReleaseSpinLock(&ne->ne_lock, irql);

				ip = nx->nx_priv;
				urb = usbd_geturb(ip);
				ubi = &urb->uu_bulkintr;
				ep = ubi->ubi_epdesc;
				goto extra;
			}
		}
		usbd_xfer_complete(sc, ne, nx,
		    ((actlen < sumlen) && (nx->nx_shortxfer == 0)) ?
		    USB_ERR_SHORT_XFER : USB_ERR_NORMAL_COMPLETION);
		/* fall through */
	case USB_ST_SETUP:
next:
		/* Get next transfer */
		KeAcquireSpinLock(&ne->ne_lock, &irql);
		if (IsListEmpty(&ne->ne_pending)) {
			KeReleaseSpinLock(&ne->ne_lock, irql);
			return;
		}
		nx = CONTAINING_RECORD(ne->ne_pending.flink,
		    struct ndisusb_xfer, nx_next);
		RemoveEntryList(&nx->nx_next);
		/* Add a entry to the active queue's tail.  */
		InsertTailList((&ne->ne_active), (&nx->nx_next));
		KeReleaseSpinLock(&ne->ne_lock, irql);

		ip = nx->nx_priv;
		urb = usbd_geturb(ip);
		ubi = &urb->uu_bulkintr;
		ep = ubi->ubi_epdesc;

		nx->nx_urbbuf = ubi->ubi_trans_buf;
		nx->nx_urbactlen = 0;
		nx->nx_urblen = ubi->ubi_trans_buflen;
		nx->nx_shortxfer = (ubi->ubi_trans_flags &
		    USBD_SHORT_TRANSFER_OK) ? 1 : 0;
extra:
		len = min(usbd_xfer_max_len(xfer), nx->nx_urblen);
		pc = usbd_xfer_get_frame(xfer, 0);
		if (UE_GET_DIR(ep->bEndpointAddress) == UE_DIR_OUT)
			usbd_copy_in(pc, 0, nx->nx_urbbuf, len);
		usbd_xfer_set_frame_len(xfer, 0, len);
		usbd_xfer_set_frames(xfer, 1);
		usbd_transfer_submit(xfer);
		break;
	default:
		nx = usbd_aq_getfirst(sc, ne);
		if (nx == NULL)
			return;
		if (error != USB_ERR_CANCELLED) {
			usbd_xfer_set_stall(xfer);
			device_printf(sc->ndis_dev, "usb xfer warning (%s)\n",
			    usbd_errstr(error));
		}
		usbd_xfer_complete(sc, ne, nx, error);
		if (error != USB_ERR_CANCELLED)
			goto next;
		break;
	}
}

static void
usbd_ctrl_callback(struct usb_xfer *xfer, usb_error_t error)
{
	struct irp *ip;
	struct ndis_softc *sc;
	struct ndisusb_ep *ne;
	struct ndisusb_xfer *nx;
	struct usbd_urb_vendor_or_class_request *vcreq;
	struct usb_page_cache *pc;
	struct usb_device_request req;
	uint8_t type = 0, irql;
	union usbd_urb *urb;
	int len;

	sc = usbd_xfer_softc(xfer);
	ne = usbd_xfer_get_priv(xfer);

	switch (USB_GET_STATE(xfer)) {
	case USB_ST_TRANSFERRED:
		nx = usbd_aq_getfirst(sc, ne);
		if (nx == NULL)
			return;

		ip = nx->nx_priv;
		urb = usbd_geturb(ip);
		vcreq = &urb->uu_vcreq;

		if (vcreq->uvc_trans_flags & USBD_TRANSFER_DIRECTION_IN) {
			pc = usbd_xfer_get_frame(xfer, 1);
			len = usbd_xfer_frame_len(xfer, 1);
			usbd_copy_out(pc, 0, vcreq->uvc_trans_buf, len);
			nx->nx_urbactlen += len;
		}

		usbd_xfer_complete(sc, ne, nx, USB_ERR_NORMAL_COMPLETION);
		/* fall through */
	case USB_ST_SETUP:
next:
		/* Get next transfer */
		KeAcquireSpinLock(&ne->ne_lock, &irql);
		if (IsListEmpty(&ne->ne_pending)) {
			KeReleaseSpinLock(&ne->ne_lock, irql);
			return;
		}
		nx = CONTAINING_RECORD(ne->ne_pending.flink,
		    struct ndisusb_xfer, nx_next);
		RemoveEntryList(&nx->nx_next);
		/* Add a entry to the active queue's tail.  */
		InsertTailList((&ne->ne_active), (&nx->nx_next));
		KeReleaseSpinLock(&ne->ne_lock, irql);

		ip = nx->nx_priv;
		urb = usbd_geturb(ip);
		vcreq = &urb->uu_vcreq;

		switch (urb->uu_hdr.uuh_func) {
		case URB_FUNCTION_CLASS_DEVICE:
			type = UT_CLASS|UT_DEVICE;
			break;
		case URB_FUNCTION_CLASS_INTERFACE:
			type = UT_CLASS|UT_INTERFACE;
			break;
		case URB_FUNCTION_CLASS_OTHER:
			type = UT_CLASS|UT_OTHER;
			break;
		case URB_FUNCTION_CLASS_ENDPOINT:
			type = UT_CLASS|UT_ENDPOINT;
			break;
		case URB_FUNCTION_VENDOR_DEVICE:
			type = UT_VENDOR|UT_DEVICE;
			break;
		case URB_FUNCTION_VENDOR_INTERFACE:
			type = UT_VENDOR|UT_INTERFACE;
			break;
		case URB_FUNCTION_VENDOR_OTHER:
			type = UT_VENDOR|UT_OTHER;
			break;
		case URB_FUNCTION_VENDOR_ENDPOINT:
			type = UT_VENDOR|UT_ENDPOINT;
			break;
		default:
			/* not reached. */
			break;
		}

		type |= (vcreq->uvc_trans_flags & USBD_TRANSFER_DIRECTION_IN) ?
		    UT_READ : UT_WRITE;
		type |= vcreq->uvc_reserved1;

		req.bmRequestType = type;
		req.bRequest = vcreq->uvc_req;
		USETW(req.wIndex, vcreq->uvc_idx);
		USETW(req.wValue, vcreq->uvc_value);
		USETW(req.wLength, vcreq->uvc_trans_buflen);

		nx->nx_urbbuf = vcreq->uvc_trans_buf;
		nx->nx_urblen = vcreq->uvc_trans_buflen;
		nx->nx_urbactlen = 0;

		pc = usbd_xfer_get_frame(xfer, 0);
		usbd_copy_in(pc, 0, &req, sizeof(req));
		usbd_xfer_set_frame_len(xfer, 0, sizeof(req));
		usbd_xfer_set_frames(xfer, 1);
		if (vcreq->uvc_trans_flags & USBD_TRANSFER_DIRECTION_IN) {
			if (vcreq->uvc_trans_buflen >= USBD_CTRL_READ_BUFFER_SP)
				device_printf(sc->ndis_dev,
				    "warning: not enough buffer space (%d).\n",
				    vcreq->uvc_trans_buflen);
			usbd_xfer_set_frame_len(xfer, 1,
			    min(usbd_xfer_max_len(xfer),
				    vcreq->uvc_trans_buflen));
			usbd_xfer_set_frames(xfer, 2);
		} else {
			if (nx->nx_urblen > USBD_CTRL_WRITE_BUFFER_SP)
				device_printf(sc->ndis_dev,
				    "warning: not enough write buffer space"
				    " (%d).\n", nx->nx_urblen);
			/*
			 * XXX With my local tests there was no cases to
			 * require a extra buffer until now but it'd need
			 * to update in the future if it needs to be.
			 */
			if (nx->nx_urblen > 0) {
				pc = usbd_xfer_get_frame(xfer, 1);
				usbd_copy_in(pc, 0, nx->nx_urbbuf,
				    nx->nx_urblen);
				usbd_xfer_set_frame_len(xfer, 1, nx->nx_urblen);
				usbd_xfer_set_frames(xfer, 2);
			}
		}
		usbd_transfer_submit(xfer);
		break;
	default:
		nx = usbd_aq_getfirst(sc, ne);
		if (nx == NULL)
			return;
		if (error != USB_ERR_CANCELLED) {
			usbd_xfer_set_stall(xfer);
			device_printf(sc->ndis_dev, "usb xfer warning (%s)\n",
			    usbd_errstr(error));
		}
		usbd_xfer_complete(sc, ne, nx, error);
		if (error != USB_ERR_CANCELLED)
			goto next;
		break;
	}
}

static struct ndisusb_ep *
usbd_get_ndisep(struct irp *ip, usb_endpoint_descriptor_t *ep)
{
	device_t dev;
	struct ndis_softc *sc;
	struct ndisusb_ep *ne;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);
	ne = &sc->ndisusb_ep[NDISUSB_GET_ENDPT(ep->bEndpointAddress)];

	IRP_NDISUSB_EP(ip) = ne;
	ip->cancelfunc = (cancel_func)usbd_irpcancel_wrap;

	return (ne);
}

static void
usbd_xfertask(struct device_object *dobj, struct ndis_softc *sc)
{
	struct irp *ip;
	device_t dev;
	struct list_entry *l;
	struct ndisusb_xferdone *nd;
	struct ndisusb_xfer *nq;
	struct usbd_urb_bulk_or_intr_transfer *ubi;
	struct usbd_urb_vendor_or_class_request *vcreq;
	union usbd_urb *urb;
	usb_error_t status;
	void *priv;
	int error;

	dev = sc->ndis_dev;

	if (IsListEmpty(&sc->ndisusb_xferdonelist))
		return;

	KeAcquireSpinLockAtDpcLevel(&sc->ndisusb_xferdonelock);
	l = sc->ndisusb_xferdonelist.flink;
	while (l != &sc->ndisusb_xferdonelist) {
		nd = CONTAINING_RECORD(l, struct ndisusb_xferdone, nd_donelist);
		nq = nd->nd_xfer;
		priv = nq->nx_priv;
		status = nd->nd_status;
		error = 0;
		ip = priv;
		urb = usbd_geturb(ip);

		ip->cancelfunc = NULL;
		IRP_NDISUSB_EP(ip) = NULL;

		switch (status) {
		case USB_ERR_NORMAL_COMPLETION:
			if (urb->uu_hdr.uuh_func ==
			    URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER) {
				ubi = &urb->uu_bulkintr;
				ubi->ubi_trans_buflen = nq->nx_urbactlen;
			} else {
				vcreq = &urb->uu_vcreq;
				vcreq->uvc_trans_buflen = nq->nx_urbactlen;
			}
			ip->iostat.info = nq->nx_urbactlen;
			ip->iostat.u.status = NDIS_STATUS_SUCCESS;
			USBD_URB_STATUS(urb) = USBD_STATUS_SUCCESS;
			break;
		case USB_ERR_CANCELLED:
			ip->iostat.info = 0;
			ip->iostat.u.status = NDIS_STATUS_CANCELLED;
			USBD_URB_STATUS(urb) = USBD_STATUS_CANCELED;
			break;
		default:
			ip->iostat.info = 0;
			USBD_URB_STATUS(urb) = usbd_usb2urb(status);
			ip->iostat.u.status =
			    usbd_urb2nt(USBD_URB_STATUS(urb));
			break;
		}

		l = l->flink;
		RemoveEntryList(&nd->nd_donelist);
		free(nq, M_USBDEV);
		free(nd, M_USBDEV);
		if (error)
			continue;
		KeReleaseSpinLockFromDpcLevel(&sc->ndisusb_xferdonelock);
		/* NB: call after cleaning  */
		IoCompleteRequest(ip, IO_NO_INCREMENT);
		KeAcquireSpinLockAtDpcLevel(&sc->ndisusb_xferdonelock);
	}
	KeReleaseSpinLockFromDpcLevel(&sc->ndisusb_xferdonelock);
}

/*
 * This function is for mainly deferring a task to the another thread because
 * we don't want to be in the scope of HAL lock.
 */
static int32_t
usbd_taskadd(struct irp *ip, unsigned type)
{
	device_t dev;
	struct ndis_softc *sc;
	struct ndisusb_task *nt;

	dev = IRP_NDIS_DEV(ip);
	sc = device_get_softc(dev);

	nt = malloc(sizeof(struct ndisusb_task), M_USBDEV, M_NOWAIT|M_ZERO);
	if (nt == NULL)
		return (USBD_STATUS_NO_MEMORY);
	nt->nt_type = type;
	nt->nt_ctx = ip;

	KeAcquireSpinLockAtDpcLevel(&sc->ndisusb_tasklock);
	InsertTailList((&sc->ndisusb_tasklist), (&nt->nt_tasklist));
	KeReleaseSpinLockFromDpcLevel(&sc->ndisusb_tasklock);

	IoQueueWorkItem(sc->ndisusb_taskitem,
	    (io_workitem_func)usbd_task_wrap, CRITICAL, sc);

	return (USBD_STATUS_SUCCESS);
}

static void
usbd_task(struct device_object *dobj, struct ndis_softc *sc)
{
	struct irp *ip;
	struct list_entry *l;
	struct ndisusb_ep *ne;
	struct ndisusb_task *nt;
	union usbd_urb *urb;

	if (IsListEmpty(&sc->ndisusb_tasklist))
		return;

	KeAcquireSpinLockAtDpcLevel(&sc->ndisusb_tasklock);
	l = sc->ndisusb_tasklist.flink;
	while (l != &sc->ndisusb_tasklist) {
		nt = CONTAINING_RECORD(l, struct ndisusb_task, nt_tasklist);

		ip = nt->nt_ctx;
		urb = usbd_geturb(ip);

		KeReleaseSpinLockFromDpcLevel(&sc->ndisusb_tasklock);
		NDISUSB_LOCK(sc);
		switch (nt->nt_type) {
		case NDISUSB_TASK_TSTART:
			ne = usbd_get_ndisep(ip, urb->uu_bulkintr.ubi_epdesc);
			if (ne == NULL)
				goto exit;
			usbd_transfer_start(ne->ne_xfer[0]);
			break;
		case NDISUSB_TASK_IRPCANCEL:
			ne = usbd_get_ndisep(ip,
			    (nt->nt_type == NDISUSB_TASK_IRPCANCEL) ?
			    urb->uu_bulkintr.ubi_epdesc :
			    urb->uu_pipe.upr_handle);
			if (ne == NULL)
				goto exit;
			
			usbd_transfer_stop(ne->ne_xfer[0]);
			usbd_transfer_start(ne->ne_xfer[0]);
			break;
		case NDISUSB_TASK_VENDOR:
			ne = (urb->uu_vcreq.uvc_trans_flags &
			    USBD_TRANSFER_DIRECTION_IN) ?
			    &sc->ndisusb_dread_ep : &sc->ndisusb_dwrite_ep;
			usbd_transfer_start(ne->ne_xfer[0]);
			break;
		default:
			break;
		}
exit:
		NDISUSB_UNLOCK(sc);
		KeAcquireSpinLockAtDpcLevel(&sc->ndisusb_tasklock);

		l = l->flink;
		RemoveEntryList(&nt->nt_tasklist);
		free(nt, M_USBDEV);
	}
	KeReleaseSpinLockFromDpcLevel(&sc->ndisusb_tasklock);
}

static int32_t
usbd_func_bulkintr(struct irp *ip)
{
	int32_t error;
	struct ndisusb_ep *ne;
	struct ndisusb_xfer *nx;
	struct usbd_urb_bulk_or_intr_transfer *ubi;
	union usbd_urb *urb;
	usb_endpoint_descriptor_t *ep;

	urb = usbd_geturb(ip);
	ubi = &urb->uu_bulkintr;
	ep = ubi->ubi_epdesc;
	if (ep == NULL)
		return (USBD_STATUS_INVALID_PIPE_HANDLE);

	ne = usbd_get_ndisep(ip, ep);
	if (ne == NULL) {
		device_printf(IRP_NDIS_DEV(ip), "get NULL endpoint info.\n");
		return (USBD_STATUS_INVALID_PIPE_HANDLE);
	}

	nx = malloc(sizeof(struct ndisusb_xfer), M_USBDEV, M_NOWAIT|M_ZERO);
	if (nx == NULL) {
		device_printf(IRP_NDIS_DEV(ip), "out of memory\n");
		return (USBD_STATUS_NO_MEMORY);
	}
	nx->nx_ep = ne;
	nx->nx_priv = ip;
	KeAcquireSpinLockAtDpcLevel(&ne->ne_lock);
	InsertTailList((&ne->ne_pending), (&nx->nx_next));
	KeReleaseSpinLockFromDpcLevel(&ne->ne_lock);

	/* We've done to setup xfer.  Let's transfer it.  */
	ip->iostat.u.status = NDIS_STATUS_PENDING;
	ip->iostat.info = 0;
	USBD_URB_STATUS(urb) = USBD_STATUS_PENDING;
	IoMarkIrpPending(ip);

	error = usbd_taskadd(ip, NDISUSB_TASK_TSTART);
	if (error != USBD_STATUS_SUCCESS)
		return (error);

	return (USBD_STATUS_PENDING);
}

static union usbd_urb *
USBD_CreateConfigurationRequest(usb_config_descriptor_t *conf, uint16_t *len)
{
	struct usbd_interface_list_entry list[2];
	union usbd_urb *urb;

	memset(list, 0, sizeof(struct usbd_interface_list_entry) * 2);
	list[0].uil_intfdesc = USBD_ParseConfigurationDescriptorEx(conf, conf,
	    -1, -1, -1, -1, -1);

	urb = USBD_CreateConfigurationRequestEx(conf, list);
	if (urb == NULL)
		return (NULL);

	*len = urb->uu_selconf.usc_hdr.uuh_len;

	return (urb);
}

static union usbd_urb *
USBD_CreateConfigurationRequestEx(usb_config_descriptor_t *conf,
    struct usbd_interface_list_entry *list)
{
	int i, j, size;
	struct usbd_interface_information *intf;
	struct usbd_pipe_information *pipe;
	struct usbd_urb_select_configuration *selconf;
	usb_interface_descriptor_t *desc;

	for (i = 0, size = 0; i < conf->bNumInterface; i++) {
		j = list[i].uil_intfdesc->bNumEndpoints;
		size = size + sizeof(struct usbd_interface_information) +
		    sizeof(struct usbd_pipe_information) * (j - 1);
	}
	size += sizeof(struct usbd_urb_select_configuration) -
	    sizeof(struct usbd_interface_information);

	selconf = ExAllocatePool(size);
	if (selconf == NULL)
		return (NULL);
	selconf->usc_hdr.uuh_func = URB_FUNCTION_SELECT_CONFIGURATION;
	selconf->usc_hdr.uuh_len = size;
	selconf->usc_handle = conf;
	selconf->usc_conf = conf;

	intf = &selconf->usc_intf;
	for (i = 0; i < conf->bNumInterface; i++) {
		if (list[i].uil_intfdesc == NULL)
			break;

		list[i].uil_intf = intf;
		desc = list[i].uil_intfdesc;

		intf->uii_len = sizeof(struct usbd_interface_information) +
		    (desc->bNumEndpoints - 1) *
		    sizeof(struct usbd_pipe_information);
		intf->uii_intfnum = desc->bInterfaceNumber;
		intf->uii_altset = desc->bAlternateSetting;
		intf->uii_intfclass = desc->bInterfaceClass;
		intf->uii_intfsubclass = desc->bInterfaceSubClass;
		intf->uii_intfproto = desc->bInterfaceProtocol;
		intf->uii_handle = desc;
		intf->uii_numeps = desc->bNumEndpoints;

		pipe = &intf->uii_pipes[0];
		for (j = 0; j < intf->uii_numeps; j++)
			pipe[j].upi_maxtxsize =
			    USBD_DEFAULT_MAXIMUM_TRANSFER_SIZE;

		intf = (struct usbd_interface_information *)((char *)intf +
		    intf->uii_len);
	}

	return ((union usbd_urb *)selconf);
}

static void
USBD_GetUSBDIVersion(struct usbd_version_info *ui)
{

	/* Pretend to be Windows XP. */
	ui->uvi_usbdi_vers = USBDI_VERSION;
	ui->uvi_supported_vers = USB_VER_2_0;
}

static usb_interface_descriptor_t *
USBD_ParseConfigurationDescriptor(usb_config_descriptor_t *conf,
    uint8_t intfnum, uint8_t altset)
{

	return (USBD_ParseConfigurationDescriptorEx(conf, conf, intfnum,
	    altset, -1, -1, -1));
}

static usb_interface_descriptor_t *
USBD_ParseConfigurationDescriptorEx(usb_config_descriptor_t *conf,
    void *start, int32_t intfnum, int32_t altset, int32_t intfclass,
    int32_t intfsubclass, int32_t intfproto)
{
	struct usb_descriptor *next = NULL;
	usb_interface_descriptor_t *desc;

	while ((next = usb_desc_foreach(conf, next)) != NULL) {
		desc = (usb_interface_descriptor_t *)next;
		if (desc->bDescriptorType != UDESC_INTERFACE)
			continue;
		if (!(intfnum == -1 || desc->bInterfaceNumber == intfnum))
			continue;
		if (!(altset == -1 || desc->bAlternateSetting == altset))
			continue;
		if (!(intfclass == -1 || desc->bInterfaceClass == intfclass))
			continue;
		if (!(intfsubclass == -1 ||
		    desc->bInterfaceSubClass == intfsubclass))
			continue;
		if (!(intfproto == -1 ||
		    desc->bInterfaceProtocol == intfproto))
			continue;
		return (desc);
	}

	return (NULL);
}

static void
dummy(void)
{
	printf("usbd dummy called...\n");
}

struct image_patch_table usbd_functbl[] = {
	IMPORT_SFUNC(USBD_CreateConfigurationRequest, 2),
	IMPORT_SFUNC(USBD_CreateConfigurationRequestEx, 2),
	IMPORT_SFUNC(USBD_GetUSBDIVersion, 1),
	IMPORT_SFUNC(USBD_ParseConfigurationDescriptor, 3),
	IMPORT_SFUNC(USBD_ParseConfigurationDescriptorEx, 7),
	IMPORT_SFUNC_MAP(_USBD_CreateConfigurationRequestEx@8,
	    USBD_CreateConfigurationRequestEx, 2),
	IMPORT_SFUNC_MAP(_USBD_ParseConfigurationDescriptorEx@28,
	    USBD_ParseConfigurationDescriptorEx, 7),
	{ NULL, (FUNC)dummy, NULL, 0, STDCALL },
	{ NULL, NULL, NULL }
};

MODULE_DEPEND(ndis, usb, 1, 1, 1);
