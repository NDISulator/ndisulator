# $FreeBSD$

.PATH: ${.CURDIR}/../../dev/if_ndis

KMOD=	if_ndis
SRCS=	if_ndis.c if_ndis_pci.c if_ndis_pccard.c if_ndis_usb.c
SRCS+=	device_if.h bus_if.h pci_if.h card_if.h pccarddevs.h
SRCS+=	usbdevs.h opt_usb.h usb_if.h opt_ndis.h opt_wlan.h

.include <bsd.kmod.mk>
