# $FreeBSD$

.PATH: ${.CURDIR}/../../compat/ndis
.PATH: ${.CURDIR}/../../dev/if_ndis

KMOD=	ndis
SRCS=	subr_pe.c subr_ndis.c subr_hal.c subr_ntoskrnl.c kern_ndis.c
SRCS+=	kern_windrv.c subr_usbd.c
SRCS+=	device_if.h bus_if.h pci_if.h vnode_if.h opt_usb.h
SRCS+=	winx_wrap.S
SRCS+=	if_ndis.c if_ndis_pci.c if_ndis_pccard.c if_ndis_usb.c
SRCS+=	device_if.h bus_if.h pci_if.h card_if.h
SRCS+=	opt_usb.h opt_ndis.h opt_wlan.h

CFLAGS+=-I${.CURDIR}/../../../sys/dev/if_ndis
CFLAGS+=-I${.CURDIR}/../../../sys/compat/ndis

WERROR=

.include <bsd.kmod.mk>
