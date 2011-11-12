# $FreeBSD$

.PATH:	${.CURDIR}/../../sys/compat/ndis

PROG=	ndisload
SRCS=	ndisload.c

MAN=	ndisload.8

DPADD=  ${LIBL}
LDADD=  -ll

CFLAGS+=-I. -I${.CURDIR} -I${.CURDIR}/../../sys/compat/ndis

.include <bsd.prog.mk>
