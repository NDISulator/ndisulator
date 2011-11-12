# $FreeBSD$

.PATH:	${.CURDIR}/../../sys/compat/ndis

PROG=	ndisload
SRCS=	ndisload.c

DPADD=  ${LIBL}
LDADD=  -ll

CFLAGS+=-I. -I${.CURDIR} -I${.CURDIR}/../../sys/compat/ndis

.include <bsd.prog.mk>
