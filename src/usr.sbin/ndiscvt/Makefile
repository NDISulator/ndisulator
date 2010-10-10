# $FreeBSD$

.PATH:	${.CURDIR}/../../sys/compat/ndis

PROG=	ndiscvt
SRCS=	ndiscvt.c
SRCS+=	subr_pe.c
SRCS+=	inf.c inf-token.l inf-parse.y y.tab.h

MAN=	ndiscvt.8
MAN+=	ndisgen.8

DPADD=  ${LIBL}
LDADD=  -ll

YFLAGS+=-v

CFLAGS+=-I. -I${.CURDIR} -I${.CURDIR}/../../sys

CLEANFILES= y.output

SCRIPTS= ndisgen.sh

.include <bsd.prog.mk>
