# $Id$
#
# Copyright (c) 2002-2017, Parallels International GmbH
# All rights reserved.
#
# Makefile for vzt-common (for build at freeBSD)
#

PORTNAME=	vzmigrate
PORTREVISION=	156

PKGDIR=${.CURDIR}
TMPPLIST=${WRKDIR}/.PLIST${PKGNAMESUFFIX}.mktmp

WRKSRC=         ${WRKDIR}/work/
WRKBUILD=	${WRKDIR}/tmp/

PLIST_SUB=	WRKBUILD=${WRKBUILD} VERSION=${PORTVERSION}

USE_GMAKE=	yes
CFLAGS=
CXXFLAGS=

BUILD_DEPENDS ?= /usr/include/vz/com:${PORTSDIR}/vz/vzagent/devel:pkg-install \
		/usr/include/vz/sys:${PORTSDIR}/vz/vzagent/devel:pkg-install
LIB_DEPENDS ?= vzacommon:${PORTSDIR}/vz/vzagent/lib:pkg-install \
	vzasys:${PORTSDIR}/vz/vzagent/lib:pkg-install

do-extract:
	@${MKDIR} ${WRKSRC}
	@cd ${.CURDIR} && ${CP} -R ../files/* ${WRKSRC}/

do-install:
	@${MKDIR} ${WRKBUILD}
	@cd ${WRKSRC} && ${GMAKE} DESTDIR=${WRKBUILD} DEBUG=defined install

.include "../../Makefile.vz.inc"
