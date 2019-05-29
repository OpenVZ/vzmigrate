#
# Copyright (c) 2001-2017, Parallels International GmbH.
# Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
# All rights reserved.
#
# Makefile for migrate
#

VZMROOT = .

include ${VZMROOT}/Makefile.incl

define do_rebrand
	sed -e "s,@PRODUCT_NAME_SHORT@,$(PRODUCT_NAME_SHORT),g" -i $(1) || exit 1;
endef

all depend ::
	for i in ${SUBDIRS} ; do \
		(cd $$i && ${MAKE} $@) || exit 1;\
	done

clean::
	for i in ${SUBDIRS} ; do \
		(cd $$i && ${MAKE} $@) || exit 1;\
	done
	find . -regex '.*[~#].*' | xargs rm -f
	find . -name "*.depend" | xargs rm -f

#version ?=		2.5.0
sbindir ?=		/usr/sbin/
mandir ?=		/usr/share/man/
#migdir ?=		/usr/share/vzmigrate-${version}/
datadir ?=		/usr/share/pmigrate/
logrotatedir ?=		/etc/logrotate.d/

include ${VZMROOT}/Makefile.inc

install:: all

	# install executables
	install -d ${DESTDIR}/${sbindir}
	install -d ${DESTDIR}/${datadir}
	install -d ${DESTDIR}/${logrotatedir}
	install -m 755 vzmsrc vzmdest vzmpipe vzmtemplate ${DESTDIR}/${sbindir}
	install -m 755 vzmd ${DESTDIR}/${sbindir}
	install -m 755 vzmigrate ${DESTDIR}/${sbindir}
	install -m 644 logrotate/vzmigrate ${DESTDIR}/${logrotatedir}

	# source binaries
	ln -sf ${sbindir}/vzmsrc ${DESTDIR}/${datadir}/pmigrate.c2c
	ln -sf vzmsrc ${DESTDIR}/${sbindir}/vzmlocal	# local move/copy

	# destination binaries
	ln -sf vzmdest ${DESTDIR}/${sbindir}/vzmdestmpl	# template migration

	# install man pages
	install -d ${DESTDIR}/${mandir}/man8
	for man in vzmigrate.8 vzmlocal.8 vzmsrc.8 vzmpipe.8 vzmtemplate.8; do \
		install -m 644 man/$$man ${DESTDIR}/${mandir}/man8/; \
		$(call do_rebrand,${DESTDIR}/${mandir}/man8/$$man) \
	done

	ln -sf vzmsrc.8 ${DESTDIR}/${mandir}/man8/vzmdest.8
	ln -sf vzmsrc.8 ${DESTDIR}/${mandir}/man8/vzmdestmpl.8

	grep -h 'fiu_do_on(' bin/*.cpp | sed 's/fiu_do_on("\(.*\)".*/\1/' > fiu.all
	grep -h 'fiu_return_on(' bin/*.cpp | sed 's/fiu_return_on("\(.*\)".*/\1/' >> fiu.all
	install -d ${DESTDIR}/usr/share/vzmigrate
	install -m 644 fiu.all ${DESTDIR}/usr/share/vzmigrate/fiu.all


rpms:
	cd .. && tar -cjf vzmigrate.tar.bz2 vzmigrate && rpmbuild -tb vzmigrate.tar.bz2
