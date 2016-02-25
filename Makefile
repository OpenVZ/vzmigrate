#
# Copyright (c) 2001-2003 by SWsoft
# All rights reserved.
#
# Makefile for migrate
#

VZMROOT = .

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

include ${VZMROOT}/Makefile.incl

install:: all

	# install executables
	install -d ${PREFIX}/${sbindir}
	install -d ${PREFIX}/${datadir}
	install -m 755 vzmsrc vzmdest vzmpipe ${PREFIX}/${sbindir}
	install -m 755 vzmd ${PREFIX}/${sbindir}
	install -m 755 vzmigrate ${PREFIX}/${sbindir}

	# source binaries
	ln -sf ${sbindir}/vzmsrc ${PREFIX}/${datadir}/pmigrate.c2c
	ln -sf vzmsrc ${PREFIX}/${sbindir}/vzmlocal	# local move/copy

	# destination binaries
	ln -sf vzmdest ${PREFIX}/${sbindir}/vzmdestmpl	# template migration

	# install man pages
	install -d ${PREFIX}/${mandir}/man8
	install -m 644 man/vzmigrate.8 man/vzmlocal.8 man/vzmsrc.8 \
		man/vzmpipe.8 ${PREFIX}/${mandir}/man8/

	ln -sf vzmsrc.8 ${PREFIX}/${mandir}/man8/vzmdest.8
	ln -sf vzmsrc.8 ${PREFIX}/${mandir}/man8/vzmdestmpl.8

	grep -h 'fiu_do_on(' bin/*.cpp | sed 's/fiu_do_on("\(.*\)".*/\1/' > fiu.all
	grep -h 'fiu_return_on(' bin/*.cpp | sed 's/fiu_return_on("\(.*\)".*/\1/' >> fiu.all
	install -d ${PREFIX}/usr/share/vzmigrate
	install -m 644 fiu.all ${PREFIX}/usr/share/vzmigrate/fiu.all


rpms:
	cd .. && tar -cjf vzmigrate.tar.bz2 vzmigrate && rpmbuild -tb vzmigrate.tar.bz2
