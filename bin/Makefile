VZMROOT = ..

ARCH=$(shell uname -s)
ifneq "" "$(findstring ai64,$(ARCH))"
__ia64__=true
endif

TRG_VZMPIPE = ${VZMROOT}/vzmpipe
OBJPIPE = vzmpipe.o
LIBPIPE = ${LIBDIR}/${LIBVZM}
SOURCE += $(OBJPIPE:.o=.cpp)

OBJC = util.o channel.o ploop.o
SOURCE += $(OBJC:.o=.c)

TRG_VZMIGRATE = ${VZMROOT}/vzmigrate
OBJVZMIGRATE = vzmigrate.o
SOURCE += $(OBJVZMIGRATE:.o=.c)

TRG_VZMSRC = ${VZMROOT}/vzmsrc
OBJSRC = vzmlocal.o bincom.o veentry.o migratecom.o migchannel.o vzacompat.o migssh.o \
	migratesrc.o migsrcremote.o migsrclocal.o multiplexer.o ct_config.o
LIBSRC = ${LIBDIR}/${LIBVZM} ${LIBVZ_SRC} ${LIBVZL}
ifdef __ia64__
LIBSRC += "/lib/libia64_syscall.a"
endif
SOURCE += $(OBJSRC:.o=.cpp)

TRG_VZMTEMPL = ${VZMROOT}/vzmtemplate
OBJTEMPL = vzmtemplate.o bincom.o veentry.o templ.o migratecom.o migchannel.o vzacompat.o \
	migsrctempl.o migssh.o ct_config.o
LIBTEMPL = ${LIBDIR}/${LIBVZM} ${LIBVZ_TEMPL} ${LIBVZL}
ifdef __ia64__
LIBTEMPL += "/lib/libia64_syscall.a"
endif
SOURCE += $(OBJTEMPL:.o=.cpp)

TRG_VZMDEST = ${VZMROOT}/vzmdest
OBJDST = vzmdest.o bincom.o veentry.o templ.o migratecom.o migchannel.o vzacompat.o \
	migratedst.o migdsttempl.o server.o migssh.o multiplexer.o ct_config.o
LIBDST = ${LIBDIR}/${LIBVZM} ${LIBVZ_DST}
SOURCE += $(OBJDST:.o=.cpp)

TRG_VZMD = ${VZMROOT}/vzmd
OBJVZMD = vzmd.o migchannel.o vzacompat.o veentry.o templ.o migratecom.o migratedst.o \
	migdsttempl.o bincom.o server.o migssh.o multiplexer.o ct_config.o
SOURCE += $(OBJVZMD:.o=.cpp)

PROGS = ${TRG_VZMPIPE} ${TRG_VZMLOCAL} ${TRG_VZMSRC} ${TRG_VZMDEST} \
	${TRG_VZMD} ${TRG_VZMTEMPL} ${TRG_VZMIGRATE}

OBJ = ${OBJPIPE} ${OBJLOCAL} ${OBJDST} ${OBJSRC} ${OBJTEMPL} ${OBJVZAC} ${OBJMIGRATE} ${OBJC}

include ${VZMROOT}/Makefile.incl

all:: ${PROGS}

${TRG_VZMPIPE}:: ${OBJPIPE}
	g++ -o $@ ${OBJPIPE} ${LDFLAGS} ${LIBPIPE}

${TRG_VZMLOCAL}:: ${OBJLOCAL}
	g++ -o $@ ${OBJLOCAL} ${LDFLAGS} ${LIBLOCAL} ${LPTHREAD}

${TRG_VZMSRC}:: ${OBJSRC} ${OBJC}
	g++ -o $@ ${OBJSRC} ${OBJC} ${LDFLAGS} ${LIBSRC} ${LPTHREAD}

${TRG_VZMTEMPL}:: ${OBJTEMPL} ${OBJC}
	g++ -o $@ ${OBJTEMPL} ${OBJC} ${LDFLAGS} ${LIBTEMPL} ${LPTHREAD}

${TRG_VZMDEST}:: ${OBJDST} ${OBJC}
	g++ -o $@ ${OBJDST} ${OBJC} ${LDFLAGS} ${LIBDST} ${LPTHREAD}

${TRG_VZMIGRATE}:: ${OBJVZMIGRATE}
	gcc -o $@ ${OBJVZMIGRATE}

${TRG_VZMD}:: ${OBJVZMD} ${OBJC}
	g++ -o $@ ${OBJVZMD} ${OBJC} ${LDFLAGS} ${LIBDST} ${LPTHREAD}

clean::
	rm -f ${PROGS} ${OBJ}
