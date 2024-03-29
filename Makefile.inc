VZMROOT ?= .

#MODE = test

ARCH=$(shell uname -s)
PLAT=$(shell uname -m)
ifneq "" "$(findstring ia64,$(PLAT))"
__ia64__=true
endif

LIBVZM = libvzm.a
LIBVZ_SRC = -Wl,-Bstatic -lvzsock -Wl,-Bdynamic -luuid -lvzctl2 -ldl \
	-lploop -lboost_system -lboost_thread -lzstd
LIBVZ_TEMPL = ${LIBVZ_SRC} -lvztt
LIBVZ_DST = -Wl,-Bstatic -lvzsock -Wl,-Bdynamic -luuid -lvzctl2 -ldl -lvztt \
	-lploop -lboost_system -lboost_thread -lzstd

LIBDIR = ${VZMROOT}/lib

# ld flags
LDFLAGS+= -L/usr/local/lib $(LGCOV)
TARCH=$(shell uname -i)
ifeq "$(TARCH)" "x86_64"
LDFLAGS += -L/usr/kerberos/lib64
else
LDFLAGS += -L/usr/kerberos/lib
endif
LDFLAGS += -g

# Set include 
INCDIRS = vzmcontrol
SUBDIRS = ${INCDIRS} bin

# set include flags
INCFLAGS ?= \
	$(shell for ops in ${INCDIRS} ; do \
		FS="$$FS -I${VZMROOT}/$$ops" ; \
	done ; \
	echo $$FS) 

INCFLAGS += -I/usr/kerberos/include

CC = gcc

MFLAGS = -pthread -Werror -Wall -W -Wformat -g ${INCFLAGS} ${VZFS} -Wno-unused-parameter -Wno-missing-field-initializers
MFLAGS += -D_FILE_OFFSET_BITS=64 -DNDEBUG -D_VZLIN_ -DBOOST_BIND_GLOBAL_PLACEHOLDERS

# -pg
LPTHREAD = -lpthread

ifeq "${FIU_ENABLE}" "yes"
MFLAGS += -DFIU_ENABLE
LIBVZ_SRC += -lfiu
LIBVZ_DST += -lfiu
endif

CFLAGS += ${MFLAGS} -Wall -D_GNU_SOURCE -Wno-unused-parameter -Wno-missing-field-initializers
CXXFLAGS += ${MFLAGS}  --std=c++98

#[ia64] gcc -pthread does not add -D_REENTRANT 
#http://gcc.gnu.org/bugzilla/show_bug.cgi?id=10865
#http://gcc.gnu.org/bugzilla/show_bug.cgi?id=20705
ifeq "$(TARCH)" "ia64"
CXXFLAGS += -D_REENTRANT
endif

#.SUFFIXES: .o .cpp .c

#.c.o:
#	gcc -c ${CFLAGS} $<

SOURCE ?= $(wildcard *.cpp *.c)
SOURCEH ?= $(wildcard *.h)
.depend:: ${SOURCE} ${SOURCEH}
	g++ -MM ${CXXFLAGS} ${SOURCE} >.depend

depend_remove:
	find ${VZMROOT} -name .depend | xargs rm

depend:: depend_remove .depend

install::

DEPEND_FILE ?= .depend

include ${DEPEND_FILE}
