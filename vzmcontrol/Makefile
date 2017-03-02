VZMROOT = ..

OBJ = common.o
SOURCE = $(OBJ:.o=.c)
TARGET = ${LIBVZM}

include ${VZMROOT}/Makefile.inc

all:: ${TARGET} Makefile

${TARGET}: ${OBJ}
	-rm -f ${LIBDIR}/$@
	ar cq ${LIBDIR}/$@ ${OBJ}
	ranlib ${LIBDIR}/$@

clean::
	-rm -f ${OBJ} ${LIBDIR}/${TARGET}

