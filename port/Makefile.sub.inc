MASTERDIR=${.CURDIR}/../main
WRKDIR=${MASTERDIR}/work

do-extract:
	@cd ${MASTERDIR} && ${MAKE} extract
do-build:
	@cd ${MASTERDIR} && ${MAKE} build
do-install:
	@cd ${MASTERDIR} && ${MAKE} install
do-clean:
	-@rm -f ${EXTRACT_COOKIE} ${CONFIGURE_COOKIE} ${INSTALL_COOKIE} \
		${BUILD_COOKIE} ${PATCH_COOKIE} ${PACKAGE_COOKIE}

.include "${MASTERDIR}/Makefile"
