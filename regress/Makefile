
MW?=		../mw

CLEANFILES=
# create a one-off temporary directory
MWBUILD_ROOT:=$(shell mktemp -d)

default: test-mw-initial                \
	 test-mw-noconfig               \
	 test-mwbuild-chicken-and-egg   \
	 test-mwbuild-dummy-env         \
	 test-mwbuild-project-svn       \
	 test-mwbuild-logwrite-fatal

test-mw-initial: clean

# test for segfault found by aseem
test-mw-noconfig:
	${MW} -f test-mw-noconfig.conf query cdb 2>&1 | grep -q 'Configuration file not found'

# test for MWBUILD_ROOT and MWBUILD_APPROOT settings
test-mwbuild-chicken-and-egg:
	sed -e "s|@@MWBUILD_ROOT@@|$(subst /,\/,${MWBUILD_ROOT})|g"               \
	    -e "s|@@MWBUILD_APPROOT@@|$(subst /,\/,${MWBUILD_ROOT}/__test__app)|g" \
	    < test-mwbuild-chicken-and-egg.conf > _mwbuild.conf
	${MW} -f _mwbuild.conf get > /dev/null 2>&1
	test -d ${MWBUILD_ROOT}/__test__app
	test -h ${MWBUILD_ROOT}/__test__app/dummy
	${MW} -f _mwbuild.conf query 2>&1 | \
	    grep 'MWBUILD_DATAROOT="${MWBUILD_ROOT}/data"' > /dev/null
	${MW} -f _mwbuild.conf query 2>&1 | \
	    grep 'MWBUILD_LOGROOT="${MWBUILD_ROOT}/log"' > /dev/null
	rm -rf ${MWBUILD_ROOT} _mwbuild.conf

# test for the environment
test-mwbuild-dummy-env:
	sed -e "s|@@MWBUILD_ROOT@@|$(subst /,\/,${MWBUILD_ROOT})|g" \
	    < test-mwbuild-dummy.conf > _mwbuild.conf
	${MW} -f _mwbuild.conf get > /dev/null 2>&1
	${MW} -f _mwbuild.conf build > /dev/null 2>&1
	${MW} -f _mwbuild.conf start > /dev/null 2>&1
	grep 'MWBUILD_ROOT=${MWBUILD_ROOT}' /tmp/dummy.{build,start} > /dev/null
	grep 'MWBUILD_DATAROOT=${MWBUILD_ROOT}/data' /tmp/dummy.{build,start} > /dev/null
	grep 'MWBUILD_LOGROOT=${MWBUILD_ROOT}/log' /tmp/dummy.{build,start} > /dev/null
	grep 'MWBUILD_APPROOT=${MWBUILD_ROOT}/app' /tmp/dummy.{build,start} > /dev/null
	grep 'PROJECT_DATADIR=${MWBUILD_ROOT}/data/dummy' /tmp/dummy.{build,start} > /dev/null
	grep 'PROJECT_LOGDIR=${MWBUILD_ROOT}/log/dummy' /tmp/dummy.{build,start} > /dev/null
	grep 'PROJECT=dummy' /tmp/dummy.{build,start} > /dev/null
	grep 'PROJECT_SVN=mwbuild/trunk/regress/dummy_project:65548' \
	    /tmp/dummy.{build,start} > /dev/null
	${MW} -f _mwbuild.conf stop > /dev/null 2>&1
	rm -rf ${MWBUILD_ROOT} _mwbuild.conf

# test for the correct replacement of revision in $PROJECT_SVN
test-mwbuild-project-svn:
	sed -e "s|@@MWBUILD_ROOT@@|$(subst /,\/,${MWBUILD_ROOT})|g" \
	    < test-mwbuild-dummy2.conf > _mwbuild.conf
	${MW} -f _mwbuild.conf get > /dev/null 2>&1
	${MW} -f _mwbuild.conf build > /dev/null 2>&1
	grep 'PROJECT_SVN' /tmp/dummy.build  | cut -d':' -f2 \
	    | xargs -I % test % -eq `./get_rev.sh ${MWBUILD_ROOT}/app/dummy`
	rm -rf ${MWBUILD_ROOT} _mwbuild.conf

# test to ensure we fatal error if we cannot create the log
# directory (ENG-593)
test-mwbuild-logwrite-fatal:
	sed -e "s|@@MWBUILD_ROOT@@|$(subst /,\/,${MWBUILD_ROOT})|g" \
	    < test-mwbuild-dummy2.conf > _mwbuild.conf
	mkdir ${MWBUILD_ROOT}
	chmod u-w ${MWBUILD_ROOT}
	${MW} -f _mwbuild.conf get 2>&1 | grep 'mw_mkpath() failure'
	rm -rf ${MWBUILD_ROOT} _mwbuild.conf


clean:
	rm -rf ${CLEANFILES}
