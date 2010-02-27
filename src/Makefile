SVN_VERSION=1.6.5
SVN=subversion-${SVN_VERSION}
NEON_VERSION=0.28.3
NEON=neon-${NEON_VERSION}
SVN_CONFIGURE_FLAGS=--enable-static-all --disable-shared --with-ssl \
	--without-berkeley-db --without-swig            \
	--without-jikes --without-ruby-sitedir          \
	--without-trang --without-jdk                   \
	--without-ruby-sitedir --without-ruby-test      \
	--without-junit
DARWIN_SVN_CONFIGURE_FLAGS=${SVN_CONFIGURE_FLAGS}	\
	--with-apr=/opt/local --with-apr-util=/opt/local
DARWIN_LINK_FLAGS=-L/opt/local/lib	\
	-lintl -lapr-1 -laprutil-1 -lz -lpthread -ldl -lssl 	\
	-lcrypto -lexpat -lsqlite3 -liconv -lpthread	\
	-lz -lgssapi_krb5 -lkrb5 -lk5crypto -lsasl2  -framework Security \
	-framework CoreFoundation -framework CoreServices
LINUX_LINK_FLAGS=-lapr-1 -laprutil-1 -lz -lpthread -ldl -lcrypt -lexpat -lsasl2 -lssl -lsqlite3
OPENBSD_LINK_FLAGS=-L/usr/local/lib -lapr-1 -laprutil-1 -lz	\
	-lpthread -lcrypto -lssl -lexpat -lintl -lsqlite3
FREEBSD_LINK_FLAGS=-L/usr/local/lib -lapr-1 -laprutil-1 -lz	\
	-lpthread -lcrypto -lssl -lexpat -lintl -lsqlite3 -lgssapi -lxml2

CC?= cc
CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare -g -ggdb
CFLAGS+= -I../work/${SVN}/subversion/include -I/usr/include/apr-1 -I/usr/include/apr-1.0
# OS X
CFLAGS+= -I/opt/local/include
# OpenBSD
CFLAGS+= -I/usr/local/include/apr-1
CFLAGS+= -I/usr/local/include/
# Ubunit
CFLAGS+= -Doff64_t=off_t

# order is important here!
#
# ../work/${SVN}/subversion/libsvn_fs_fs/.libs/libsvn_fs_fs-1.a


STATIC_LIBS = \
 ../work/${SVN}/subversion/libsvn_client/.libs/libsvn_client-1.a \
 ../work/${SVN}/subversion/libsvn_wc/.libs/libsvn_wc-1.a \
 ../work/${SVN}/subversion/libsvn_ra/.libs/libsvn_ra-1.a \
 ../work/${SVN}/subversion/libsvn_diff/.libs/libsvn_diff-1.a \
 ../work/${SVN}/subversion/tests/.libs/libsvn_test-1.a \
 ../work/${SVN}/subversion/libsvn_ra_local/.libs/libsvn_ra_local-1.a \
 ../work/${SVN}/subversion/libsvn_repos/.libs/libsvn_repos-1.a \
 ../work/${SVN}/subversion/libsvn_fs/.libs/libsvn_fs-1.a  \
 ../work/${SVN}/subversion/libsvn_fs_fs/.libs/libsvn_fs_fs-1.a \
 ../work/${SVN}/subversion/libsvn_fs_util/.libs/libsvn_fs_util-1.a \
 ../work/${SVN}/subversion/libsvn_ra_svn/.libs/libsvn_ra_svn-1.a \
 ../work/${SVN}/subversion/libsvn_delta/.libs/libsvn_delta-1.a \
 ../work/${SVN}/subversion/libsvn_ra_neon/.libs/libsvn_ra_neon-1.a \
 ../work/${SVN}/subversion/libsvn_subr/.libs/libsvn_subr-1.a \
 ../work/${SVN}/neon/src/.libs/libneon.a

OBJS = \
 add-cmd.o \
 blame-cmd.o \
 cat-cmd.o \
 changelist-cmd.o \
 checkout-cmd.o \
 cleanup-cmd.o \
 mwconf-cmd.o \
 conflict-callbacks.c \
 commit-cmd.o \
 copy-cmd.o \
 delete-cmd.o \
 diff-cmd.o \
 export-cmd.o \
 help-cmd.o \
 import-cmd.o \
 info-cmd.o \
 list-cmd.o \
 lock-cmd.o \
 log-cmd.o \
 main.o \
 merge-cmd.o \
 mergeinfo-cmd.o \
 mkdir-cmd.o \
 move-cmd.o \
 mwbuild-cmd.o \
 mwcheck-cmd.o \
 mwget-cmd.o \
 mwstart-cmd.o \
 mwstop-cmd.o \
 mwquery-cmd.o \
 mwutil.o \
 notify.o \
 props.o \
 propdel-cmd.o \
 propedit-cmd.o \
 propget-cmd.o \
 proplist-cmd.o \
 propset-cmd.o \
 resolve-cmd.o \
 resolved-cmd.o \
 revert-cmd.o \
 status-cmd.o \
 status.o \
 update-cmd.o \
 unlock-cmd.o \
 util.o \
 y.tab.o \
 setproctitle.o \
 strlcpy.o \
 strlcat.o \
 strtonum.o \
 switch-cmd.o \
 vis.o
# Nanny code
OBJS += nanny/nanny_children.o	\
	nanny/nanny_core.o	\
	nanny/nanny_counter.o	\
	nanny/nanny_http_server.o	\
	nanny/nanny_log.o	\
	nanny/nanny_timer.o	\
	nanny/nanny_udp_server.o	\
	nanny/nanny_utility.o 	\
	nanny/nanny_variable.o

# We need to build the thirdparty libs before we build our local source.
mw: ${STATIC_LIBS} _linkflags ${OBJS}
	${CC} -o mw ${CFLAGS} `cat _linkflags` ${OBJS} ${STATIC_LIBS}

y.tab.o: parse.y
	yacc parse.y
	${CC} -c y.tab.c -o y.tab.o ${CFLAGS}

${OBJS}: cl.h client_errors.h svn_private_config.h

# Write the flags for this platform to a file on disk for convenience.
_linkflags:
	if [ $$(uname) = "Darwin" ]; then echo ${DARWIN_LINK_FLAGS} > _linkflags; fi
	if [ $$(uname) = "Linux" ]; then echo ${LINUX_LINK_FLAGS} > _linkflags; fi
	if [ $$(uname) = "OpenBSD" ]; then echo ${OPENBSD_LINK_FLAGS} > _linkflags; fi
	if [ $$(uname) = "FreeBSD" ]; then echo ${FREEBSD_LINK_FLAGS} > _linkflags; fi

# Building the third-party libraries after they've been configured.
${STATIC_LIBS}: ../work/${SVN}/Makefile
	cd ../work/${SVN} ; make

# To configure svn libs, unpack both svn and neon libs, then configure for
# this platform.
# Note: Configuring requires an unpacked distribution, generates a 'Makefile'
../work/${SVN}/Makefile: ../work/${SVN}/_unpacked ../work/${SVN}/neon/_unpacked
	cd ../work/${SVN} ;					\
	if [ $$(uname) = "Darwin" ]; then			\
		./configure ${DARWIN_SVN_CONFIGURE_FLAGS};	\
	else							\
		./configure ${SVN_CONFIGURE_FLAGS};		\
	fi

# How to unpack the subversion libraries
# We know we've unpacked properly if we have an '_unpacked' marker file
../work/${SVN}/_unpacked: ../thirdparty/${SVN}.tar.bz2
	mkdir -p ../work
	rm -rf ../work/${SVN}
	bunzip2 < ../thirdparty/${SVN}.tar.bz2 | tar -C ../work -xf -
	patch -p1 -d ../work/${SVN} < ../thirdparty/externals-base-defaulted.diff
	touch ../work/${SVN}/_unpacked

# Neon libraries unpack over the unpacked svn libraries
# We know we've unpacked properly if we have an '_unpacked' marker file
../work/${SVN}/neon/_unpacked: ../work/${SVN}/_unpacked	../thirdparty/${NEON}.tar.gz
	cd ../work/${SVN} ; tar -xzf ../../thirdparty/${NEON}.tar.gz
	cd ../work/${SVN} ; ln -s ${NEON} neon
	touch ../work/${SVN}/neon/_unpacked

.PHONY: clean
clean:
	rm -f *.o mw _linkflags y.tab.c
	rm -rf ../work

static-libs: ${STATIC_LIBS}
