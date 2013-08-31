
# This file is part of pom-ng.
# Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software


#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([pom-ng], [0.0.13], [Guy Martin <gmsoft@tuxicoman.be>])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_DEFUN([AC_PROG_CXX], [])
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# BSD specific header files
AC_CHECK_HEADERS([sys/endian.h])

# Linux specific header files
AC_CHECK_HEADERS([mcheck.h endian.h])

# Check for backtrace()'s header
AC_CHECK_HEADERS([execinfo.h])

# Check for valgrind.h
AC_CHECK_HEADERS([valgrind/valgrind.h])

# Check endianess
AC_C_BIGENDIAN

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero gettimeofday inet_ntoa memmove memset strerror])

# Try to find a good CFLAGS/LDFLAGS for pthreads
AC_CHECK_HEADERS(pthread.h, [], [AC_MSG_ERROR([pthread support required])])
CFLAGS="$CFLAGS -D_REENTRANT -D_GNU_SOURCE"
checkpthread=yes

AC_MSG_CHECKING([for pthread_create with libc])
AC_TRY_LINK([], [pthread_create();], 
                [pthflag=yes; checkpthread=no], 
                [pthflag=no])
AC_MSG_RESULT($pthflag)

for flag in "pthreads" "pthread"; do
  if test "x$checkpthread" = "xyes"; then
    AC_MSG_CHECKING([for pthread_create with -$flag])
    OLDLDFLAGS="$LDFLAGS"
    LDFLAGS="-$flag $LDFLAGS"
    AC_TRY_LINK([], [pthread_create();], 
                    [pthflag=yes; checkpthread=no], 
                    [pthflag=no; LDFLAGS="$OLDLDFLAGS"])
    AC_MSG_RESULT($pthflag)
  fi
done

for lib in "c_r" "pthread"; do
  if test "x$checkpthread" = "xyes"; then
     case "x$LIBS" in
        *-l$lib*);;
        *) AC_CHECK_LIB($lib, pthread_create, [LIBS="$LIBS -l$lib"; checkpthread=no]) ;;
     esac
   fi
done

if test "x$checkpthread" = "xyes"; then
  AC_CHECK_FUNC(pthread_create, checkpthread=no)
  text "x$checkpthread" = "xyes" && AC_MSG_ERROR([pthread library required])
fi


LIB_DL=''
AC_CHECK_LIB([dl], [dlopen], [LIB_DL='-ldl'])
LIBS="$LIB_DL $LIBS"

AC_CHECK_LIB([nsl], [gethostbyname])
AC_CHECK_LIB([socket], [socket])



# Checks for packages.
PKG_CHECK_MODULES(libxml2, [libxml-2.0], [], [AC_MSG_ERROR([libxml2 is required to build this program])])
AC_SUBST(libxml2_CFLAGS)
AC_SUBST(libxml2_LIBS)

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 src/modules/Makefile
		 include/Makefile])

# Check for libmicrohttpd
PKG_CHECK_MODULES(libmicrohttpd, [libmicrohttpd >= 0.9.25], [], [AC_MSG_ERROR([libmicrohttpd >= 0.9.25 is required to build this program])])
AC_SUBST(libmicrohttpd_LIBS)

# Check for libmagic
AC_CHECK_HEADERS([magic.h], [want_magic=yes], [want_magic=no])
if test "x$want_magic" = "xyes"
then
	AC_DEFINE(HAVE_LIBMAGIC, , [Lib magic])
	magic_LIBS="-lmagic"
	AC_SUBST(magic_LIBS)
fi

# Check for PCAP
AC_CHECK_HEADERS([pcap.h pcap-bpf.h], [pcap_headers=yes], [pcap_headers=no])
AC_CHECK_LIB([pcap], [pcap_open_offline, pcap_open_dead, pcap_close, pcap_breakloop], [want_pcap=yes], [want_pcap=no])
if test "x$pcap_headers" = "xyes" -a "x$want_pcap" = "xyes"
then
	INPUT_OBJS="$INPUT_OBJS input_pcap.la"
	OUTPUT_OBJS="$OUTPUT_OBJS output_pcap.la"
fi

# Check for Linux' raw socket iface
AC_CHECK_HEADERS([linux/socket.h netpacket/packet.h], [want_netpacket=yes], [want_netpacket=no])

if test "x$want_netpacket" = "xyes"
then
	AC_DEFINE(HAVE_LINUX_IP_SOCKET, , [Linux raw socket iface])
fi

# Check for DVB
AC_CHECK_HEADERS([linux/dvb/dmx.h linux/dvb/frontend.h], [want_dvb=yes], [want_dvb=no])

if test "x$want_dvb" = "xyes"
then
	INPUT_OBJS="input_dvb.la $INPUT_OBJS"
fi

if test "x$INPUT_OBJS" = "x"
then
	AC_MSG_ERROR([No input could be compiled.])
fi

# Check for xmlrpc-c

OLD_LIBS=[$LIBS]
AC_CHECK_HEADERS([xmlrpc-c/base.h xmlrpc-c/server.h], [want_xmlrpc=yes], [want_xmlrpc=no])
AC_CHECK_LIB([xmlrpc_util], [xmlrpc_millisecond_sleep], [LIB_XMLRPC_UTIL='-lxmlrpc_util'])
LIBS="$LIB_XMLRPC_UTIL $LIBS"

AC_MSG_CHECKING([for xmlrpc-c-config])
XMLRPC_CONFIG=`which xmlrpc-c-config 2>/dev/null`
if [ test ! -x "${XMLRPC_CONFIG}" ]
then
	want_xmlrpc=no
fi
AC_MSG_RESULT($want_xmlrpc)

if test  "x$want_xmlrpc" = "xno"
then
	AC_MSG_ERROR([xmlrpc-c is required to build this program])
fi

if test "x$want_xmlrpc" = "xyes"
then
	AC_CHECK_LIB([xmlrpc_server], [xmlrpc_registry_process_call2], [AC_DEFINE(HAVE_XMLRPC_REGISTRY_PROCESS_CALL2, , [Has the new xmlrpc API])])
	xmlrpc_LIBS="-lxmlrpc_server -lxmlrpc -lxmlrpc_util -lm"
	xmlrpc_LIBS="${xmlrpc_LIBS} `xmlrpc-c-config server-util --libs`"
	AC_DEFINE(USE_XMLRPC, , [Compile XML-RPC interface])
fi
LIBS="$OLD_LIBS"

AC_SUBST(xmlrpc_SRC)
AC_SUBST(xmlrpc_LIBS)

# Check for Linux' tun header
AC_CHECK_HEADERS([linux/if_tun.h], [want_tun=yes], [want_tun=no])
if test "x$want_tun" = "xyes"
then
	OUTPUT_OBJS="$OUTPUT_OBJS output_tap.la"
fi

# Check for Zlib
AC_CHECK_HEADERS([zlib.h], [want_zlib=yes], [want_zlib=no])
if test "x$want_zlib" = "xyes"
then
	AC_DEFINE(HAVE_ZLIB, , [Zlib])
	zlib_LIBS="-lz"
	AC_SUBST(zlib_LIBS)
fi

# Check for JPEG
AC_CHECK_HEADERS([jpeglib.h], [want_jpeg=yes], [want_jpeg=no])
if test "x$want_jpeg" = "xyes"
then
	ANALYZER_OBJS="analyzer_jpeg.la"
fi

# Check for Sqlite3
AC_CHECK_HEADERS([sqlite3.h], [want_sqlite3=yes], [want_sqlite3=no])
if test "x$want_sqlite3" = "xyes"
then
	DATASTORE_OBJS="$DATASTORE_OBJS datastore_sqlite.la"
fi

# Check for PostgreSQL
AC_CHECK_HEADERS([libpq-fe.h], [want_postgres=yes], [want_postgres=no])
if test "x$want_postgres" = "xyes"
then
	DATASTORE_OBJS="$DATASTORE_OBJS datastore_postgres.la"
fi

# Check for Lua
PKG_CHECK_MODULES(lua, [lua5.1], [has_lua=yes], [has_lua=no])
if test "x$has_lua" = "xno"
then
	PKG_CHECK_MODULES(lua, [lua], [], AC_MSG_ERROR([lua is required to build this program])])
fi
AC_SUBST(lua_LIBS)
AC_SUBST(lua_CFLAGS)

# Check for libexif
PKG_CHECK_MODULES(libexif, [libexif], [want_libexif=yes], [want_libexif=no])
if test "x$want_libexif" = "xyes"
then
	AC_DEFINE(HAVE_LIBEXIF, , [libexif])
	AC_SUBST(libexit_LIBS)
	AC_SUBST(libexif_CFLAGS)
fi

# Check that there is at least one datastore
if test "x$DATASTORE_OBJS" = "x"
then
	AC_MSG_ERROR([At least one database backend is required.])
fi

AC_SUBST(ANALYZER_OBJS)
AC_SUBST(DATASTORE_OBJS)
AC_SUBST(INPUT_OBJS)
AC_SUBST(OUTPUT_OBJS)

AC_OUTPUT

echo ""
echo "============================================="                                                              
echo "| .-----.-----.--------.______.-----.-----. |"
echo "| |  _  |  _  |        |______|     |  _  | |"
echo "| |   __|_____|__|__|__|      |__|__|___  | |"
echo "| |__|                              |_____| |"
echo "============================================="
echo ""
echo " Configuration result :"
echo " ----------------------"
echo ""
echo " * libpcap          : $want_pcap"
echo " * XMLRPC-C         : $want_xmlrpc"
echo " * Linux raw socket : $want_netpacket"
echo " * Linux DVB        : $want_dvb"
echo " * Libmagic         : $want_magic"
echo " * Zlib             : $want_zlib"
echo " * JPEG             : $want_jpeg"
echo " * Sqlite3          : $want_sqlite3"
echo " * Postgresql       : $want_postgres"
echo " * libexif          : $want_libexif"
echo ""
echo "Author : Guy Martin <gmsoft@tuxicoman.be>"


