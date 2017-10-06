
# This file is part of pom-ng.
# Copyright (C) 2010-2015 Guy Martin <gmsoft@tuxicoman.be>
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
AC_INIT([pom-ng], [0.0.19], [gmsoft@tuxicoman.be], , [http://www.packet-o-matic.org])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR

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
PKG_CHECK_MODULES(libmicrohttpd, [libmicrohttpd >= 0.9.28], [], [AC_MSG_ERROR([libmicrohttpd >= 0.9.28 is required to build this program])])
AC_SUBST(libmicrohttpd_LIBS)

# Check for uthash
AC_CHECK_HEADERS(uthash.h, [], [AC_MSG_ERROR([uthash is required])])

# Check for libmagic

AC_CHECK_HEADERS([magic.h], [has_magic=yes], [has_magic=no])
AC_ARG_WITH([magic], AS_HELP_STRING([--with-magic], [support file signature detection using libmagic]))

if test "x$with_magic" = "xyes"
then
	if test "x$has_magic" = "xno"
	then
		AC_MSG_ERROR([libmagic was requested but it was not found])
	fi
else
	if test "x$with_magic" = "xno"
	then
		has_magic=no
	fi
fi

if test "x$has_magic" = "xyes"
then
	AC_DEFINE(HAVE_LIBMAGIC, , [Lib magic])
	magic_LIBS="-lmagic"
	AC_SUBST(magic_LIBS)
fi

# Check for PCAP
AC_CHECK_HEADERS([pcap.h pcap-bpf.h], [pcap_headers=yes], [pcap_headers=no])
AC_CHECK_LIB([pcap], [pcap_open_offline, pcap_open_dead, pcap_close, pcap_breakloop], [has_pcap=$pcap_headers], [has_pcap=no])
AC_ARG_WITH([pcap], AS_HELP_STRING([--with-pcap], [use libpcap for capturing and injecting packet, needed for input_pcap, output_pcap and output_inject]))

if test "x$with_pcap" = "xyes"
then
	if test "x$has_pcap" = "xno"
	then
		AC_MSG_ERROR([libpcap was requested but it was not found])
	fi
else
	if test "x$with_pcap" = "xno"
	then
		has_pcap=no
	fi
fi

if test "x$has_pcap" = "xyes"
then

	INPUT_OBJS="$INPUT_OBJS input_pcap.la"
	OUTPUT_OBJS="$OUTPUT_OBJS output_inject.la output_pcap.la"
fi

# Check for DVB
AC_CHECK_HEADERS([linux/dvb/dmx.h linux/dvb/frontend.h], [has_dvb=yes], [has_dvb=no])
AC_ARG_WITH([dvb], AS_HELP_STRING([--with-dvb], [enable support for linux dvb API, needed for input_dvb_*]))

if test "x$with_dvb" = "xyes"
then
	if test "x$has_dvb" = "xno"
	then
		AC_MSG_ERROR([dvb was requested but the headers were not found])
	fi
else
	if test "x$with_dvb" = "xno"
	then
		has_dvb=no
	fi
fi

if test "x$has_dvb" = "xyes"
then
	INPUT_OBJS="input_dvb.la $INPUT_OBJS"
fi

if test "x$INPUT_OBJS" = "x"
then
	AC_MSG_ERROR([No input could be compiled.])
fi

# Check for xmlrpc-c

OLD_LIBS=[$LIBS]
AC_CHECK_HEADERS([xmlrpc-c/base.h xmlrpc-c/server.h], [has_xmlrpc=yes], [has_xmlrpc=no])
AC_CHECK_LIB([xmlrpc_util], [xmlrpc_millisecond_sleep], [LIB_XMLRPC_UTIL='-lxmlrpc_util'])
LIBS="$LIB_XMLRPC_UTIL $LIBS"

AC_MSG_CHECKING([for xmlrpc-c-config])
XMLRPC_CONFIG=`which xmlrpc-c-config 2>/dev/null`
if [ test ! -x "${XMLRPC_CONFIG}" ]
then
	has_xmlrpc=no
fi
AC_MSG_RESULT($has_xmlrpc)

if test  "x$has_xmlrpc" = "xno"
then
	AC_MSG_ERROR([xmlrpc-c is required to build this program])
fi

AC_CHECK_LIB([xmlrpc_server], [xmlrpc_registry_process_call2], [AC_DEFINE(HAVE_XMLRPC_REGISTRY_PROCESS_CALL2, , [Has the new xmlrpc API])])
xmlrpc_LIBS="-lxmlrpc_server -lxmlrpc -lxmlrpc_util -lm"
xmlrpc_LIBS="${xmlrpc_LIBS} `xmlrpc-c-config server-util --libs`"
AC_DEFINE(USE_XMLRPC, , [Compile XML-RPC interface])

LIBS="$OLD_LIBS"

AC_SUBST(xmlrpc_SRC)
AC_SUBST(xmlrpc_LIBS)



# Check for Linux' tun header
AC_CHECK_HEADERS([linux/if_tun.h], [has_tun=yes], [has_tun=no])
AC_ARG_WITH([tun], AS_HELP_STRING([--with-tun], [enable support for linux tun interface, needed for output_tap]))

if test "x$with_tun" = "xyes"
then
	if test "x$has_tun" = "xno"
	then
		AC_MSG_ERROR([tun was requested but the headers were not found])
	fi
else
	if test "x$with_tun" = "xno"
	then
		has_tun=no
	fi
fi

if test "x$has_tun" = "xyes"
then
	OUTPUT_OBJS="$OUTPUT_OBJS output_tap.la"
fi

# Check for Zlib
AC_CHECK_HEADERS([zlib.h], [has_zlib=yes], [has_zlib=no])
AC_ARG_WITH([zlib], AS_HELP_STRING([--with-zlib], [enable zlib support for automatic decompression of streams]))
if test "x$with_zlib" = "xyes"
then
	if test "x$has_zlib" = "xno"
	then
		AC_MSG_ERROR([zlib was requested but the headers were not found])
	fi
else
	if test "x$with_zlib" = "xno"
	then
		has_zlib=no
	fi
fi

if test "x$has_zlib" = "xyes"
then
	AC_DEFINE(HAVE_ZLIB, , [Zlib])
	zlib_LIBS="-lz"
	AC_SUBST(zlib_LIBS)
	DECODER_OBJS="decoder_gzip.la"
fi

# Check for JPEG
AC_CHECK_HEADERS([jpeglib.h], [has_jpeg=yes], [has_jpeg=no])
AC_ARG_WITH([jpeg], AS_HELP_STRING([--with-jpeg], [enable jpeg support for image analysis]))
if test "x$with_jpeg" = "xyes"
then
	if test "x$has_jpeg" = "xno"
	then
		AC_MSG_ERROR([jpeg was requested but the headers were not found])
	fi
else
	if test "x$with_jpeg" = "xno"
	then
		has_jpeg=no
	fi
fi
if test "x$has_jpeg" = "xyes"
then
	ANALYZER_OBJS="analyzer_jpeg.la"
fi

# Check for Sqlite3
AC_CHECK_HEADERS([sqlite3.h], [has_sqlite3=yes], [has_sqlite3=no])
AC_ARG_WITH([sqlite3], AS_HELP_STRING([--with-sqlite3], [enable sqlite3 database support]))
if test "x$with_sqlite3" = "xyes"
then
	if test "x$has_sqlite3" = "xno"
	then
		AC_MSG_ERROR([sqlite3 was requested but the headers were not found])
	fi
else
	if test "x$with_sqlite3" = "xno"
	then
		has_sqlite3=no
	fi
fi
if test "x$has_sqlite3" = "xyes"
then
	DATASTORE_OBJS="$DATASTORE_OBJS datastore_sqlite.la"
fi

# Check for PostgreSQL
AC_CHECK_HEADERS([libpq-fe.h], [has_postgres=yes], [has_postgres=no])
AC_ARG_WITH([postgres], AS_HELP_STRING([--with-postgres], [enable postgres database support]))
if test "x$with_postgres" = "xyes"
then
	if test "x$has_postgres" = "xno"
	then
		AC_MSG_ERROR([postgres was requested but the headers were not found])
	fi
else
	if test "x$with_postgres" = "xno"
	then
		has_postgres=no
	fi
fi
if test "x$has_postgres" = "xyes"
then
	DATASTORE_OBJS="$DATASTORE_OBJS datastore_postgres.la"
fi

# Check that there is at least one datastore
if test "x$DATASTORE_OBJS" = "x"
then
	AC_MSG_ERROR([At least one database backend is required.])
fi

# Check for Lua
PKG_CHECK_MODULES(lua, [lua5.1], [has_lua=yes], [has_lua=no])
if test "x$has_lua" = "xno"
then
	PKG_CHECK_MODULES(lua, [lua5.2], [has_lua=yes], [has_lua=no])
fi
if test "x$has_lua" = "xno"
then
	PKG_CHECK_MODULES(lua, [lua], [], AC_MSG_ERROR([lua is required to build this program])])
fi
AC_SUBST(lua_LIBS)
AC_SUBST(lua_CFLAGS)

# Check for libexif
PKG_CHECK_MODULES(libexif, [libexif], [has_exif=yes], [has_exif=no])
AC_ARG_WITH([exif], AS_HELP_STRING([--with-exif], [enable exif database support]))
if test "x$with_exif" = "xyes"
then
	if test "x$has_exif" = "xno"
	then
		AC_MSG_ERROR([exif was requested but the headers were not found])
	fi
else
	if test "x$with_exif" = "xno"
	then
		has_exif=no
	fi
fi
if test "x$has_exif" = "xyes"
then
	AC_DEFINE(HAVE_LIBEXIF, , [libexif])
	AC_SUBST(libexit_LIBS)
	AC_SUBST(libexif_CFLAGS)
fi


AC_SUBST(ANALYZER_OBJS)
AC_SUBST(DATASTORE_OBJS)
AC_SUBST(DECODER_OBJS)
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
echo " * libpcap          : $has_pcap"
echo " * Linux DVB        : $has_dvb"
echo " * Libmagic         : $has_magic"
echo " * Zlib             : $has_zlib"
echo " * JPEG             : $has_jpeg"
echo " * Sqlite3          : $has_sqlite3"
echo " * Postgresql       : $has_postgres"
echo " * libexif          : $has_exif"
echo ""
echo "Author : Guy Martin <gmsoft@tuxicoman.be>"


