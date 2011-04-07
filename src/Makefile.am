# This file is part of pom-ng.
# Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


include $(top_srcdir)/Makefile.common

XMLRPC_SRC = xmlrpcsrv.c xmlrpcsrv.h xmlrpccmd.c xmlrpccmd.h xmlrpccmd_registry.c xmlrpccmd_registry.h
CORE_SRC = ipc.c ipc.h httpd.c httpd.h pomlog.c pomlog.h mod.c mod.h
INPUT_SRC = input_ipc.c input_ipc.h input_client.c input_client.h input_server.c input_server.h

bin_PROGRAMS = pom-ng
pom_ng_SOURCES = main.c main.h $(CORE_SRC) $(XMLRPC_SRC) $(INPUT_SRC)
pom_ng_CFLAGS = @libxml2_CFLAGS@ -DPOM_LIBDIR='"@POM_MOD_LIBDIR@"' -DDATAROOT='"$(pkgdatadir)"'
pom_ng_LDFLAGS = @LIBS@ @libxml2_LIBS@ @libmicrohttpd_LIBS@
pom_ng_LDADD = libpom-ng.la @xmlrpc_LIBS@

libpom_ng_la_SOURCES = common.c common.h core.c core.h ptype.c ptype.h input.c input.h packet.c packet.h proto.c proto.h conntrack.c conntrack.h jhash.h timer.c timer.h registry.c registry.h

lib_LTLIBRARIES = libpom-ng.la
