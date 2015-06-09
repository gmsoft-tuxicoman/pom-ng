# This file is part of pom-ng.
# Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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

XMLRPC_SRC = xmlrpcsrv.c xmlrpcsrv.h xmlrpccmd.c xmlrpccmd.h xmlrpccmd_monitor.c xmlrpccmd_monitor.h xmlrpccmd_registry.c xmlrpccmd_registry.h
ADDON_SRC = addon.c addon.h addon_event.c addon_event.h addon_output.c addon_output.h addon_ptype.c addon_ptype.h addon_pload.c addon_pload.h addon_data.c addon_data.h
CORE_SRC = httpd.c httpd.h pomlog.c pomlog.h mod.c mod.h

bin_PROGRAMS = pom-ng
pom_ng_SOURCES = main.c main.h $(CORE_SRC) $(XMLRPC_SRC) $(ADDON_SRC)
pom_ng_CFLAGS = @libxml2_CFLAGS@ @lua_CFLAGS@ -DPOM_LIBDIR='"$(mod_dir)"' -DDATAROOT='"$(pkgdatadir)"'
pom_ng_LDADD = libpom-ng.la @xmlrpc_LIBS@ @LIBS@ @libxml2_LIBS@ @libmicrohttpd_LIBS@ @magic_LIBS@ @lua_LIBS@

libpom_ng_la_SOURCES = analyzer.c analyzer.h common.c common.h core.c core.h dns.c dns.h decoder.h decoder.c ptype.c ptype.h input.c input.h packet.c packet.h proto.c proto.h conntrack.c conntrack.h jhash.h output.c output.h timer.c timer.h registry.c registry.h event.c event.h data.c datastore.c datastore.h resource.c resource.h filter.c filter.h addon_plugin.c addon_plugin.h stream.c stream.h mime.c pload.c pload.h telephony.c telephony.h
libpom_ng_la_CFLAGS = @libxml2_CFLAGS@ @lua_CFLAGS@ -DDATAROOT='"$(pkgdatadir)"'
libpom_ng_la_LDFLAGS = @libxml2_LIBS@

lib_LTLIBRARIES = libpom-ng.la
