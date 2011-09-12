# This file is part of pom-ng.
# Copyright (C) 2010-2011 Guy Martin <gmsoft@tuxicoman.be>
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

ANALYZER_SRC = analyzer_gif.la analyzer_http.la @ANALYZER_OBJS@
INPUT_SRC = @INPUT_OBJS@
OUTPUT_SRC = output_log.la @OUTPUT_OBJS@
PROTO_SRC = proto_arp.la proto_docsis.la proto_ethernet.la proto_http.la proto_icmp.la proto_ipv4.la proto_mpeg.la proto_tcp.la
PTYPE_SRC = ptype_bool.la ptype_mac.la ptype_ipv4.la ptype_uint8.la ptype_uint16.la ptype_uint32.la ptype_string.la ptype_timestamp.la

lib_LTLIBRARIES = $(ANALYZER_SRC) $(INPUT_SRC) $(OUTPUT_SRC) $(PROTO_SRC) $(PTYPE_SRC)

EXTRA_LTLIBRARIES = input_pcap.la input_dvb.la output_pcap.la analyzer_jpeg.la


analyzer_gif_la_SOURCES = analyzer/analyzer_gif.c analyzer/analyzer_gif.h
analyzer_gif_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lgif
analyzer_gif_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_jpeg_la_SOURCES = analyzer/analyzer_jpeg.c analyzer/analyzer_jpeg.h
analyzer_jpeg_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -ljpeg
analyzer_jpeg_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_http_la_SOURCES = analyzer/analyzer_http.c analyzer/analyzer_http.h analyzer/analyzer_http_post.c analyzer/analyzer_http_post.h
analyzer_http_la_LDFLAGS = -module -avoid-version
analyzer_http_la_LIBADD = $(top_builddir)/src/libpom-ng.la

input_pcap_la_SOURCES = input/input_pcap.c input/input_pcap.h
input_pcap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
input_pcap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
input_dvb_la_SOURCES = input/input_dvb.c input/input_dvb.h
input_dvb_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
input_dvb_la_LIBADD = $(top_builddir)/src/libpom-ng.la

output_log_la_SOURCES = output/output_log.c output/output_log.h output/output_log_txt.c output/output_log_txt.h output/output_log_xml.c output/output_log_xml.h
output_log_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
output_log_la_LIBADD = $(top_builddir)/src/libpom-ng.la
output_pcap_la_SOURCES = output/output_pcap.c output/output_pcap.h
output_pcap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
output_pcap_la_LIBADD = $(top_builddir)/src/libpom-ng.la

proto_arp_la_SOURCES = proto/proto_arp.c proto/proto_arp.h
proto_arp_la_LDFLAGS = -module -avoid-version
proto_arp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_docsis_la_SOURCES = proto/proto_docsis.c proto/proto_docsis.h
proto_docsis_la_LDFLAGS = -module -avoid-version
proto_docsis_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ethernet_la_SOURCES = proto/proto_ethernet.c proto/proto_ethernet.h
proto_ethernet_la_LDFLAGS = -module -avoid-version
proto_ethernet_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_http_la_SOURCES = proto/proto_http.c proto/proto_http.h
proto_http_la_LDFLAGS = -module -avoid-version
proto_http_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_icmp_la_SOURCES = proto/proto_icmp.c proto/proto_icmp.h
proto_icmp_la_LDFLAGS = -module -avoid-version
proto_icmp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ipv4_la_SOURCES = proto/proto_ipv4.c proto/proto_ipv4.h
proto_ipv4_la_LDFLAGS = -module -avoid-version
proto_ipv4_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_mpeg_la_SOURCES = proto/proto_mpeg.c proto/proto_mpeg.h proto/proto_mpeg_ts.c proto/proto_mpeg_ts.h proto/proto_mpeg_sect.c proto/proto_mpeg_sect.h proto/proto_mpeg_dvb_mpe.c proto/proto_mpeg_dvb_mpe.h
proto_mpeg_la_LDFLAGS = -module -avoid-version
proto_mpeg_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_tcp_la_SOURCES = proto/proto_tcp.c proto/proto_tcp.h
proto_tcp_la_LDFLAGS = -module -avoid-version
proto_tcp_la_LIBADD = $(top_builddir)/src/libpom-ng.la

ptype_bool_la_SOURCES = ptype/ptype_bool.c ptype/ptype_bool.h
ptype_bool_la_LDFLAGS = -module -avoid-version 
ptype_bool_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_mac_la_SOURCES = ptype/ptype_mac.c ptype/ptype_mac.h
ptype_mac_la_LDFLAGS = -module -avoid-version 
ptype_mac_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_ipv4_la_SOURCES = ptype/ptype_ipv4.c ptype/ptype_ipv4.h
ptype_ipv4_la_LDFLAGS = -module -avoid-version 
ptype_ipv4_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_uint8_la_SOURCES = ptype/ptype_uint8.c ptype/ptype_uint8.h
ptype_uint8_la_LDFLAGS = -module -avoid-version 
ptype_uint8_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_uint16_la_SOURCES = ptype/ptype_uint16.c ptype/ptype_uint16.h
ptype_uint16_la_LDFLAGS = -module -avoid-version 
ptype_uint16_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_uint32_la_SOURCES = ptype/ptype_uint32.c ptype/ptype_uint32.h
ptype_uint32_la_LDFLAGS = -module -avoid-version 
ptype_uint32_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_string_la_SOURCES = ptype/ptype_string.c ptype/ptype_string.h
ptype_string_la_LDFLAGS = -module -avoid-version 
ptype_string_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_timestamp_la_SOURCES = ptype/ptype_timestamp.c ptype/ptype_timestamp.h
ptype_timestamp_la_LDFLAGS = -module -avoid-version 
ptype_timestamp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
