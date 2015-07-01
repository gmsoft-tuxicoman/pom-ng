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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

include $(top_srcdir)/Makefile.common
libdir=$(mod_dir)

ANALYZER_SRC = analyzer_arp.la analyzer_dns.la analyzer_docsis.la analyzer_dtmf.la analyzer_eap.la analyzer_gif.la analyzer_http.la analyzer_multipart.la analyzer_png.la analyzer_ppp_chap.la analyzer_ppp_pap.la analyzer_rfc822.la analyzer_rtp.la analyzer_sdp.la analyzer_sip.la analyzer_smtp.la analyzer_tftp.la @ANALYZER_OBJS@
DATASTORE_SRC = @DATASTORE_OBJS@
DECODER_SRC = decoder_base64.la decoder_percent.la decoder_quoted_printable.la @DECODER_OBJS@
INPUT_SRC = input_kismet.la @INPUT_OBJS@
OUTPUT_SRC = output_file.la output_log.la @OUTPUT_OBJS@
PROTO_SRC = proto_80211.la proto_8021x.la proto_arp.la proto_dns.la proto_docsis.la proto_eap.la proto_ethernet.la proto_gre.la proto_http.la proto_icmp.la proto_icmp6.la proto_ipv4.la proto_ipv6.la proto_mpeg.la proto_ppi.la proto_ppp.la proto_ppp_chap.la proto_ppp_pap.la proto_pppoe.la proto_radiotap.la proto_rtp.la proto_sip.la proto_smtp.la proto_tcp.la proto_tftp.la proto_udp.la proto_vlan.la
PTYPE_SRC = ptype_bool.la ptype_bytes.la ptype_mac.la ptype_ipv4.la ptype_ipv6.la ptype_uint8.la ptype_uint16.la ptype_uint32.la ptype_uint64.la ptype_string.la ptype_timestamp.la

lib_LTLIBRARIES = $(ANALYZER_SRC) $(DATASTORE_SRC) $(DECODER_SRC) $(INPUT_SRC) $(OUTPUT_SRC) $(PROTO_SRC) $(PTYPE_SRC)

EXTRA_LTLIBRARIES = analyzer_jpeg.la datastore_sqlite.la datastore_postgres.la decoder_gzip.la input_pcap.la input_dvb.la output_inject.la output_pcap.la output_tap.la


analyzer_arp_la_SOURCES = analyzer/analyzer_arp.c analyzer/analyzer_arp.h
analyzer_arp_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_arp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_dns_la_SOURCES = analyzer/analyzer_dns.c analyzer/analyzer_dns.h
analyzer_dns_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_dns_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_docsis_la_SOURCES = analyzer/analyzer_docsis.c analyzer/analyzer_docsis.h
analyzer_docsis_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_docsis_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_dtmf_la_SOURCES = analyzer/analyzer_dtmf.c analyzer/analyzer_dtmf.h
analyzer_dtmf_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_dtmf_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_eap_la_SOURCES = analyzer/analyzer_eap.c analyzer/analyzer_eap.h
analyzer_eap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_eap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_gif_la_SOURCES = analyzer/analyzer_gif.c analyzer/analyzer_gif.h
analyzer_gif_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_gif_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_jpeg_la_SOURCES = analyzer/analyzer_jpeg.c analyzer/analyzer_jpeg.h
analyzer_jpeg_la_CFLAGS = $(AM_CFLAGS) @libexif_CFLAGS@
analyzer_jpeg_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -ljpeg
analyzer_jpeg_la_LIBADD = $(top_builddir)/src/libpom-ng.la @libexif_LIBS@
analyzer_http_la_SOURCES = analyzer/analyzer_http.c analyzer/analyzer_http.h analyzer/analyzer_http_post.c analyzer/analyzer_http_post.h
analyzer_http_la_LDFLAGS = -module -avoid-version
analyzer_http_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_multipart_la_SOURCES = analyzer/analyzer_multipart.c analyzer/analyzer_multipart.h
analyzer_multipart_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_multipart_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_png_la_SOURCES = analyzer/analyzer_png.c analyzer/analyzer_png.h
analyzer_png_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_png_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_ppp_chap_la_SOURCES = analyzer/analyzer_ppp_chap.c analyzer/analyzer_ppp_chap.h
analyzer_ppp_chap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_ppp_chap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_ppp_pap_la_SOURCES = analyzer/analyzer_ppp_pap.c analyzer/analyzer_ppp_pap.h
analyzer_ppp_pap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_ppp_pap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_rfc822_la_SOURCES = analyzer/analyzer_rfc822.c analyzer/analyzer_rfc822.h
analyzer_rfc822_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_rfc822_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_rtp_la_SOURCES = analyzer/analyzer_rtp.c analyzer/analyzer_rtp.h
analyzer_rtp_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_rtp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_sdp_la_SOURCES = analyzer/analyzer_sdp.c analyzer/analyzer_sdp.h
analyzer_sdp_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_sdp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_sip_la_SOURCES = analyzer/analyzer_sip.c analyzer/analyzer_sip.h
analyzer_sip_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_sip_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_smtp_la_SOURCES = analyzer/analyzer_smtp.c analyzer/analyzer_smtp.h
analyzer_smtp_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_smtp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
analyzer_tftp_la_SOURCES = analyzer/analyzer_tftp.c analyzer/analyzer_tftp.h
analyzer_tftp_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
analyzer_tftp_la_LIBADD = $(top_builddir)/src/libpom-ng.la

datastore_sqlite_la_SOURCES = datastore/datastore_sqlite.c datastore/datastore_sqlite.h
datastore_sqlite_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lsqlite3
datastore_sqlite_la_LIBADD = $(top_builddir)/src/libpom-ng.la
datastore_postgres_la_SOURCES = datastore/datastore_postgres.c datastore/datastore_postgres.h
datastore_postgres_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpq
datastore_postgres_la_LIBADD = $(top_builddir)/src/libpom-ng.la

decoder_base64_la_SOURCES = decoder/decoder_base64.c decoder/decoder_base64.h
decoder_base64_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
decoder_base64_la_LIBADD = $(top_builddir)/src/libpom-ng.la
decoder_gzip_la_SOURCES = decoder/decoder_gzip.c decoder/decoder_gzip.h
decoder_gzip_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
decoder_gzip_la_LIBADD = $(top_builddir)/src/libpom-ng.la
decoder_percent_la_SOURCES = decoder/decoder_percent.c decoder/decoder_percent.h
decoder_percent_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
decoder_percent_la_LIBADD = $(top_builddir)/src/libpom-ng.la
decoder_quoted_printable_la_SOURCES = decoder/decoder_quoted_printable.c decoder/decoder_quoted_printable.h
decoder_quoted_printable_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
decoder_quoted_printable_la_LIBADD = $(top_builddir)/src/libpom-ng.la

input_dvb_la_SOURCES = input/input_dvb.c input/input_dvb.h
input_dvb_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
input_dvb_la_LIBADD = $(top_builddir)/src/libpom-ng.la
input_kismet_la_SOURCES = input/input_kismet.c input/input_kismet.h
input_kismet_la_LDFLAGS = -module -avoid-version
input_kismet_la_LIBADD = $(top_builddir)/src/libpom-ng.la
input_pcap_la_SOURCES = input/input_pcap.c input/input_pcap.h
input_pcap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
input_pcap_la_LIBADD = $(top_builddir)/src/libpom-ng.la

output_file_la_SOURCES = output/output_file.c output/output_file.h
output_file_la_LDFLAGS = -module -avoid-version
output_file_la_LIBADD = $(top_builddir)/src/libpom-ng.la
output_inject_la_SOURCES = output/output_inject.c output/output_inject.h
output_inject_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
output_inject_la_LIBADD = $(top_builddir)/src/libpom-ng.la
output_log_la_SOURCES = output/output_log.c output/output_log.h output/output_log_txt.c output/output_log_txt.h output/output_log_xml.c output/output_log_xml.h
output_log_la_CFLAGS = $(AM_CFLAGS) @libxml2_CFLAGS@
output_log_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' @libxml2_LIBS@
output_log_la_LIBADD = $(top_builddir)/src/libpom-ng.la
output_pcap_la_SOURCES = output/output_pcap.c output/output_pcap.h
output_pcap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
output_pcap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
output_tap_la_SOURCES = output/output_tap.c output/output_tap.h
output_tap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
output_tap_la_LIBADD = $(top_builddir)/src/libpom-ng.la

proto_80211_la_SOURCES = proto/proto_80211.c proto/proto_80211.h
proto_80211_la_LDFLAGS = -module -avoid-version
proto_80211_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_8021x_la_SOURCES = proto/proto_8021x.c proto/proto_8021x.h
proto_8021x_la_LDFLAGS = -module -avoid-version
proto_8021x_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_arp_la_SOURCES = proto/proto_arp.c proto/proto_arp.h
proto_arp_la_LDFLAGS = -module -avoid-version
proto_arp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_dns_la_SOURCES = proto/proto_dns.c proto/proto_dns.h
proto_dns_la_LDFLAGS = -module -avoid-version
proto_dns_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_docsis_la_SOURCES = proto/proto_docsis.c proto/proto_docsis.h
proto_docsis_la_LDFLAGS = -module -avoid-version
proto_docsis_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_eap_la_SOURCES = proto/proto_eap.c proto/proto_eap.h
proto_eap_la_LDFLAGS = -module -avoid-version
proto_eap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ethernet_la_SOURCES = proto/proto_ethernet.c proto/proto_ethernet.h
proto_ethernet_la_LDFLAGS = -module -avoid-version
proto_ethernet_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_gre_la_SOURCES = proto/proto_gre.c proto/proto_gre.h
proto_gre_la_LDFLAGS = -module -avoid-version
proto_gre_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_http_la_SOURCES = proto/proto_http.c proto/proto_http.h
proto_http_la_LDFLAGS = -module -avoid-version
proto_http_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_icmp_la_SOURCES = proto/proto_icmp.c proto/proto_icmp.h
proto_icmp_la_LDFLAGS = -module -avoid-version
proto_icmp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_icmp6_la_SOURCES = proto/proto_icmp6.c proto/proto_icmp6.h
proto_icmp6_la_LDFLAGS = -module -avoid-version
proto_icmp6_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ipv4_la_SOURCES = proto/proto_ipv4.c proto/proto_ipv4.h
proto_ipv4_la_LDFLAGS = -module -avoid-version
proto_ipv4_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ipv6_la_SOURCES = proto/proto_ipv6.c proto/proto_ipv6.h
proto_ipv6_la_LDFLAGS = -module -avoid-version
proto_ipv6_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_mpeg_la_SOURCES = proto/proto_mpeg.c proto/proto_mpeg.h proto/proto_mpeg_ts.c proto/proto_mpeg_ts.h proto/proto_mpeg_sect.c proto/proto_mpeg_sect.h proto/proto_mpeg_dvb_mpe.c proto/proto_mpeg_dvb_mpe.h
proto_mpeg_la_LDFLAGS = -module -avoid-version
proto_mpeg_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ppi_la_SOURCES = proto/proto_ppi.c proto/proto_ppi.h
proto_ppi_la_LDFLAGS = -module -avoid-version
proto_ppi_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ppp_la_SOURCES = proto/proto_ppp.c proto/proto_ppp.h
proto_ppp_la_LDFLAGS = -module -avoid-version
proto_ppp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ppp_chap_la_SOURCES = proto/proto_ppp_chap.c proto/proto_ppp_chap.h
proto_ppp_chap_la_LDFLAGS = -module -avoid-version
proto_ppp_chap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_ppp_pap_la_SOURCES = proto/proto_ppp_pap.c proto/proto_ppp_pap.h
proto_ppp_pap_la_LDFLAGS = -module -avoid-version
proto_ppp_pap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_pppoe_la_SOURCES = proto/proto_pppoe.c proto/proto_pppoe.h
proto_pppoe_la_LDFLAGS = -module -avoid-version
proto_pppoe_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_radiotap_la_SOURCES = proto/proto_radiotap.c proto/proto_radiotap.h
proto_radiotap_la_LDFLAGS = -module -avoid-version
proto_radiotap_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_rtp_la_SOURCES = proto/proto_rtp.c proto/proto_rtp.h
proto_rtp_la_LDFLAGS = -module -avoid-version
proto_rtp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_sip_la_SOURCES = proto/proto_sip.c proto/proto_sip.h
proto_sip_la_LDFLAGS = -module -avoid-version
proto_sip_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_smtp_la_SOURCES = proto/proto_smtp.c proto/proto_smtp.h
proto_smtp_la_LDFLAGS = -module -avoid-version
proto_smtp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_tcp_la_SOURCES = proto/proto_tcp.c proto/proto_tcp.h
proto_tcp_la_LDFLAGS = -module -avoid-version
proto_tcp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_tftp_la_SOURCES = proto/proto_tftp.c proto/proto_tftp.h
proto_tftp_la_LDFLAGS = -module -avoid-version
proto_tftp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_udp_la_SOURCES = proto/proto_udp.c proto/proto_udp.h
proto_udp_la_LDFLAGS = -module -avoid-version
proto_udp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
proto_vlan_la_SOURCES = proto/proto_vlan.c proto/proto_vlan.h
proto_vlan_la_LDFLAGS = -module -avoid-version
proto_vlan_la_LIBADD = $(top_builddir)/src/libpom-ng.la

ptype_bool_la_SOURCES = ptype/ptype_bool.c ptype/ptype_bool.h
ptype_bool_la_LDFLAGS = -module -avoid-version 
ptype_bool_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_bytes_la_SOURCES = ptype/ptype_bytes.c ptype/ptype_bytes.h
ptype_bytes_la_LDFLAGS = -module -avoid-version 
ptype_bytes_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_mac_la_SOURCES = ptype/ptype_mac.c ptype/ptype_mac.h
ptype_mac_la_LDFLAGS = -module -avoid-version 
ptype_mac_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_ipv4_la_SOURCES = ptype/ptype_ipv4.c ptype/ptype_ipv4.h
ptype_ipv4_la_LDFLAGS = -module -avoid-version 
ptype_ipv4_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_ipv6_la_SOURCES = ptype/ptype_ipv6.c ptype/ptype_ipv6.h
ptype_ipv6_la_LDFLAGS = -module -avoid-version 
ptype_ipv6_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_uint8_la_SOURCES = ptype/ptype_uint8.c ptype/ptype_uint8.h
ptype_uint8_la_LDFLAGS = -module -avoid-version 
ptype_uint8_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_uint16_la_SOURCES = ptype/ptype_uint16.c ptype/ptype_uint16.h
ptype_uint16_la_LDFLAGS = -module -avoid-version 
ptype_uint16_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_uint32_la_SOURCES = ptype/ptype_uint32.c ptype/ptype_uint32.h
ptype_uint32_la_LDFLAGS = -module -avoid-version 
ptype_uint32_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_uint64_la_SOURCES = ptype/ptype_uint64.c ptype/ptype_uint64.h
ptype_uint64_la_LDFLAGS = -module -avoid-version 
ptype_uint64_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_string_la_SOURCES = ptype/ptype_string.c ptype/ptype_string.h
ptype_string_la_LDFLAGS = -module -avoid-version 
ptype_string_la_LIBADD = $(top_builddir)/src/libpom-ng.la
ptype_timestamp_la_SOURCES = ptype/ptype_timestamp.c ptype/ptype_timestamp.h
ptype_timestamp_la_LDFLAGS = -module -avoid-version 
ptype_timestamp_la_LIBADD = $(top_builddir)/src/libpom-ng.la
