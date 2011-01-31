/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <pom-ng/ptype.h>
#include <pom-ng/proto.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>

#include "proto_tcp.h"

#include <string.h>
#include <arpa/inet.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>


static struct proto_dependency *proto_http = NULL;

// ptypes for fields value template
static struct ptype *ptype_uint8 = NULL, *ptype_uint16 = NULL, *ptype_uint32 = NULL;

struct mod_reg_info* proto_tcp_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_tcp_mod_register;
	reg_info.unregister_func = proto_tcp_mod_unregister;

	return &reg_info;
}


static int proto_tcp_mod_register(struct mod_reg *mod) {

	ptype_uint8 = ptype_alloc("uint8");
	ptype_uint16 = ptype_alloc("uint16");
	ptype_uint32 = ptype_alloc("uint32");
	
	if (!ptype_uint8 || !ptype_uint16 || !ptype_uint32)
		goto err;

	static struct proto_pkt_field fields[PROTO_TCP_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_TCP_FIELD_NUM + 1));
	fields[0].name = "sport";
	fields[0].value_template = ptype_uint16;
	fields[0].description = "Source port";
	fields[1].name = "dport";
	fields[1].value_template = ptype_uint16;
	fields[1].description = "Destination port";
	fields[2].name = "flags";
	fields[2].value_template = ptype_uint8;
	fields[2].description = "Flags";
	fields[3].name = "seq";
	fields[3].value_template = ptype_uint32;
	fields[3].description = "Sequence";
	fields[4].name = "ack";
	fields[4].value_template = ptype_uint32;
	fields[4].description = "Sequence ACK";
	fields[5].name = "win";
	fields[5].value_template = ptype_uint16;
	fields[5].description = "Window";


	static struct proto_reg_info proto_tcp;
	memset(&proto_tcp, 0, sizeof(struct proto_reg_info));
	proto_tcp.name = "tcp";
	proto_tcp.api_ver = PROTO_API_VER;
	proto_tcp.mod = mod;
	proto_tcp.pkt_fields = fields;
	
	proto_tcp.ct_info.default_table_size = 20000;
	proto_tcp.ct_info.fwd_pkt_field_id = proto_tcp_field_sport;
	proto_tcp.ct_info.rev_pkt_field_id = proto_tcp_field_dport;
	
	proto_tcp.init = proto_tcp_init;
	proto_tcp.parse = proto_tcp_parse;
	proto_tcp.cleanup = proto_tcp_cleanup;


	if (proto_register(&proto_tcp) == POM_OK)
		return POM_OK;

err:
	if (ptype_uint8) {
		ptype_cleanup(ptype_uint8);
		ptype_uint8 = NULL;
	}
	if (ptype_uint16) {
		ptype_cleanup(ptype_uint16);
		ptype_uint16 = NULL;
	}
	if (ptype_uint32) {
		ptype_cleanup(ptype_uint32);
		ptype_uint32 = NULL;
	}
	return POM_ERR;

}


static int proto_tcp_init() {

	proto_http = proto_add_dependency("http");

	if (!proto_http) {
		proto_tcp_cleanup();
		return POM_ERR;
	}

	return POM_OK;
}

static size_t proto_tcp_parse(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];


	if (s->plen < sizeof(struct tcphdr)) {
		s->proto = NULL; // Invalid (CHECKME)
		return POM_OK;
	}

	struct tcphdr* hdr = s->pload;

	unsigned int hdrlen = (hdr->th_off << 2);

	if (hdrlen > s->plen || hdrlen < 20) {
		s->proto = NULL; // Incomplete or invalid packet
		return POM_OK;
	}
	
	s_next->pload = s->pload + hdrlen;
	s_next->plen = s->plen - hdrlen;

	if ((hdr->th_flags & TH_RST) && s_next->plen > 0)
		s_next->plen = 0; // RFC 1122 4.2.2.12 : RST may contain the data that caused the packet to be sent, discard it
	
	if ((hdr->th_flags & TH_SYN) && s_next->plen > 0) {
		s->proto = NULL; // Invalid packet, SYN or RST flag present and len > 0
		return POM_OK;
	}

	if ((hdr->th_flags & TH_SYN) && ((hdr->th_flags & TH_RST) || (hdr->th_flags & TH_FIN))) {
		s->proto = NULL; // Invalid packet SYN and either RST or FIN flag present
		return POM_OK;
	}

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tcp_field_sport], ntohs(hdr->th_sport));
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tcp_field_dport], ntohs(hdr->th_dport));
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tcp_field_flags], hdr->th_flags);
	PTYPE_UINT32_SETVAL(s->pkt_info->fields_value[proto_tcp_field_seq], ntohl(hdr->th_seq));
	PTYPE_UINT32_SETVAL(s->pkt_info->fields_value[proto_tcp_field_ack], ntohl(hdr->th_ack));
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tcp_field_win], ntohl(hdr->th_win));


	// Conntrack stuff
	s->ct_field_fwd = s->pkt_info->fields_value[proto_tcp_field_sport];
	s->ct_field_rev = s->pkt_info->fields_value[proto_tcp_field_dport];

	// TODO improve this
	
	if (ntohs(hdr->th_sport) == 80 || ntohs(hdr->th_dport) == 80)
		s_next->proto = proto_http->proto;
	else
		s_next->proto = NULL;

	return POM_OK;

}

static int proto_tcp_cleanup() {

	ptype_cleanup(ptype_uint8);
	ptype_uint8 = NULL;
	ptype_cleanup(ptype_uint16);
	ptype_uint16 = NULL;
	ptype_cleanup(ptype_uint32);
	ptype_uint32 = NULL;

	int res = POM_OK;

	res += proto_remove_dependency(proto_http);

	return res;
}

static int proto_tcp_mod_unregister() {

	return proto_unregister("tcp");
}
