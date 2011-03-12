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
#include <pom-ng/ptype_ipv4.h>
#include <pom-ng/ptype_uint8.h>

#include "proto_ipv4.h"

#include <string.h>
#include <arpa/inet.h>


static struct proto_dependency *proto_icmp = NULL, *proto_tcp = NULL, *proto_udp = NULL, *proto_ipv6 = NULL, *proto_gre = NULL;

static struct ptype *ptype_uint8 = NULL, *ptype_ipv4 = NULL;

struct mod_reg_info* proto_ipv4_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ipv4_mod_register;
	reg_info.unregister_func = proto_ipv4_mod_unregister;

	return &reg_info;
}


static int proto_ipv4_mod_register(struct mod_reg *mod) {

	ptype_uint8 = ptype_alloc("uint8");
	ptype_ipv4 = ptype_alloc("ipv4");

	if (!ptype_uint8 || !ptype_ipv4)
		goto err;

	static struct proto_pkt_field fields[PROTO_IPV4_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_IPV4_FIELD_NUM + 1));
	fields[0].name = "src";
	fields[0].value_template = ptype_ipv4;
	fields[0].description = "Source address";
	fields[1].name = "dst";
	fields[1].value_template = ptype_ipv4;
	fields[1].description = "Destination address";
	fields[2].name = "tos";
	fields[2].value_template = ptype_uint8;
	fields[2].description = "Type of service";
	fields[3].name = "ttl";
	fields[3].value_template = ptype_uint8;
	fields[3].description = "Time to live";

	static struct proto_reg_info proto_ipv4;
	memset(&proto_ipv4, 0, sizeof(struct proto_reg_info));
	proto_ipv4.name = "ipv4";
	proto_ipv4.api_ver = PROTO_API_VER;
	proto_ipv4.mod = mod;

	proto_ipv4.pkt_fields = fields;
	proto_ipv4.ct_info.default_table_size = 20000;
	proto_ipv4.ct_info.fwd_pkt_field_id = proto_ipv4_field_src;
	proto_ipv4.ct_info.rev_pkt_field_id = proto_ipv4_field_dst;
	
	proto_ipv4.init = proto_ipv4_init;
	proto_ipv4.parse = proto_ipv4_parse;
	proto_ipv4.process = proto_ipv4_process;
	proto_ipv4.cleanup = proto_ipv4_cleanup;

	if (proto_register(&proto_ipv4) == POM_OK)
		return POM_OK;

err:
	if (ptype_uint8) {
		ptype_cleanup(ptype_uint8);
		ptype_uint8 = NULL;
	}
	if (ptype_ipv4) {
		ptype_cleanup(ptype_ipv4);
		ptype_ipv4 = NULL;
	}

	return POM_ERR;
}


static int proto_ipv4_init() {

	proto_icmp = proto_add_dependency("icmp");
	proto_tcp = proto_add_dependency("tcp");
	proto_udp = proto_add_dependency("udp");
	proto_ipv6 = proto_add_dependency("ipv6");
	proto_gre = proto_add_dependency("gre");

	if (!proto_icmp || !proto_tcp || !proto_udp || !proto_ipv6 || !proto_gre) {
		proto_ipv4_cleanup();
		return POM_ERR;
	}

	return POM_OK;
}

static ssize_t proto_ipv4_parse(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {


	struct proto_process_stack *s = &stack[stack_index];

	struct in_addr saddr, daddr;
	struct ip* hdr = s->pload;
	saddr.s_addr = hdr->ip_src.s_addr;
	daddr.s_addr = hdr->ip_dst.s_addr;

	unsigned int hdr_len = hdr->ip_hl * 4;

	if (s->plen < sizeof(struct ip) || // lenght smaller than header
		hdr->ip_hl < 5 || // ip header < 5 bytes
		ntohs(hdr->ip_len) < hdr_len || // datagram size < ip header length
		ntohs(hdr->ip_len) > s->plen) { // datagram size > given size
		s->proto = NULL;
		return POM_OK;
	}


	PTYPE_IPV4_SETADDR(s->pkt_info->fields_value[proto_ipv4_field_src], hdr->ip_src);
	PTYPE_IPV4_SETADDR(s->pkt_info->fields_value[proto_ipv4_field_dst], hdr->ip_dst);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ipv4_field_tos], hdr->ip_tos);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ipv4_field_ttl], hdr->ip_ttl);

	// Handle conntrack stuff
	s->ct_field_fwd = s->pkt_info->fields_value[proto_ipv4_field_src];
	s->ct_field_rev = s->pkt_info->fields_value[proto_ipv4_field_dst];

	return hdr_len;

}

static ssize_t proto_ipv4_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index, int hdr_len) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	struct ip* hdr = s->pload;

	switch (hdr->ip_p) {
		case IPPROTO_ICMP: // 1
			s_next->proto = proto_icmp->proto;
			break;
		case IPPROTO_TCP: // 6
			s_next->proto = proto_tcp->proto;
			break;
		case IPPROTO_UDP: // 17
			s_next->proto = proto_udp->proto;
			break;
		case IPPROTO_IPV6: // 41
			s_next->proto = proto_ipv6->proto;
			break;
		case IPPROTO_GRE: // 47
			s_next->proto = proto_gre->proto;
			break;

		default:
			s_next->proto = NULL;
			break;

	}
	

	return s->plen - hdr_len;

}


static int proto_ipv4_cleanup() {

	ptype_cleanup(ptype_uint8);
	ptype_uint8 = NULL;
	ptype_cleanup(ptype_ipv4);
	ptype_ipv4 = NULL;

	int res = POM_OK;

//	res += packet_unregister_info_owner(proto_ipv4_packet_info_owner);

	res += proto_remove_dependency(proto_icmp);
	res += proto_remove_dependency(proto_udp);
	res += proto_remove_dependency(proto_tcp);
	res += proto_remove_dependency(proto_ipv6);
	res += proto_remove_dependency(proto_gre);

	return res;
}

static int proto_ipv4_mod_unregister() {

	return proto_unregister("ipv4");
}
