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


static struct packet_info_owner *proto_ipv4_packet_info_owner = NULL;
static struct proto_dependency *proto_icmp = NULL, *proto_tcp = NULL, *proto_udp = NULL, *proto_ipv6 = NULL, *proto_gre = NULL;

struct mod_reg_info* proto_ipv4_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ipv4_mod_register;
	reg_info.unregister_func = proto_ipv4_mod_unregister;

	return &reg_info;
}


static int proto_ipv4_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_ipv4;
	memset(&proto_ipv4, 0, sizeof(struct proto_reg_info));
	proto_ipv4.name = "ipv4";
	proto_ipv4.api_ver = PROTO_API_VER;
	proto_ipv4.mod = mod;
	proto_ipv4.init = proto_ipv4_init;
	proto_ipv4.process = proto_ipv4_process;
	proto_ipv4.cleanup = proto_ipv4_cleanup;

	proto_register(&proto_ipv4);
	return POM_OK;

}


static int proto_ipv4_init() {

	const int proto_ipv4_info_max = 4;

	struct packet_info_reg infos[proto_ipv4_info_max + 1];
	memset(infos, 0, sizeof(struct packet_info_reg) * (proto_ipv4_info_max + 1));
	infos[0].name = "src";
	infos[0].value_template = ptype_alloc("ipv4");
	infos[1].name = "dst";
	infos[1].value_template = ptype_alloc("ipv4");
	infos[2].name = "tos";
	infos[2].value_template = ptype_alloc("uint8");
	infos[3].name = "ttl";
	infos[3].value_template = ptype_alloc("uint8");

	proto_ipv4_packet_info_owner = packet_register_info_owner("ipv4", infos);
	if (!proto_ipv4_packet_info_owner) {
		ptype_cleanup(infos[0].value_template);
		ptype_cleanup(infos[1].value_template);
		ptype_cleanup(infos[2].value_template);
		ptype_cleanup(infos[3].value_template);
		return POM_ERR;
	}

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

static size_t proto_ipv4_process(struct packet *p, struct proto_process_state *s) {


	struct in_addr saddr, daddr;
	struct ip* hdr = s->pload;
	saddr.s_addr = hdr->ip_src.s_addr;
	daddr.s_addr = hdr->ip_dst.s_addr;

	unsigned int hdr_len = hdr->ip_hl * 4;

	if (s->plen < sizeof(struct ip) || // lenght smaller than header
		hdr->ip_hl < 5 || // ip header < 5 bytes
		ntohs(hdr->ip_len) < hdr_len || // datagram size < ip header length
		ntohs(hdr->ip_len) > s->plen) // datagram size > given size
		return POM_ERR;


	struct packet_info_list *infos = packet_add_infos(p, proto_ipv4_packet_info_owner);

	PTYPE_IPV4_SETADDR(infos->values[0].value, hdr->ip_src);
	PTYPE_IPV4_SETADDR(infos->values[1].value, hdr->ip_dst);
	PTYPE_UINT8_SETVAL(infos->values[2].value, hdr->ip_tos);
	PTYPE_UINT8_SETVAL(infos->values[3].value, hdr->ip_ttl);


	switch (hdr->ip_p) {
		case IPPROTO_ICMP: // 1
			s->next_proto = proto_icmp->proto;
			break;
		case IPPROTO_TCP: // 6
			s->next_proto = proto_tcp->proto;
			break;
		case IPPROTO_UDP: // 17
			s->next_proto = proto_udp->proto;
			break;
		case IPPROTO_IPV6: // 41
			s->next_proto = proto_ipv6->proto;
			break;
		case IPPROTO_GRE: // 47
			s->next_proto = proto_gre->proto;

		default:
			s->next_proto = NULL;
			break;

	}

	s->pload += hdr_len;
	s->plen = ntohs(hdr->ip_len) - hdr_len;

	return POM_OK;

}

static int proto_ipv4_cleanup() {

	int res = POM_OK;

	res += packet_unregister_info_owner(proto_ipv4_packet_info_owner);

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
