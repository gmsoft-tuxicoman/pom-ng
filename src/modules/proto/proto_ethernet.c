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
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_mac.h>

#include "proto_ethernet.h"

#include <string.h>
#include <arpa/inet.h>


static struct packet_info_owner *proto_ethernet_packet_info_owner = NULL;
static struct proto_dependency *proto_ipv4 = NULL, *proto_ipv6 = NULL, *proto_arp = NULL, *proto_vlan = NULL, *proto_pppoe = NULL;

struct mod_reg_info* proto_ethernet_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ethernet_mod_register;
	reg_info.unregister_func = proto_ethernet_mod_unregister;

	return &reg_info;
}


static int proto_ethernet_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_ethernet;
	memset(&proto_ethernet, 0, sizeof(struct proto_reg_info));
	proto_ethernet.name = "ethernet";
	proto_ethernet.api_ver = PROTO_API_VER;
	proto_ethernet.mod = mod;
	proto_ethernet.init = proto_ethernet_init;
	proto_ethernet.process = proto_ethernet_process;
	proto_ethernet.cleanup = proto_ethernet_cleanup;

	proto_register(&proto_ethernet);
	return POM_OK;

}


static int proto_ethernet_init() {

	const int proto_ethernet_info_max = 2;

	struct packet_info_reg infos[proto_ethernet_info_max + 1];
	memset(infos, 0, sizeof(struct packet_info_reg) * (proto_ethernet_info_max + 1));
	infos[0].name = "src";
	infos[0].value_template = ptype_alloc("mac");
	infos[1].name = "dst";
	infos[1].value_template = ptype_alloc("mac");

	proto_ethernet_packet_info_owner = packet_register_info_owner("ethernet", infos);
	if (!proto_ethernet_packet_info_owner) {
		ptype_cleanup(infos[0].value_template);
		ptype_cleanup(infos[1].value_template);
		return POM_ERR;
	}

	proto_ipv4 = proto_add_dependency("ipv4");
	proto_ipv6 = proto_add_dependency("ipv6");
	proto_arp = proto_add_dependency("arp");
	proto_vlan = proto_add_dependency("vlan");
	proto_pppoe = proto_add_dependency("pppoe");

	if (!proto_ipv4 || !proto_ipv6 || !proto_arp || !proto_vlan || !proto_pppoe) {
		proto_ethernet_cleanup();
		return POM_ERR;
	}

	return POM_OK;

}

static size_t proto_ethernet_process(struct packet *p, struct proto_process_state *s) {

	// TODO buffer stuff
	if (sizeof(struct ether_header) > s->plen)
		return POM_ERR;

	struct packet_info_list *infos = packet_add_infos(p, proto_ethernet_packet_info_owner);

	struct ether_header *ehdr = s->pload;


	PTYPE_MAC_SETADDR(infos->values[0].value, ehdr->ether_shost);
	PTYPE_MAC_SETADDR(infos->values[1].value, ehdr->ether_dhost);

	switch (ntohs(ehdr->ether_type)) {
		case 0x0800:
			s->next_proto = proto_ipv4->proto;
			break;
		case 0x0806:
			s->next_proto = proto_arp->proto;
			break;
		case 0x8100:
			s->next_proto = proto_vlan->proto;
			break;
		case 0x86dd:
			s->next_proto = proto_ipv6->proto;
			break;
		case 0x8863:
		case 0x8864:
			s->next_proto = proto_pppoe->proto;

		default:
			s->next_proto = NULL;
			break;

	}

	s->pload += sizeof(struct ether_header);
	s->plen -= sizeof(struct ether_header);

	return POM_OK;

}

static int proto_ethernet_cleanup() {

	int res = POM_OK;

	res += packet_unregister_info_owner(proto_ethernet_packet_info_owner);

	res += proto_remove_dependency(proto_ipv4);
	res += proto_remove_dependency(proto_ipv6);
	res += proto_remove_dependency(proto_arp);
	res += proto_remove_dependency(proto_vlan);
	res += proto_remove_dependency(proto_pppoe);

	return res;
}

static int proto_ethernet_mod_unregister() {

	return proto_unregister("ethernet");
}
