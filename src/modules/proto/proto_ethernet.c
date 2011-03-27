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


static struct proto_dependency *proto_ipv4 = NULL, *proto_ipv6 = NULL, *proto_arp = NULL, *proto_vlan = NULL, *proto_pppoe = NULL;

// ptype for fields value template
static struct ptype *ptype_mac = NULL;

struct mod_reg_info* proto_ethernet_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ethernet_mod_register;
	reg_info.unregister_func = proto_ethernet_mod_unregister;

	return &reg_info;
}


static int proto_ethernet_mod_register(struct mod_reg *mod) {

	ptype_mac = ptype_alloc("mac");
	
	if (!ptype_mac)
		return POM_ERR;

	static struct proto_pkt_field fields[PROTO_ETHERNET_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_ETHERNET_FIELD_NUM + 1));
	fields[0].name = "src";
	fields[0].value_template = ptype_mac;
	fields[0].description = "Source address";
	fields[1].name = "dst";
	fields[1].value_template = ptype_mac;
	fields[1].description = "Destination address";

	static struct proto_reg_info proto_ethernet;
	memset(&proto_ethernet, 0, sizeof(struct proto_reg_info));
	proto_ethernet.name = "ethernet";
	proto_ethernet.api_ver = PROTO_API_VER;
	proto_ethernet.mod = mod;
	proto_ethernet.pkt_fields = fields;

	// No contrack here

	proto_ethernet.init = proto_ethernet_init;
	proto_ethernet.parse = proto_ethernet_parse;
	proto_ethernet.process = proto_ethernet_process;
	proto_ethernet.cleanup = proto_ethernet_cleanup;

	if (proto_register(&proto_ethernet) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_ethernet_init() {


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

static ssize_t proto_ethernet_parse(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	// TODO buffer stuff
	if (sizeof(struct ether_header) > s->plen)
		return POM_ERR;

	struct ether_header *ehdr = s->pload;

	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_ethernet_field_src], ehdr->ether_shost);
	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_ethernet_field_dst], ehdr->ether_dhost);


	return sizeof(struct ether_header);

}

static ssize_t proto_ethernet_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index, int hdr_len) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	struct ether_header *ehdr = s->pload;

	switch (ntohs(ehdr->ether_type)) {
		case 0x0800:
			s_next->proto = proto_ipv4->proto;
			break;
		case 0x0806:
			s_next->proto = proto_arp->proto;
			break;
		case 0x8100:
			s_next->proto = proto_vlan->proto;
			break;
		case 0x86dd:
			s_next->proto = proto_ipv6->proto;
			break;
		case 0x8863:
		case 0x8864:
			s_next->proto = proto_pppoe->proto;

		default:
			s_next->proto = NULL;
			break;

	}

	return s->plen - hdr_len;

}

static int proto_ethernet_cleanup() {

	int res = POM_OK;

	res += proto_remove_dependency(proto_ipv4);
	res += proto_remove_dependency(proto_ipv6);
	res += proto_remove_dependency(proto_arp);
	res += proto_remove_dependency(proto_vlan);
	res += proto_remove_dependency(proto_pppoe);

	return res;
}

static int proto_ethernet_mod_unregister() {

	int res = proto_unregister("ethernet");

	ptype_cleanup(ptype_mac);
	ptype_mac = NULL;

	return res;
}
