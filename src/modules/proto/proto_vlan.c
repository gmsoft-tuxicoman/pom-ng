/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>

#include <pom-ng/proto_vlan.h>
#include "proto_vlan.h"

#include <arpa/inet.h>

static struct proto *proto_arp = NULL, *proto_ipv4 = NULL, *proto_ipv6 = NULL, *proto_pppoe = NULL;

struct mod_reg_info* proto_vlan_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_vlan_mod_register;
	reg_info.unregister_func = proto_vlan_mod_unregister;
	reg_info.dependencies = "proto_arp, proto_ipv4, proto_ipv6, proto_pppoe, ptype_bool, ptype_uint8, ptype_uint16";

	return &reg_info;
}

static int proto_vlan_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_VLAN_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "vid";
	fields[0].value_type = ptype_get_type("uint16");
	fields[0].description = "VLAN id";
	fields[1].name = "de";
	fields[1].value_type = ptype_get_type("bool");
	fields[1].description = "Drop eligible";
	fields[2].name = "pcp";
	fields[2].value_type = ptype_get_type("uint8");
	fields[3].description = "Priority Code Point";

	static struct proto_reg_info proto_vlan = { 0 };
	proto_vlan.name = "vlan";
	proto_vlan.api_ver = PROTO_API_VER;
	proto_vlan.mod = mod;
	proto_vlan.pkt_fields = fields;

	// No contrack here

	proto_vlan.init = proto_vlan_init;
	proto_vlan.process = proto_vlan_process;

	if (proto_register(&proto_vlan) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_vlan_init(struct proto *proto, struct registry_instance *i) {
	
	proto_arp = proto_get("arp");
	proto_ipv4 = proto_get("ipv4");
	proto_ipv6 = proto_get("ipv6");
	proto_pppoe = proto_get("pppoe");

	if (!proto_arp || !proto_ipv4 || !proto_ipv6 || !proto_pppoe) {
		pomlog(POMLOG_ERR "Could not get hold of all the needed protocols");
		return POM_ERR;
	}

	return POM_OK;

}

static int proto_vlan_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (s->plen < PROTO_VLAN_HEADER_SIZE)
		return PROTO_INVALID;

	uint16_t tci = ntohs(*(uint16_t*)s->pload);
	uint16_t *ether_type = s->pload + sizeof(uint16_t);


	uint16_t de = (tci & PROTO_VLAN_DE_MASK) >> PROTO_VLAN_DE_SHIFT;
	uint16_t pcp = (tci & PROTO_VLAN_PCP_MASK) >> PROTO_VLAN_PCP_SHIFT;
	uint16_t vid = tci & PROTO_VLAN_VID_MASK;

	
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_vlan_field_vid], vid);
	PTYPE_BOOL_SETVAL(s->pkt_info->fields_value[proto_vlan_field_de], de);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_vlan_field_pcp], pcp);

	struct proto_process_stack *s_next = &stack[stack_index + 1];

	s_next->pload = s->pload + PROTO_VLAN_HEADER_SIZE;
	s_next->plen = s->plen - PROTO_VLAN_HEADER_SIZE;

	switch (ntohs(*ether_type)) {
		case 0x0800:
			s_next->proto = proto_ipv4;
			break;
		case 0x0806:
			s_next->proto = proto_arp;
			break;
		case 0x8100:
			s_next->proto = proto;
			break;

		case 0x86dd:
			s_next->proto = proto_ipv6;
			break;

		case 0x8863:
		case 0x8864:
			s_next->proto = proto_pppoe;
			break;

		default:
			s_next->proto = NULL;
			break;

	}

	return PROTO_OK;

}

static int proto_vlan_mod_unregister() {

	return proto_unregister("vlan");
}
