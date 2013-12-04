/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/conntrack.h>
#include <pom-ng/ptype_mac.h>
#include <pom-ng/ptype_uint16.h>

#include "proto_ethernet.h"

#include <arpa/inet.h>

struct mod_reg_info* proto_ethernet_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ethernet_mod_register;
	reg_info.unregister_func = proto_ethernet_mod_unregister;
	reg_info.dependencies = "ptype_mac";

	return &reg_info;
}

static int proto_ethernet_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_ETHERNET_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "src";
	fields[0].value_type = ptype_get_type("mac");
	fields[0].description = "Source address";
	fields[1].name = "dst";
	fields[1].value_type = ptype_get_type("mac");
	fields[1].description = "Destination address";
	fields[2].name = "type";
	fields[2].value_type = ptype_get_type("uint16");
	fields[2].description = "Ethernet type";

	static struct proto_reg_info proto_ethernet = { 0 };
	proto_ethernet.name = "ethernet";
	proto_ethernet.api_ver = PROTO_API_VER;
	proto_ethernet.mod = mod;
	proto_ethernet.pkt_fields = fields;
	proto_ethernet.number_class = "ethernet";

	// Conntracks are only used for 802.1X
	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 16;
	ct_info.fwd_pkt_field_id = proto_ethernet_field_src;
	ct_info.rev_pkt_field_id = proto_ethernet_field_dst;
	proto_ethernet.ct_info = &ct_info;

	proto_ethernet.process = proto_ethernet_process;

	if (proto_register(&proto_ethernet) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_ethernet_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct ether_header) > s->plen)
		return PROTO_INVALID;

	struct ether_header *ehdr = s->pload;

	uint16_t eth_type = ntohs(ehdr->ether_type);

	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_ethernet_field_src], ehdr->ether_shost);
	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_ethernet_field_dst], ehdr->ether_dhost);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_ethernet_field_type], eth_type);

	if (eth_type == 0x888e) {
		if (conntrack_get(stack, stack_index) != POM_OK)
			return PROTO_ERR;
		conntrack_unlock(s->ce);
	}

	struct proto_process_stack *s_next = &stack[stack_index + 1];

	s_next->pload = s->pload + sizeof(struct ether_header);
	s_next->plen = s->plen - sizeof(struct ether_header);
	s_next->proto = proto_get_by_number(s->proto, eth_type);

	return PROTO_OK;

}

static int proto_ethernet_mod_unregister() {

	return proto_unregister("ethernet");
}
