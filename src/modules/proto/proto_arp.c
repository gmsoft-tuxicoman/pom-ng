/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_mac.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_ipv4.h>
#include <pom-ng/proto_arp.h>

#include "proto_arp.h"

struct mod_reg_info* proto_arp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_arp_mod_register;
	reg_info.unregister_func = proto_arp_mod_unregister;
	reg_info.dependencies = "ptype_uint16, ptype_mac, ptype_ipv4";

	return &reg_info;
}


static int proto_arp_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_ARP_FIELD_NUM + 1] = { { 0 } };
	fields[proto_arp_field_oper].name = "oper";
	fields[proto_arp_field_oper].value_type = ptype_get_type("uint16");
	fields[proto_arp_field_oper].description = "Operation";
	fields[proto_arp_field_sender_hw_addr].name = "sender_hw_addr";
	fields[proto_arp_field_sender_hw_addr].value_type = ptype_get_type("mac");
	fields[proto_arp_field_sender_hw_addr].description = "Sender hardware address";
	fields[proto_arp_field_sender_proto_addr].name = "sender_proto_addr";
	fields[proto_arp_field_sender_proto_addr].value_type = ptype_get_type("ipv4");
	fields[proto_arp_field_sender_proto_addr].description = "Sender protocol address";
	fields[proto_arp_field_target_hw_addr].name = "target_hw_addr";
	fields[proto_arp_field_target_hw_addr].value_type = ptype_get_type("mac");
	fields[proto_arp_field_target_hw_addr].description = "Target hardware address";
	fields[proto_arp_field_target_proto_addr].name = "target_proto_addr";
	fields[proto_arp_field_target_proto_addr].value_type = ptype_get_type("ipv4");
	fields[proto_arp_field_target_proto_addr].description = "Target protocol address";


	static struct proto_reg_info proto_arp = { 0 };
	proto_arp.name = "arp";
	proto_arp.api_ver = PROTO_API_VER;
	proto_arp.mod = mod;
	proto_arp.pkt_fields = fields;

	// No contrack here

	proto_arp.process = proto_arp_process;

	return proto_register(&proto_arp);

}

static int proto_arp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct arp_packet) > s->plen)
		return PROTO_INVALID;

	struct arp_packet *apkt = s->pload;

	if (ntohs(apkt->hw_type) != 0x1)
		// We only support arp for ethernet links for now
		return PROTO_INVALID;

	if (ntohs(apkt->proto_type) != 0x0800)
		// We only support arp for IPv4 addresses
		return PROTO_INVALID;

	if (apkt->hw_addr_len != 6)
		// Ethernet addresses are 6 bytes long
		return PROTO_INVALID;

	if (apkt->proto_addr_len != 4)
		// IPv4 addresses are 4 bytes long
		return PROTO_INVALID;

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_arp_field_oper], ntohs(apkt->oper));
	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_arp_field_sender_hw_addr], apkt->sender_hw_addr);
	PTYPE_IPV4_SETADDR(s->pkt_info->fields_value[proto_arp_field_sender_proto_addr], apkt->sender_proto_addr);
	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_arp_field_target_hw_addr], apkt->target_hw_addr);
	PTYPE_IPV4_SETADDR(s->pkt_info->fields_value[proto_arp_field_target_proto_addr], apkt->target_proto_addr);


	return PROTO_OK;

}


static int proto_arp_mod_unregister() {

	return proto_unregister("arp");
}
