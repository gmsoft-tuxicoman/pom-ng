/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#include "proto_8021x.h"

#include <arpa/inet.h>

struct mod_reg_info* proto_8021x_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_8021x_mod_register;
	reg_info.unregister_func = proto_8021x_mod_unregister;
	reg_info.dependencies = "ptype_uint8";

	return &reg_info;
}

static int proto_8021x_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_8021X_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "version";
	fields[0].value_type = ptype_get_type("uint8");
	fields[0].description = "Version";
	fields[1].name = "type";
	fields[1].value_type = ptype_get_type("uint8");
	fields[1].description = "Packet type";

	static struct proto_reg_info proto_8021x = { 0 };
	proto_8021x.name = "8021x";
	proto_8021x.api_ver = PROTO_API_VER;
	proto_8021x.mod = mod;
	proto_8021x.pkt_fields = fields;
	proto_8021x.number_class = "8021x";


	struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 1; // No hashing done here
	proto_8021x.ct_info = &ct_info;

	proto_8021x.init = proto_8021x_init;
	proto_8021x.process = proto_8021x_process;

	if (proto_register(&proto_8021x) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_8021x_init(struct proto *proto, struct registry_instance *i) {

	return proto_number_register("ethernet", 0x888e, proto);
}

static int proto_8021x_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_prev = &stack[stack_index - 1];

	if (sizeof(struct ieee8021x_header) > s->plen)
		return PROTO_INVALID;

	if (s_prev->ce) {
		if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK)
			return POM_ERR;
	} else {
		// No conntrack is possible over ethernet since the destination mac address is a broadcast one for requests
		if (conntrack_get_unique(stack, stack_index) != POM_OK)
			return POM_ERR;
	}
	
	conntrack_unlock(s->ce);

	struct ieee8021x_header *hdr = s->pload;


	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_8021x_field_version], hdr->version);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_8021x_field_type], hdr->type);

	struct proto_process_stack *s_next = &stack[stack_index + 1];

	s_next->pload = s->pload + sizeof(struct ieee8021x_header);
	s_next->plen = ntohs(hdr->length);
	s_next->proto = proto_get_by_number(s->proto, hdr->type);

	return PROTO_OK;

}

static int proto_8021x_mod_unregister() {

	return proto_unregister("8021x");
}
