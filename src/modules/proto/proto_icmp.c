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

#include "proto_icmp.h"

#include <string.h>


// ptype for fields value template
static struct ptype *ptype_uint8 = NULL;

struct mod_reg_info* proto_icmp_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_icmp_mod_register;
	reg_info.unregister_func = proto_icmp_mod_unregister;

	return &reg_info;
}


static int proto_icmp_mod_register(struct mod_reg *mod) {

	ptype_uint8 = ptype_alloc("uint8");
	
	if (!ptype_uint8)
		return POM_ERR;

	static struct proto_pkt_field fields[PROTO_ICMP_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_ICMP_FIELD_NUM + 1));
	fields[0].name = "type";
	fields[0].value_template = ptype_uint8;
	fields[0].description = "Type";
	fields[1].name = "code";
	fields[1].value_template = ptype_uint8;
	fields[1].description = "Code";

	static struct proto_reg_info proto_icmp;
	memset(&proto_icmp, 0, sizeof(struct proto_reg_info));
	proto_icmp.name = "icmp";
	proto_icmp.api_ver = PROTO_API_VER;
	proto_icmp.mod = mod;
	proto_icmp.pkt_fields = fields;

	// No contrack here

	proto_icmp.parse = proto_icmp_parse;
	proto_icmp.process = proto_icmp_process;

	if (proto_register(&proto_icmp) == POM_OK)
		return POM_OK;

	return POM_ERR;

}


static ssize_t proto_icmp_parse(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	struct icmp *ihdr = s->pload;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_icmp_field_type], ihdr->icmp_type);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_icmp_field_code], ihdr->icmp_code);


	return sizeof(uint8_t) * 2;

}

static ssize_t proto_icmp_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index, int hdr_len) {

	struct proto_process_stack *s = &stack[stack_index];

	return s->plen - hdr_len;

}

static int proto_icmp_mod_unregister() {

	int res = proto_unregister("icmp");

	ptype_cleanup(ptype_uint8);
	ptype_uint8 = NULL;

	return res;
}
