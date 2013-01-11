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
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>

#include "proto_pppoe.h"

#include <string.h>
#include <arpa/inet.h>

static struct proto *proto_ppp = NULL;

struct mod_reg_info* proto_pppoe_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_pppoe_mod_register;
	reg_info.unregister_func = proto_pppoe_mod_unregister;
	reg_info.dependencies = "ptype_uint8, ptype_uint16, proto_ppp";

	return &reg_info;
}

static int proto_pppoe_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_PPPOE_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "code";
	fields[0].value_type = ptype_get_type("uint8");
	fields[0].description = "Code";
	fields[1].name = "session_id";
	fields[1].value_type = ptype_get_type("uint16");
	fields[1].description = "Session ID";

	static struct proto_reg_info proto_pppoe = { 0 };
	proto_pppoe.name = "pppoe";
	proto_pppoe.api_ver = PROTO_API_VER;
	proto_pppoe.mod = mod;
	proto_pppoe.pkt_fields = fields;

	proto_pppoe.init = proto_pppoe_init;
	proto_pppoe.process = proto_pppoe_process;

	if (proto_register(&proto_pppoe) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_pppoe_init(struct proto *proto, struct registry_instance *i) {

	proto_ppp = proto_get("ppp");

	if (!proto_ppp) {
		pomlog(POMLOG_ERR "Could not get hold of all the needed protocols");
		return POM_ERR;
	}

	return POM_OK;

}

static int proto_pppoe_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct pppoe_header) > s->plen)
		return PROTO_INVALID;

	struct pppoe_header *phdr = s->pload;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_pppoe_field_code], phdr->code);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_pppoe_field_session_id],ntohs(phdr->session_id));

	struct proto_process_stack *s_next = &stack[stack_index + 1];

	s_next->pload = s->pload + sizeof(struct pppoe_header);

	if(ntohs(phdr->len) > s->plen - sizeof(struct pppoe_header))
		return PROTO_INVALID;

	s_next->plen  = ntohs(phdr->len);
	s_next->proto = proto_ppp;

	return PROTO_OK;

}

static int proto_pppoe_mod_unregister() {

	return proto_unregister("pppoe");
}
