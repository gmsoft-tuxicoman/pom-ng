/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Dimitrios Karametos <dkarametos@gmail.com>
 *  Copyright (C) 2012-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#include "proto_ppp.h"

#include <string.h>
#include <arpa/inet.h>

struct mod_reg_info* proto_ppp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ppp_mod_register;
	reg_info.unregister_func = proto_ppp_mod_unregister;

	return &reg_info;
}

static int proto_ppp_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_ppp = { 0 };
	proto_ppp.name = "ppp";
	proto_ppp.api_ver = PROTO_API_VER;
	proto_ppp.mod = mod;
	proto_ppp.number_class = "ppp";

	struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 1; // No hashing done here
	proto_ppp.ct_info = &ct_info;

	proto_ppp.init = proto_ppp_init;
	proto_ppp.process = proto_ppp_process;

	if (proto_register(&proto_ppp) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_ppp_init(struct proto *proto, struct registry_instance *i) {

	return proto_number_register("ethernet", 0x880b, proto);
}


static int proto_ppp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	uint16_t ppp_type = 0;

	if (sizeof(struct ppp_comp_header) > s->plen)
		return PROTO_INVALID;

	struct proto_process_stack *s_next = &stack[stack_index + 1];
	size_t hdrlen = 0;

	if (*(uint8_t*)s->pload == 0xff) {
		if (sizeof(struct ppp_header) > s->plen)
			return PROTO_INVALID;
		struct ppp_header *phdr = s->pload;
		ppp_type = ntohs(phdr->ppp_type);
		hdrlen = sizeof(struct ppp_header);
	} else {
		struct ppp_comp_header *phdr = s->pload;
		ppp_type = ntohs(phdr->ppp_type);
		hdrlen = sizeof(struct ppp_comp_header);
	}

	struct proto_process_stack *s_prev = &stack[stack_index - 1];
	if (!s_prev->proto) { // We are the link protocol
		if (conntrack_get_unique(stack, stack_index) != POM_OK) {
			pomlog(POMLOG_ERR "Could not get conntrack entry");
			return POM_ERR;
		}
	} else {

		if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK) {
			pomlog(POMLOG_ERR "Could not get conntrack entry");
			return POM_ERR;
		}
	}
	conntrack_unlock(s->ce);

	s_next->pload = s->pload + hdrlen;
	s_next->plen = s->plen - hdrlen;
	s_next->proto = proto_get_by_number(s->proto, ppp_type);

	return PROTO_OK;

}

static int proto_ppp_mod_unregister() {

	return proto_unregister("ppp");

}
