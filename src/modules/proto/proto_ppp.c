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

static struct proto *proto_ipv4 = NULL, *proto_ipv6 = NULL;

struct mod_reg_info* proto_ppp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ppp_mod_register;
	reg_info.unregister_func = proto_ppp_mod_unregister;
	reg_info.dependencies = "proto_ipv4, proto_ipv6";

	return &reg_info;
}

static int proto_ppp_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_ppp = { 0 };
	proto_ppp.name = "ppp";
	proto_ppp.api_ver = PROTO_API_VER;
	proto_ppp.mod = mod;

	proto_ppp.init = proto_ppp_init;
	proto_ppp.process = proto_ppp_process;

	if (proto_register(&proto_ppp) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_ppp_init(struct proto *proto, struct registry_instance *i) {
	
	proto_ipv4 = proto_get("ipv4");
	proto_ipv6 = proto_get("ipv6");

	if (!proto_ipv4 || !proto_ipv6) {
		pomlog(POMLOG_ERR "Could not get hold of all the needed protocols");
		return POM_ERR;
	}

	return POM_OK;

}

static int proto_ppp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct ppp_header) > s->plen)
		return PROTO_INVALID;

	struct ppp_header *ehdr = s->pload;

	struct proto_process_stack *s_next = &stack[stack_index + 1];

	s_next->pload = s->pload + sizeof(struct ppp_header);
	s_next->plen  = s->plen  - sizeof(struct ppp_header);

	switch (ntohs(ehdr->ppp_type)) {
		case 0x21:
			s_next->proto = proto_ipv4;
			break;
		case 0x57:
			s_next->proto = proto_ipv6;
			break;
		default:
			s_next->proto = NULL;
			break;
	}

	return PROTO_OK;

}

static int proto_ppp_mod_unregister() {

	return proto_unregister("ppp");

}
