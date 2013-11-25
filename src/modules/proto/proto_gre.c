/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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

#include "proto_gre.h"

#include <string.h>
#include <arpa/inet.h>

struct mod_reg_info* proto_gre_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_gre_mod_register;
	reg_info.unregister_func = proto_gre_mod_unregister;

	return &reg_info;
}

static int proto_gre_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_gre = { 0 };
	proto_gre.name = "gre";
	proto_gre.api_ver = PROTO_API_VER;
	proto_gre.mod = mod;
	proto_gre.number_class = "ethernet";

	struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 1; // No hashing done here
	proto_gre.ct_info = &ct_info;

	proto_gre.init = proto_gre_init;
	proto_gre.process = proto_gre_process;

	if (proto_register(&proto_gre) == POM_OK)
		return POM_OK;

	return POM_ERR;

}


static int proto_gre_init(struct proto *proto, struct registry_instance *i) {

	return proto_number_register("ip", IPPROTO_GRE, proto);
}

static int proto_gre_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct gre_header) > s->plen)
		return PROTO_INVALID;

	struct gre_header *ghdr = s->pload;

	struct proto_process_stack *s_next = &stack[stack_index + 1];


	ssize_t offset = 0;

	if (ghdr->flg_cksum) // Checksum field is present
		offset += sizeof(uint16_t);
	if (ghdr->flg_cksum || ghdr->flg_routing) // Offset field is present
		offset += sizeof(uint16_t);
	if (ghdr->flg_key) // Key field is present
		offset += sizeof(uint32_t);
	if (ghdr->flg_seq) // Sequence field is present
		offset += sizeof(uint32_t);
	if (ghdr->flg_ack) { // Ack field (only in PPTP enhanced version)
		if (ghdr->version != 1)
			return PROTO_INVALID;
		offset += sizeof(uint32_t);
	}

	if (sizeof(struct gre_header) + offset > s->plen)
		return PROTO_INVALID;

	// Parse routing info ...
	if (ghdr->flg_routing) {
		// We don't support it for now ...
		// TODO Add routing info parsing
		return PROTO_OK;
	}

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK) {
		pomlog(POMLOG_ERR "Could not get conntrack entry");
		return POM_ERR;
	}
	conntrack_unlock(s->ce);
		
	s_next->pload = s->pload + sizeof(struct gre_header) + offset;
	s_next->plen = s->plen - (sizeof(struct gre_header) + offset);

	s_next->proto = proto_get_by_number(s->proto, ntohs(ghdr->proto));

	return PROTO_OK;

}

static int proto_gre_mod_unregister() {

	return proto_unregister("gre");

}
