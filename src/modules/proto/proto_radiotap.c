/*
 *  This file is part of pom-ng.
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

#include <radiotap.h>
#include "proto_radiotap.h"

static struct proto *proto_80211 = NULL;

struct mod_reg_info* proto_radiotap_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_radiotap_mod_register;
	reg_info.unregister_func = proto_radiotap_mod_unregister;
	reg_info.dependencies = "proto_80211";

	return &reg_info;
}

static int proto_radiotap_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_radiotap = { 0 };
	proto_radiotap.name = "radiotap";
	proto_radiotap.api_ver = PROTO_API_VER;
	proto_radiotap.mod = mod;

	// No contrack here

	proto_radiotap.init = proto_radiotap_init;
	proto_radiotap.process = proto_radiotap_process;

	if (proto_register(&proto_radiotap) == POM_OK)
		return POM_OK;

	return POM_ERR;

}


static int proto_radiotap_init(struct proto *proto, struct registry_instance *i) {
	
	proto_80211 = proto_get("80211");

	if (!proto_80211) {
		pomlog(POMLOG_ERR "Protocol 80211 is not registered.");
		return POM_ERR;
	}


	return POM_OK;

}

static int proto_radiotap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	radiotap_header *rtaphdr = s->pload;

	if (sizeof(radiotap_header) > s->plen &&
		le16(rtaphdr->it_len) < s->plen)
		return PROTO_INVALID;

	struct proto_process_stack *s_next = &stack[stack_index + 1];

	unsigned int header_len = le16(rtaphdr->it_len);

	s_next->pload = s->pload + header_len;
	s_next->plen = s->plen - header_len;
	s_next->proto = proto_80211;

	return PROTO_OK;

}

static int proto_radiotap_mod_unregister() {

	return proto_unregister("radiotap");
}
