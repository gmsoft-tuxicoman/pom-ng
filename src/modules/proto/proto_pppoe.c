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

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 256;
	ct_info.fwd_pkt_field_id = proto_pppoe_field_session_id;
	ct_info.rev_pkt_field_id = CONNTRACK_PKT_FIELD_NONE;
	proto_pppoe.ct_info = &ct_info;

	proto_pppoe.init = proto_pppoe_init;
	proto_pppoe.cleanup = proto_pppoe_cleanup;
	proto_pppoe.process = proto_pppoe_process;

	if (proto_register(&proto_pppoe) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_pppoe_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("ethernet", 0x8863, proto) != POM_OK ||
		proto_number_register("ethernet", 0x8864, proto) != POM_OK)
			return POM_ERR;

	proto_ppp = proto_get("ppp");

	if (!proto_ppp) {
		pomlog(POMLOG_ERR "Could not get hold of all the needed protocols");
		return POM_ERR;
	}

	struct proto_pppoe_priv *priv = malloc(sizeof(struct proto_pppoe_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_pppoe_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_pppoe_priv));

	proto_set_priv(proto, priv);

	struct registry_param *p = NULL;

	priv->p_session_timeout = ptype_alloc_unit("uint16", "seconds");
	if (!priv->p_session_timeout)
		goto err;

	p = registry_new_param("stream_timeout", "1800", priv->p_session_timeout, "Timeout for PPPoE sessions", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	return POM_OK;

err:
	if (p)
		registry_cleanup_param(p);

	proto_pppoe_cleanup(priv);

	return POM_ERR;
}

static int proto_pppoe_cleanup(void *proto_priv) {

	if (proto_priv) {
		struct proto_pppoe_priv *p = proto_priv;
		if (p->p_session_timeout)
			ptype_cleanup(p->p_session_timeout);

		free(p);
	}

	return POM_OK;
}

static int proto_pppoe_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_pppoe_priv *priv = proto_priv;
	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct pppoe_header) > s->plen)
		return PROTO_INVALID;

	struct pppoe_header *phdr = s->pload;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_pppoe_field_code], phdr->code);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_pppoe_field_session_id],ntohs(phdr->session_id));

	if (conntrack_get(stack, stack_index) != POM_OK)
		return PROTO_ERR;
	conntrack_delayed_cleanup(s->ce, *PTYPE_UINT16_GETVAL(priv->p_session_timeout) , p->ts);
	conntrack_unlock(s->ce);

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
