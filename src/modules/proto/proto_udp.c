/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_uint16.h>
#include <arpa/inet.h>

#include "proto_udp.h"

#define __FAVOR_BSD // We use BSD favor of the udp header
#include <netinet/udp.h>

struct mod_reg_info* proto_udp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_udp_mod_register;
	reg_info.unregister_func = proto_udp_mod_unregister;
	reg_info.dependencies = "ptype_uint16";

	return &reg_info;
}

static int proto_udp_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_udp = { 0 };
	proto_udp.name = "udp";
	proto_udp.api_ver = PROTO_API_VER;
	proto_udp.mod = mod;

	static struct proto_pkt_field fields[PROTO_UDP_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "sport";
	fields[0].value_type = ptype_get_type("uint16");
	fields[0].description = "Source port";
	fields[1].name = "dport";
	fields[1].value_type = ptype_get_type("uint16");
	fields[1].description = "Destination port";
	proto_udp.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 2048;
	ct_info.fwd_pkt_field_id = proto_udp_field_sport;
	ct_info.rev_pkt_field_id = proto_udp_field_dport;
	proto_udp.ct_info = &ct_info;

	proto_udp.init = proto_udp_init;
	proto_udp.process = proto_udp_process;
	proto_udp.cleanup = proto_udp_cleanup;

	if (proto_register(&proto_udp) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_udp_init(struct proto *proto, struct registry_instance *i) {

	struct proto_udp_priv *priv = malloc(sizeof(struct proto_udp_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_udp_priv));
		return POM_ERR;
	}

	memset(priv, 0, sizeof(struct proto_udp_priv));

	proto->priv = priv;

	priv->proto_dns = proto_add_dependency("dns");

	if (!priv->proto_dns)	{
		proto_udp_cleanup(proto);
		return POM_ERR;
	}

	return POM_OK;
}

static int proto_udp_cleanup(struct proto *proto) {
	
	if (proto->priv) {
		struct proto_udp_priv *priv = proto->priv;
		if (priv->proto_dns)
			proto_remove_dependency(priv->proto_dns);


		free(priv);
	}

	return POM_OK;
}

static int proto_udp_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_udp_priv *priv = proto->priv;

	if (sizeof(struct udphdr) > s->plen)
		return PROTO_INVALID;

	struct udphdr *hdr = s->pload;

	uint16_t ulen = ntohs(hdr->uh_ulen);
	uint16_t sport = ntohs(hdr->uh_sport);
	uint16_t dport = ntohs(hdr->uh_dport);

	if (ulen > s->plen)
		return PROTO_INVALID;

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_udp_field_sport], sport);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_udp_field_dport], dport);

	struct proto_process_stack *s_next = &stack[stack_index + 1];

	s_next->pload = s->pload + sizeof(struct udphdr);
	s_next->plen = ulen - sizeof(struct udphdr);

	if (dport == 53 || sport == 53)
		s_next->proto = priv->proto_dns->proto;

	return PROTO_OK;

}

static int proto_udp_mod_unregister() {

	return proto_unregister("udp");
}
