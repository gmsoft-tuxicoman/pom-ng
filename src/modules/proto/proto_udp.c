/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_uint32.h>
#include <arpa/inet.h>

#include "proto_udp.h"

#define __FAVOR_BSD // We use BSD favor of the udp header
#include <netinet/udp.h>

static struct ptype *param_conntrack_timeout = NULL;

struct mod_reg_info* proto_udp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_udp_mod_register;
	reg_info.unregister_func = proto_udp_mod_unregister;
	reg_info.dependencies = "ptype_uint16, ptype_uint32";

	return &reg_info;
}

static int proto_udp_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_udp = { 0 };
	proto_udp.name = "udp";
	proto_udp.api_ver = PROTO_API_VER;
	proto_udp.mod = mod;
	proto_udp.number_class = "udp";

	static struct proto_pkt_field fields[PROTO_UDP_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "sport";
	fields[0].value_type = ptype_get_type("uint16");
	fields[0].description = "Source port";
	fields[1].name = "dport";
	fields[1].value_type = ptype_get_type("uint16");
	fields[1].description = "Destination port";
	proto_udp.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 32768;
	ct_info.fwd_pkt_field_id = proto_udp_field_sport;
	ct_info.rev_pkt_field_id = proto_udp_field_dport;
	proto_udp.ct_info = &ct_info;

	proto_udp.init = proto_udp_init;
	proto_udp.cleanup = proto_udp_cleanup;
	proto_udp.process = proto_udp_process;

	if (proto_register(&proto_udp) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_udp_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("ip", IPPROTO_UDP, proto) != POM_OK)
		return POM_ERR;

	param_conntrack_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!param_conntrack_timeout)
		return POM_ERR;

	struct registry_param *p = registry_new_param("conntrack_timeout", "600", param_conntrack_timeout, "Timeout for UDP connections", 0);
	if (!p)
		goto err;
	if (proto_add_param(proto, p) != POM_OK)
		goto err;

	return POM_OK;
err:
	if (p)
		registry_cleanup_param(p);

	if (param_conntrack_timeout) {
		ptype_cleanup(param_conntrack_timeout);
		param_conntrack_timeout = NULL;
	}

	return POM_ERR;
}

static int proto_udp_cleanup(void *proto_priv) {

	if (param_conntrack_timeout) {
		ptype_cleanup(param_conntrack_timeout);
		param_conntrack_timeout = NULL;
	}

	return POM_OK;
}

static int proto_udp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct udphdr) > s->plen)
		return PROTO_INVALID;

	struct udphdr *hdr = s->pload;

	uint16_t ulen = ntohs(hdr->uh_ulen);
	uint16_t sport = ntohs(hdr->uh_sport);
	uint16_t dport = ntohs(hdr->uh_dport);

	if (ulen > s->plen || ulen < sizeof(struct udphdr))
		return PROTO_INVALID;

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_udp_field_sport], sport);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_udp_field_dport], dport);

	if (conntrack_get(stack, stack_index) != POM_OK)
		return POM_ERR;

	int res = POM_ERR;
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (s->ce->children) {
		res = conntrack_delayed_cleanup(s->ce, 0, p->ts);
		s_next->proto = s->ce->children->ce->proto;
	} else {
		uint32_t *conntrack_timeout = PTYPE_UINT32_GETVAL(param_conntrack_timeout);
		res = conntrack_delayed_cleanup(s->ce, *conntrack_timeout, p->ts);
	}

	conntrack_unlock(s->ce);

	s_next->pload = s->pload + sizeof(struct udphdr);
	s_next->plen = ulen - sizeof(struct udphdr);

	if (!s_next->proto) {

		s_next->proto = proto_get_by_number(s->proto, sport);
		if (!s_next->proto)
			s_next->proto = proto_get_by_number(s->proto, dport);
	}

	return res;

}

static int proto_udp_mod_unregister() {

	return proto_unregister("udp");
}
