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
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/proto_dns.h>

#include <arpa/inet.h>

#include "proto_dns.h"

#include <string.h>

struct mod_reg_info* proto_dns_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_dns_mod_register;
	reg_info.unregister_func = proto_dns_mod_unregister;
	reg_info.dependencies = "proto_tcp, ptype_bool, ptype_uint8, ptype_uint16";

	return &reg_info;
}

static int proto_dns_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_DNS_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "id";
	fields[0].value_type = ptype_get_type("uint16");
	fields[0].description = "ID";
	fields[1].name = "response";
	fields[1].value_type = ptype_get_type("bool");
	fields[1].description = "Query or response";
	fields[2].name = "rcode";
	fields[2].value_type = ptype_get_type("uint8");
	fields[2].description = "Response code";
	fields[3].name = "qdcount";
	fields[3].value_type = ptype_get_type("uint16");
	fields[3].description = "Question count";
	fields[4].name = "ancount";
	fields[4].value_type = ptype_get_type("uint16");
	fields[4].description = "Answer count";
	fields[5].name = "nscount";
	fields[5].value_type = ptype_get_type("uint16");
	fields[5].description = "Name server count";
	fields[6].name = "arcount";
	fields[6].value_type = ptype_get_type("uint16");
	fields[6].description = "Additional records count";

	static struct proto_reg_info proto_dns = { 0 };
	proto_dns.name = "dns";
	proto_dns.api_ver = PROTO_API_VER;
	proto_dns.mod = mod;
	proto_dns.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 1; // No hashing done here
	ct_info.cleanup_handler = proto_dns_conntrack_cleanup;
	proto_dns.ct_info = &ct_info;

	proto_dns.init = proto_dns_init;
	proto_dns.cleanup = proto_dns_cleanup;
	proto_dns.process = proto_dns_process;

	if (proto_register(&proto_dns) == POM_OK)
		return POM_OK;

	return POM_ERR;

}

static int proto_dns_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("udp", 53, proto) != POM_OK ||
		proto_number_register("tcp", 53, proto) != POM_OK)
		return POM_ERR;

	struct proto_dns_priv *priv = malloc(sizeof(struct proto_dns_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_dns_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_dns_priv));

	priv->proto_tcp = proto_get("tcp");
	if (!priv->proto_tcp) {
		pomlog(POMLOG_ERR "Unable to find proto tcp !");
		free(priv);
		return POM_ERR;
	}

	proto_set_priv(proto, priv);
	
	return POM_OK;
}

static int proto_dns_cleanup(void *proto_priv) {

	if (!proto_priv)
		return POM_OK;
	free(proto_priv);
	return POM_OK;
}

static int proto_dns_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	struct proto_process_stack *s_prev = &stack[stack_index - 1];

	struct proto_dns_priv *priv = proto_priv;
	void *pload = s->pload;
	size_t len = s->plen;

	// We need to do some buffering for TCP
	if (s_prev->proto == priv->proto_tcp) {
		
		if (!len)
			return PROTO_OK;

		if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK)
			return PROTO_ERR;
		
		// There should be no need to keep the lock here since we are in the packet_stream lock from proto_tcp
		conntrack_unlock(s->ce);

		struct proto_dns_conntrack_priv *cpriv = s->ce->priv;
		if (!cpriv) {
			cpriv = malloc(sizeof(struct proto_dns_conntrack_priv));
			if (!cpriv) {
				pom_oom(sizeof(struct proto_dns_conntrack_priv));
				return PROTO_ERR;
			}
			memset(cpriv, 0, sizeof(struct proto_dns_conntrack_priv));

			s->ce->priv = cpriv;
		}

		if (!cpriv->buff[s->direction]) {
			cpriv->buff[s->direction] = packet_stream_parser_alloc(0, 0);
			if (!cpriv->buff[s->direction])
				return PROTO_ERR;
		}

		struct packet_stream_parser *buff = cpriv->buff[s->direction];
		if (packet_stream_parser_add_payload(buff, s->pload, s->plen) != POM_OK)
			return PROTO_ERR;

		size_t avail_len = 0;
		if (packet_stream_parser_get_remaining(buff, &pload, &avail_len) != POM_OK)
			return PROTO_ERR;

		if (avail_len < sizeof(uint16_t))
			return PROTO_STOP;

		uint16_t pkt_len = ntohs(*(uint16_t*)pload);

		if (packet_stream_parser_get_bytes(buff, pkt_len + sizeof(uint16_t), &pload) != POM_OK)
			return PROTO_ERR;

		if (!pload)
			return PROTO_STOP;

		pload += sizeof(uint16_t);
		len = pkt_len;

	}

	if (len < sizeof(struct dns_header))
		return PROTO_INVALID;



	struct dns_header *dhdr = pload;

	uint16_t qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
	qdcount = ntohs(dhdr->qdcount);
	ancount = ntohs(dhdr->ancount);
	nscount = ntohs(dhdr->nscount);
	arcount = ntohs(dhdr->arcount);

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_id], ntohs(dhdr->id));
	PTYPE_BOOL_SETVAL(s->pkt_info->fields_value[proto_dns_field_response], dhdr->qr);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_dns_field_rcode], dhdr->rcode);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_qdcount], qdcount);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_ancount], ancount);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_nscount], nscount);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_arcount], arcount);


	if (qdcount != 1)
		return PROTO_INVALID;

	s_next->plen = len - sizeof(struct dns_header);
	s_next->pload = pload + sizeof(struct dns_header);

	return PROTO_OK;

}

static int proto_dns_conntrack_cleanup(void *ce_priv) {

	struct proto_dns_conntrack_priv *priv = ce_priv;

	if (!priv)
		return POM_OK;

	int i;
	for (i = 0; i < POM_DIR_TOT; i++) {
		if (priv->buff[i])
			packet_stream_parser_cleanup(priv->buff[i]);
	}

	free(priv);

	return POM_OK;
}

static int proto_dns_mod_unregister() {

	return proto_unregister("dns");
}
