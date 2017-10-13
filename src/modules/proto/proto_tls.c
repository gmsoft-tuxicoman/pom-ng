/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2017 Guy Martin <gmsoft@tuxicoman.be>
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



#include "proto_tls.h"

#include <pom-ng/core.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>

#include <arpa/inet.h>

struct mod_reg_info* proto_tls_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_tls_mod_register;
	reg_info.unregister_func = proto_tls_mod_unregister;
	reg_info.dependencies = "ptype_uint8, ptype_uint16";

	return &reg_info;
}

static int proto_tls_mod_register(struct mod_reg *mod) {

	// Dummy protocol to split between the different contents

	static struct proto_reg_info proto_tls = { 0 };
	proto_tls.name = "tls";
	proto_tls.api_ver = PROTO_API_VER;
	proto_tls.mod = mod;
	proto_tls.number_class = "tls";


	static struct conntrack_info proto_tls_ct_info = { 0 };
	proto_tls_ct_info.default_table_size = 1;
	proto_tls_ct_info.cleanup_handler = proto_tls_conntrack_cleanup;
	proto_tls.ct_info = &proto_tls_ct_info;

	proto_tls.init = proto_tls_init;
	proto_tls.process = proto_tls_process;

	if (proto_register(&proto_tls) != POM_OK)
		return POM_ERR;


	static struct proto_pkt_field fields[PROTO_TLS_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "version_major";
	fields[0].value_type = ptype_get_type("uint8");
	fields[0].description = "Version major";
	fields[1].name = "version_minor";
	fields[1].value_type = ptype_get_type("uint8");
	fields[1].description = "Version minor";
	fields[2].name = "length";
	fields[2].value_type = ptype_get_type("uint16");
	fields[2].description = "Length";


	static struct proto_reg_info proto_tls_changecipherspec = { 0 };
	proto_tls_changecipherspec.name = "tls_changecipherspec";
	proto_tls_changecipherspec.api_ver = PROTO_API_VER;
	proto_tls_changecipherspec.mod = mod;
	proto_tls_changecipherspec.pkt_fields = fields;

	proto_tls_changecipherspec.init = proto_tls_changecipherspec_init;
	proto_tls_changecipherspec.process = proto_tls_changecipherspec_process;

	if (proto_register(&proto_tls_changecipherspec) != POM_OK) {
		proto_unregister("tls");
		return POM_ERR;
	}

	static struct proto_reg_info proto_tls_alert = { 0 };
	proto_tls_alert.name = "tls_alert";
	proto_tls_alert.api_ver = PROTO_API_VER;
	proto_tls_alert.mod = mod;
	proto_tls_alert.pkt_fields = fields;

	proto_tls_alert.init = proto_tls_alert_init;
	proto_tls_alert.process = proto_tls_alert_process;

	if (proto_register(&proto_tls_alert) != POM_OK) {
		proto_unregister("tls_changecipherspec");
		proto_unregister("tls");
		return POM_ERR;
	}

	static struct proto_pkt_field fields_handshake[PROTO_TLS_HANDSHAKE_FIELD_NUM + 1] = { { 0 } };
	fields_handshake[0].name = "version_major";
	fields_handshake[0].value_type = ptype_get_type("uint8");
	fields_handshake[0].description = "Version major";
	fields_handshake[1].name = "version_minor";
	fields_handshake[1].value_type = ptype_get_type("uint8");
	fields_handshake[1].description = "Version minor";
	fields_handshake[2].name = "length";
	fields_handshake[2].value_type = ptype_get_type("uint16");
	fields_handshake[2].description = "Length";
	fields_handshake[3].name = "type";
	fields_handshake[3].value_type = ptype_get_type("uint8");
	fields_handshake[3].description = "Message type";

	static struct proto_reg_info proto_tls_handshake = { 0 };
	proto_tls_handshake.name = "tls_handshake";
	proto_tls_handshake.api_ver = PROTO_API_VER;
	proto_tls_handshake.mod = mod;
	proto_tls_handshake.pkt_fields = fields_handshake;

	proto_tls_handshake.init = proto_tls_handshake_init;
	proto_tls_handshake.process = proto_tls_handshake_process;

	if (proto_register(&proto_tls_handshake) != POM_OK) {
		proto_unregister("tls_alert");
		proto_unregister("tls_changecipherspec");
		proto_unregister("tls");
		return POM_ERR;
	}
	
	static struct proto_reg_info proto_tls_appdata = { 0 };

	proto_tls_appdata.name = "tls_appdata";
	proto_tls_appdata.api_ver = PROTO_API_VER;
	proto_tls_appdata.mod = mod;
	proto_tls_appdata.pkt_fields = fields;

	proto_tls_appdata.init = proto_tls_appdata_init;
	proto_tls_appdata.process = proto_tls_appdata_process;

	if (proto_register(&proto_tls_appdata) != POM_OK) {
		proto_unregister("tls_handshake");
		proto_unregister("tls_alert");
		proto_unregister("tls_changecipherspec");
		proto_unregister("tls");
		return POM_ERR;
	}

	return POM_OK;
}

static int proto_tls_mod_unregister() {

	return proto_unregister("tls");
}

///
// Proto TLS
///

static int proto_tls_init(struct proto *proto, struct registry_instance *i) {

	// Register for https for now
	return proto_number_register("tcp", 443, proto);
}

static int proto_tls_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK)
		return PROTO_ERR;

	struct proto_tls_conntrack_priv *cpriv = s->ce->priv;

	if (!cpriv) {
		cpriv = malloc(sizeof(struct proto_tls_conntrack_priv));
		if (!cpriv) {
			conntrack_unlock(s->ce);
			pom_oom(sizeof(struct proto_tls_conntrack_priv));
			return PROTO_ERR;
		}

		memset(cpriv, 0, sizeof(struct proto_tls_conntrack_priv));
	}

	if (!cpriv->parser) {
		cpriv->parser = packet_stream_parser_alloc(0, 0);
		if (!cpriv->parser)
			return POM_ERR;
	}

	if (packet_stream_parser_add_payload(cpriv->parser, s->pload, s->plen) != POM_OK)
		return POM_ERR;

	int res = PROTO_OK;

	while (res == PROTO_OK) {

		void *pload = NULL;
		size_t len = 0;

		if (packet_stream_parser_get_remaining(cpriv->parser, &pload, &len) != POM_OK) {
			res = PROTO_ERR;
			break;
		}

		if (!len)
			break;

		if (len < sizeof(struct tls_header)) {
			// Force the stream parser to buffer the leftover by requesting more than available
			res = packet_stream_parser_get_bytes(cpriv->parser, sizeof(struct tls_header), &pload);
			break;
		}

		struct tls_header *thdr = pload;

		len = sizeof(struct tls_header) + ntohs(thdr->length);

		if (packet_stream_parser_get_bytes(cpriv->parser, len, &pload) != POM_OK) {
			res = PROTO_ERR;
			break;
		}

		if (!pload) {
			// Not enough bytes in the buffer
			res = PROTO_STOP;
			break;
		}

		struct proto_process_stack *s_next = &stack[stack_index + 1];

		s_next->plen = len;
		s_next->pload = pload;
		s_next->proto = proto_get_by_number(s->proto, thdr->content_type);

		res = core_process_multi_packet(stack, stack_index + 1, p);
	}

	conntrack_unlock(s->ce);

	return PROTO_STOP;
}

static int proto_tls_conntrack_cleanup(void *ce_priv) {

	struct proto_tls_conntrack_priv *priv = ce_priv;

	if (!priv)
		return POM_OK;

	free(priv);

	return POM_OK;
}


///
// Proto TLS Change Cipher Spec
///

static int proto_tls_changecipherspec_init(struct proto *proto, struct registry_instance *i) {

	return proto_number_register("tls", 20, proto);

}

static int proto_tls_changecipherspec_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	
	if (s->plen < sizeof(struct tls_header))
		return PROTO_INVALID;

	struct tls_header *thdr = s->pload;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_field_version_major], thdr->version_major);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_field_version_minor], thdr->version_minor);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tls_field_length], ntohs(thdr->length));


	return PROTO_OK;
}

///
// Proto TLS Alert
///


static int proto_tls_alert_init(struct proto *proto, struct registry_instance *i) {

	return proto_number_register("tls", 21, proto);
}

static int proto_tls_alert_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (s->plen < sizeof(struct tls_header))
		return PROTO_INVALID;

	struct tls_header *thdr = s->pload;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_field_version_major], thdr->version_major);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_field_version_minor], thdr->version_minor);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tls_field_length], ntohs(thdr->length));


	return PROTO_OK;
}


///
// Proto TLS Handshake
///


static int proto_tls_handshake_init(struct proto *proto, struct registry_instance *i) {

	return proto_number_register("tls", 22, proto);
}

static int proto_tls_handshake_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	
	if (s->plen < sizeof(struct tls_header))
		return PROTO_INVALID;

	struct tls_header *thdr = s->pload;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_field_version_major], thdr->version_major);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_field_version_minor], thdr->version_minor);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tls_field_length], ntohs(thdr->length));

	uint8_t *data = s->pload + sizeof(struct tls_header);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_handshake_field_type], data[0]);

	return PROTO_OK;
}

///
// Proto TLS Application Data
///

static int proto_tls_appdata_init(struct proto *proto, struct registry_instance *i) {

	return proto_number_register("tls", 23, proto);
}

static int proto_tls_appdata_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (s->plen < sizeof(struct tls_header))
		return PROTO_INVALID;

	struct tls_header *thdr = s->pload;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_field_version_major], thdr->version_major);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tls_field_version_minor], thdr->version_minor);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tls_field_length], ntohs(thdr->length));

	return PROTO_OK;
}
