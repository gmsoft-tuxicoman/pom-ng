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
#include <pom-ng/event.h>
#include <pom-ng/ptype_bytes.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint8.h>

#include "proto_ppp_chap.h"

#include <arpa/inet.h>

struct mod_reg_info* proto_ppp_chap_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ppp_chap_mod_register;
	reg_info.unregister_func = proto_ppp_chap_mod_unregister;
	reg_info.dependencies = "ptype_bytes, ptype_string, ptype_uint8, ptype_uint32";

	return &reg_info;
}

static int proto_ppp_chap_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_ppp_chap = { 0 };
	proto_ppp_chap.name = "ppp_chap";
	proto_ppp_chap.api_ver = PROTO_API_VER;
	proto_ppp_chap.mod = mod;

	static struct proto_pkt_field fields[PROTO_PPP_CHAP_FIELDS + 1] = { { 0 } };
	fields[0].name = "code";
	fields[0].value_type = ptype_get_type("uint8");
	fields[0].description = "Code";
	fields[1].name = "identifier";
	fields[1].value_type = ptype_get_type("uint8");
	fields[1].description = "Identifier";
	proto_ppp_chap.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 16;
	ct_info.fwd_pkt_field_id = proto_ppp_chap_identifier;
	ct_info.rev_pkt_field_id = CONNTRACK_PKT_FIELD_NONE;
	proto_ppp_chap.ct_info = &ct_info;

	proto_ppp_chap.init = proto_ppp_chap_init;
	proto_ppp_chap.cleanup = proto_ppp_chap_cleanup;
	proto_ppp_chap.process = proto_ppp_chap_process;

	if (proto_register(&proto_ppp_chap) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_ppp_chap_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("ppp", 0xc223, proto) != POM_OK)
		return POM_ERR;

	struct proto_ppp_chap_priv *priv = malloc(sizeof(struct proto_ppp_chap_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_ppp_chap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_ppp_chap_priv));
	proto_set_priv(proto, priv);


	static struct data_item_reg evt_challenge_response_data_items[PROTO_PPP_CHAP_EVT_CHALLENGE_RESPONSE_DATA_COUNT] = { { 0 } };
	evt_challenge_response_data_items[evt_ppp_chap_challenge_response_code].name = "code";
	evt_challenge_response_data_items[evt_ppp_chap_challenge_response_code].value_type = ptype_get_type("uint8");
	evt_challenge_response_data_items[evt_ppp_chap_challenge_response_identifier].name = "identifier";
	evt_challenge_response_data_items[evt_ppp_chap_challenge_response_identifier].value_type = ptype_get_type("uint8");
	evt_challenge_response_data_items[evt_ppp_chap_challenge_response_value].name = "value";
	evt_challenge_response_data_items[evt_ppp_chap_challenge_response_value].value_type = ptype_get_type("bytes");
	evt_challenge_response_data_items[evt_ppp_chap_challenge_response_name].name = "name";
	evt_challenge_response_data_items[evt_ppp_chap_challenge_response_name].value_type = ptype_get_type("string");

	static struct data_reg evt_ppp_chap_challenge_response_data = {
		.items = evt_challenge_response_data_items,
		.data_count = PROTO_PPP_CHAP_EVT_CHALLENGE_RESPONSE_DATA_COUNT
	};

	static struct event_reg_info proto_ppp_chap_challenge_response = { 0 };
	proto_ppp_chap_challenge_response.source_name = "proto_ppp_chap";
	proto_ppp_chap_challenge_response.source_obj = priv;
	proto_ppp_chap_challenge_response.name = "ppp_chap_challenge_response";
	proto_ppp_chap_challenge_response.description = "PPP-CHAP Challenge/Response";
	proto_ppp_chap_challenge_response.data_reg = &evt_ppp_chap_challenge_response_data;

	priv->evt_challenge_response = event_register(&proto_ppp_chap_challenge_response);
	if (!priv->evt_challenge_response)
		goto err;


	static struct data_item_reg evt_success_failure_data_items[PROTO_PPP_CHAP_EVT_SUCCESS_FAILURE_DATA_COUNT] = { { 0 } };
	evt_success_failure_data_items[evt_ppp_chap_success_failure_code].name = "code";
	evt_success_failure_data_items[evt_ppp_chap_success_failure_code].value_type = ptype_get_type("uint8");
	evt_success_failure_data_items[evt_ppp_chap_success_failure_identifier].name = "identifier";
	evt_success_failure_data_items[evt_ppp_chap_success_failure_identifier].value_type = ptype_get_type("uint8");
	evt_success_failure_data_items[evt_ppp_chap_success_failure_message].name = "message";
	evt_success_failure_data_items[evt_ppp_chap_success_failure_message].value_type = ptype_get_type("string");

	static struct data_reg evt_ppp_chap_success_failure_data = {
		.items = evt_success_failure_data_items,
		.data_count = PROTO_PPP_CHAP_EVT_SUCCESS_FAILURE_DATA_COUNT
	};

	static struct event_reg_info proto_ppp_chap_success_failure = { 0 };
	proto_ppp_chap_success_failure.source_name = "proto_ppp_chap";
	proto_ppp_chap_success_failure.source_obj = priv;
	proto_ppp_chap_success_failure.name = "ppp_chap_success_failure";
	proto_ppp_chap_success_failure.description = "PPP-CHAP Success/Failure";
	proto_ppp_chap_success_failure.data_reg = &evt_ppp_chap_success_failure_data;

	priv->evt_success_failure = event_register(&proto_ppp_chap_success_failure);
	if (!priv->evt_success_failure)
		goto err;

	priv->p_auth_timeout = ptype_alloc_unit("uint32", "seconds");
	(!priv->p_auth_timeout)
		goto err;

	struct registry_param *p = registry_new_param("auth_timeout", "60", priv->p_auth_timeout, "Authentification timeout", 0);
	if (registry_instance_add_param(i, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	return POM_OK;

err:
	proto_ppp_chap_cleanup(priv);
	return POM_ERR;

}

static int proto_ppp_chap_cleanup(void *proto_priv) {

	if (!proto_priv)
		return POM_OK;

	struct proto_ppp_chap_priv *priv = proto_priv;

	if (priv->p_auth_timeout)
		ptype_cleanup(priv->p_auth_timeout);

	if (priv->evt_challenge_response)
		event_unregister(priv->evt_challenge_response);
	if (priv->evt_success_failure)
		event_unregister(priv->evt_success_failure);

	free(priv);

	return POM_OK;
}


static int proto_ppp_chap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct ppp_chap_header) > s->plen)
		return PROTO_INVALID;

	struct ppp_chap_header *pchdr = s->pload;
	size_t len = ntohs(pchdr->length);

	if (len > s->plen)
		return PROTO_INVALID;

	// Keep only the payload len
	len -= sizeof(struct ppp_chap_header);

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ppp_chap_field_code], pchdr->code);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ppp_chap_field_identifier], pchdr->identifier);

	if (conntrack_get(stack, stack_index) != POM_OK)
		return PROTO_ERR;
	if (conntrack_delayed_cleanup(s->ce, PTYPE_UINT32_GETVAL(priv->p_auth_timeout))) {
		conntrack_unlock(s->ce);
		return PROTO_ERR;
	}
	
	conntrack_unlock(s->ce);

	struct proto_ppp_chap_priv *priv = proto_priv;

	if ((pchdr->code == 1 || pchdr->code == 2) && event_has_listener(priv->evt_challenge_response)) {

		char *value_size = NULL;
		size_t name_len = 0;
		
		if (len >= 2) {
			value_size = s->pload + sizeof(struct ppp_chap_header);
			if (*value_size > len - 1)
				return PROTO_INVALID;
			name_len = len - 1 - *value_size;

		}

		// Process the challenge/response event
		struct event *evt = event_alloc(priv->evt_challenge_response);
		if (!evt)
			return PROTO_ERR;

		struct data *evt_data = event_get_data(evt);
		PTYPE_UINT8_SETVAL(evt_data[evt_ppp_chap_challenge_response_code].value, pchdr->code);
		data_set(evt_data[evt_ppp_chap_challenge_response_code]);
		PTYPE_UINT8_SETVAL(evt_data[evt_ppp_chap_challenge_response_identifier].value, pchdr->identifier);
		data_set(evt_data[evt_ppp_chap_challenge_response_identifier]);

		if (value_size && *value_size) {
			PTYPE_BYTES_SETLEN(evt_data[evt_ppp_chap_challenge_response_value].value, *value_size);
			PTYPE_BYTES_SETVAL(evt_data[evt_ppp_chap_challenge_response_value].value, value_size + 1);
			data_set(evt_data[evt_ppp_chap_challenge_response_value]);

			if (name_len) {
				PTYPE_STRING_SETVAL_N(evt_data[evt_ppp_chap_challenge_response_name].value, value_size + 1 + *value_size, name_len);
				data_set(evt_data[evt_ppp_chap_challenge_response_name]);
			}
		}

		if (event_process(evt, stack, stack_index, p->ts) != POM_OK)
			return PROTO_ERR;

	}

	if ((pchdr->code == 3 || pchdr->code == 4) && event_has_listener(priv->evt_success_failure)) {
		
		struct event *evt = event_alloc(priv->evt_success_failure);
		if (!evt)
			return PROTO_ERR;

		struct data *evt_data = event_get_data(evt);
		PTYPE_UINT8_SETVAL(evt_data[evt_ppp_chap_success_failure_code].value, pchdr->code);
		data_set(evt_data[evt_ppp_chap_success_failure_code]);
		PTYPE_UINT8_SETVAL(evt_data[evt_ppp_chap_success_failure_identifier].value, pchdr->identifier);
		data_set(evt_data[evt_ppp_chap_success_failure_identifier]);

		if (len > 0) {
			PTYPE_STRING_SETVAL_N(evt_data[evt_ppp_chap_success_failure_message].value, s->pload + sizeof(struct ppp_chap_header), len);
			data_set(evt_data[evt_ppp_chap_success_failure_message]);
		}

		if (event_process(evt, stack, stack_index, p->ts) != POM_OK)
			return PROTO_ERR;

	}

	return PROTO_OK;

}

static int proto_ppp_chap_mod_unregister() {

	return proto_unregister("ppp_chap");

}
