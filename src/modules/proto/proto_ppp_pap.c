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
#include <pom-ng/ptype_uint32.h>

#include "proto_ppp_pap.h"

#include <arpa/inet.h>

struct mod_reg_info* proto_ppp_pap_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ppp_pap_mod_register;
	reg_info.unregister_func = proto_ppp_pap_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_uint8, ptype_uint32";

	return &reg_info;
}

static int proto_ppp_pap_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_ppp_pap = { 0 };
	proto_ppp_pap.name = "ppp_pap";
	proto_ppp_pap.api_ver = PROTO_API_VER;
	proto_ppp_pap.mod = mod;

	static struct proto_pkt_field fields[PROTO_PPP_PAP_FIELDS + 1] = { { 0 } };
	fields[0].name = "code";
	fields[0].value_type = ptype_get_type("uint8");
	fields[0].description = "Code";
	fields[1].name = "identifier";
	fields[1].value_type = ptype_get_type("uint8");
	fields[1].description = "Identifier";
	proto_ppp_pap.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 16;
	ct_info.fwd_pkt_field_id = proto_ppp_pap_field_identifier;
	ct_info.rev_pkt_field_id = CONNTRACK_PKT_FIELD_NONE;
	proto_ppp_pap.ct_info = &ct_info;

	proto_ppp_pap.init = proto_ppp_pap_init;
	proto_ppp_pap.cleanup = proto_ppp_pap_cleanup;
	proto_ppp_pap.process = proto_ppp_pap_process;

	if (proto_register(&proto_ppp_pap) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_ppp_pap_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("ppp", 0xc023, proto) != POM_OK)
		return POM_ERR;

	struct proto_ppp_pap_priv *priv = malloc(sizeof(struct proto_ppp_pap_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_ppp_pap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_ppp_pap_priv));
	proto_set_priv(proto, priv);


	static struct data_item_reg evt_request_data_items[PROTO_PPP_PAP_EVT_REQUEST_DATA_COUNT] = { { 0 } };
	evt_request_data_items[evt_ppp_pap_request_code].name = "code";
	evt_request_data_items[evt_ppp_pap_request_code].value_type = ptype_get_type("uint8");
	evt_request_data_items[evt_ppp_pap_request_identifier].name = "identifier";
	evt_request_data_items[evt_ppp_pap_request_identifier].value_type = ptype_get_type("uint8");
	evt_request_data_items[evt_ppp_pap_request_peer_id].name = "peer_id";
	evt_request_data_items[evt_ppp_pap_request_peer_id].value_type = ptype_get_type("string");
	evt_request_data_items[evt_ppp_pap_request_password].name = "password";
	evt_request_data_items[evt_ppp_pap_request_password].value_type = ptype_get_type("string");

	static struct data_reg evt_ppp_pap_request_data = {
		.items = evt_request_data_items,
		.data_count = PROTO_PPP_PAP_EVT_REQUEST_DATA_COUNT
	};

	static struct event_reg_info proto_ppp_pap_request = { 0 };
	proto_ppp_pap_request.source_name = "proto_ppp_pap";
	proto_ppp_pap_request.source_obj = priv;
	proto_ppp_pap_request.name = "ppp_pap_request";
	proto_ppp_pap_request.description = "PPP PAP Authentication request";
	proto_ppp_pap_request.data_reg = &evt_ppp_pap_request_data;

	priv->evt_request = event_register(&proto_ppp_pap_request);
	if (!priv->evt_request)
		goto err;


	static struct data_item_reg evt_ack_nack_data_items[PROTO_PPP_PAP_EVT_ACK_NACK_DATA_COUNT] = { { 0 } };
	evt_ack_nack_data_items[evt_ppp_pap_ack_nack_code].name = "code";
	evt_ack_nack_data_items[evt_ppp_pap_ack_nack_code].value_type = ptype_get_type("uint8");
	evt_ack_nack_data_items[evt_ppp_pap_ack_nack_identifier].name = "identifier";
	evt_ack_nack_data_items[evt_ppp_pap_ack_nack_identifier].value_type = ptype_get_type("uint8");
	evt_ack_nack_data_items[evt_ppp_pap_ack_nack_message].name = "message";
	evt_ack_nack_data_items[evt_ppp_pap_ack_nack_message].value_type = ptype_get_type("string");

	static struct data_reg evt_ppp_pap_ack_nack_data = {
		.items = evt_ack_nack_data_items,
		.data_count = PROTO_PPP_PAP_EVT_ACK_NACK_DATA_COUNT
	};

	static struct event_reg_info proto_ppp_pap_ack_nack = { 0 };
	proto_ppp_pap_ack_nack.source_name = "proto_ppp_pap";
	proto_ppp_pap_ack_nack.source_obj = priv;
	proto_ppp_pap_ack_nack.name = "ppp_pap_ack_nack";
	proto_ppp_pap_ack_nack.description = "PPP-PAP ACK/NACK";
	proto_ppp_pap_ack_nack.data_reg = &evt_ppp_pap_ack_nack_data;

	priv->evt_ack_nack = event_register(&proto_ppp_pap_ack_nack);
	if (!priv->evt_ack_nack)
		goto err;

	priv->p_auth_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!priv->p_auth_timeout)
		goto err;

	struct registry_param *p = registry_new_param("auth_timeout", "60", priv->p_auth_timeout, "Authentication timeout", 0);
	if (registry_instance_add_param(i, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	return POM_OK;

err:
	proto_ppp_pap_cleanup(priv);
	return POM_ERR;

}

static int proto_ppp_pap_cleanup(void *proto_priv) {

	if (!proto_priv)
		return POM_OK;

	struct proto_ppp_pap_priv *priv = proto_priv;

	if (priv->p_auth_timeout)
		ptype_cleanup(priv->p_auth_timeout);

	if (priv->evt_request)
		event_unregister(priv->evt_request);
	if (priv->evt_ack_nack)
		event_unregister(priv->evt_ack_nack);

	free(priv);

	return POM_OK;
}


static int proto_ppp_pap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct ppp_pap_header) > s->plen)
		return PROTO_INVALID;

	struct ppp_pap_header *pchdr = s->pload;
	size_t len = ntohs(pchdr->length);

	if (len > s->plen)
		return PROTO_INVALID;

	// Keep only the payload len
	len -= sizeof(struct ppp_pap_header);

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ppp_pap_field_code], pchdr->code);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ppp_pap_field_identifier], pchdr->identifier);

	struct proto_ppp_pap_priv *priv = proto_priv;

	if (conntrack_get(stack, stack_index) != POM_OK)
		return PROTO_ERR;
	if (conntrack_delayed_cleanup(s->ce, *PTYPE_UINT32_GETVAL(priv->p_auth_timeout), p->ts)) {
		conntrack_unlock(s->ce);
		return PROTO_ERR;
	}
	
	conntrack_unlock(s->ce);

	if (pchdr->code == 1 && event_has_listener(priv->evt_request)) {

		if (len < 4)
			return PROTO_INVALID;

		uint8_t *peer_id_len = s->pload + sizeof(struct ppp_pap_header);
		if (*peer_id_len > len - 2)
			return PROTO_INVALID;

		len -= (*peer_id_len + 1);
		uint8_t *pwd_len = peer_id_len + *peer_id_len + 1;
		if (*pwd_len > len - 1)
			return PROTO_INVALID;


		// Process the challenge/response event
		struct event *evt = event_alloc(priv->evt_request);
		if (!evt)
			return PROTO_ERR;

		struct data *evt_data = event_get_data(evt);
		PTYPE_UINT8_SETVAL(evt_data[evt_ppp_pap_request_code].value, pchdr->code);
		data_set(evt_data[evt_ppp_pap_request_code]);
		PTYPE_UINT8_SETVAL(evt_data[evt_ppp_pap_request_identifier].value, pchdr->identifier);
		data_set(evt_data[evt_ppp_pap_request_identifier]);

	
		PTYPE_STRING_SETVAL_N(evt_data[evt_ppp_pap_request_peer_id].value, (char *)peer_id_len + 1, *peer_id_len);
		data_set(evt_data[evt_ppp_pap_request_peer_id]);

		PTYPE_STRING_SETVAL_N(evt_data[evt_ppp_pap_request_password].value, (char *)pwd_len + 1, *pwd_len);
		data_set(evt_data[evt_ppp_pap_request_password]);

		if (event_process(evt, stack, stack_index, p->ts) != POM_OK)
			return PROTO_ERR;

	}

	if ((pchdr->code == 2 || pchdr->code == 3) && event_has_listener(priv->evt_ack_nack)) {
		
		struct event *evt = event_alloc(priv->evt_ack_nack);
		if (!evt)
			return PROTO_ERR;

		struct data *evt_data = event_get_data(evt);
		PTYPE_UINT8_SETVAL(evt_data[evt_ppp_pap_ack_nack_code].value, pchdr->code);
		data_set(evt_data[evt_ppp_pap_ack_nack_code]);
		PTYPE_UINT8_SETVAL(evt_data[evt_ppp_pap_ack_nack_identifier].value, pchdr->identifier);
		data_set(evt_data[evt_ppp_pap_ack_nack_identifier]);

		uint8_t *msg_len = s->pload + sizeof(struct ppp_pap_header);
		if (*msg_len > len - 1)
			return PROTO_INVALID;

		PTYPE_STRING_SETVAL_N(evt_data[evt_ppp_pap_ack_nack_message].value, (char *)msg_len + 1, *msg_len);
		data_set(evt_data[evt_ppp_pap_ack_nack_message]);

		if (event_process(evt, stack, stack_index, p->ts) != POM_OK)
			return PROTO_ERR;

	}

	return PROTO_OK;

}

static int proto_ppp_pap_mod_unregister() {

	return proto_unregister("ppp_pap");

}
