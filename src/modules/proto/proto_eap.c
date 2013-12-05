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
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_bytes.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/proto_eap.h>

#include "proto_eap.h"

#include <arpa/inet.h>

struct mod_reg_info* proto_eap_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_eap_mod_register;
	reg_info.unregister_func = proto_eap_mod_unregister;
	reg_info.dependencies = "ptype_bool, ptype_bytes, ptype_string, ptype_uint8, ptype_uint32";

	return &reg_info;
}

static int proto_eap_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_EAP_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "code";
	fields[0].value_type = ptype_get_type("uint8");
	fields[0].description = "Code";
	fields[1].name = "identifier";
	fields[1].value_type = ptype_get_type("uint8");
	fields[1].description = "Identifier";

	static struct proto_reg_info proto_eap = { 0 };
	proto_eap.name = "eap";
	proto_eap.api_ver = PROTO_API_VER;
	proto_eap.mod = mod;
	proto_eap.pkt_fields = fields;
	proto_eap.number_class = "eap";

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 256; // No hashing done here
	ct_info.fwd_pkt_field_id = proto_eap_field_identifier;
	ct_info.rev_pkt_field_id = CONNTRACK_PKT_FIELD_NONE;
	proto_eap.ct_info = &ct_info;


	proto_eap.init = proto_eap_init;
	proto_eap.cleanup = proto_eap_cleanup;
	proto_eap.process = proto_eap_process;

	if (proto_register(&proto_eap) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_eap_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("8021x", 0x0, proto) != POM_OK ||
		proto_number_register("ppp", 0xc227, proto) != POM_OK)
		return POM_ERR;

	struct proto_eap_priv *priv = malloc(sizeof(struct proto_eap_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_eap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_eap_priv));
	proto_set_priv(proto, priv);

	priv->p_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!priv->p_timeout)
		goto err;

	struct registry_param *p = registry_new_param("timeout", "60", priv->p_timeout, "Transaction timeout", 0);
	if (registry_instance_add_param(i, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	static struct data_item_reg evt_identity_data_items[PROTO_EAP_EVT_IDENTITY_DATA_COUNT] = { { 0 } };
	evt_identity_data_items[evt_eap_common_identifier].name = "identifier";
	evt_identity_data_items[evt_eap_common_identifier].value_type = ptype_get_type("uint8");
	evt_identity_data_items[evt_eap_common_code].name = "code";
	evt_identity_data_items[evt_eap_common_code].value_type = ptype_get_type("uint8");
	evt_identity_data_items[evt_eap_identity_identity].name = "identity";
	evt_identity_data_items[evt_eap_identity_identity].value_type = ptype_get_type("string");

	static struct data_reg evt_eap_identity_data = {
		.items = evt_identity_data_items,
		.data_count = PROTO_EAP_EVT_IDENTITY_DATA_COUNT
	};

	static struct event_reg_info proto_eap_identity = { 0 };
	proto_eap_identity.source_name = "proto_eap";
	proto_eap_identity.source_obj = priv;
	proto_eap_identity.name = "eap_identity";
	proto_eap_identity.description = "EAP Identity";
	proto_eap_identity.data_reg = &evt_eap_identity_data;

	priv->evt_identity = event_register(&proto_eap_identity);
	if (!priv->evt_identity)
		goto err;

	static struct data_item_reg evt_md5_challenge_data_items[PROTO_EAP_EVT_MD5_CHALLENGE_DATA_COUNT] = { { 0 } };
	evt_md5_challenge_data_items[evt_eap_common_identifier].name = "identifier";
	evt_md5_challenge_data_items[evt_eap_common_identifier].value_type = ptype_get_type("uint8");
	evt_md5_challenge_data_items[evt_eap_common_code].name = "code";
	evt_md5_challenge_data_items[evt_eap_common_code].value_type = ptype_get_type("uint8");
	evt_md5_challenge_data_items[evt_eap_md5_challenge_value].name = "value";
	evt_md5_challenge_data_items[evt_eap_md5_challenge_value].value_type = ptype_get_type("bytes");
	evt_md5_challenge_data_items[evt_eap_md5_challenge_name].name = "name";
	evt_md5_challenge_data_items[evt_eap_md5_challenge_name].value_type = ptype_get_type("string");

	static struct data_reg evt_eap_md5_challenge_data = {
		.items = evt_md5_challenge_data_items,
		.data_count = PROTO_EAP_EVT_MD5_CHALLENGE_DATA_COUNT
	};

	static struct event_reg_info proto_eap_md5_challenge = { 0 };
	proto_eap_md5_challenge.source_name = "proto_eap";
	proto_eap_md5_challenge.source_obj = priv;
	proto_eap_md5_challenge.name = "eap_md5_challenge";
	proto_eap_md5_challenge.description = "EAP MD5-Challenge";
	proto_eap_md5_challenge.data_reg = &evt_eap_md5_challenge_data;

	priv->evt_md5_challenge = event_register(&proto_eap_md5_challenge);
	if (!priv->evt_md5_challenge)
		goto err;

	static struct data_item_reg evt_success_failure_data_items[PROTO_EAP_EVT_SUCCESS_FAILURE_DATA_COUNT] = { { 0 } };
	evt_success_failure_data_items[evt_eap_common_identifier].name = "identifier";
	evt_success_failure_data_items[evt_eap_common_identifier].value_type = ptype_get_type("uint8");
	evt_success_failure_data_items[evt_eap_success_failure_success].name = "success";
	evt_success_failure_data_items[evt_eap_success_failure_success].value_type = ptype_get_type("bool");

	static struct data_reg evt_eap_success_failure_data = {
		.items = evt_success_failure_data_items,
		.data_count = PROTO_EAP_EVT_SUCCESS_FAILURE_DATA_COUNT
	};

	static struct event_reg_info proto_eap_success_failure = { 0 };
	proto_eap_success_failure.source_name = "proto_eap";
	proto_eap_success_failure.source_obj = priv;
	proto_eap_success_failure.name = "eap_success_failure";
	proto_eap_success_failure.description = "EAP Success/Failure";
	proto_eap_success_failure.data_reg = &evt_eap_success_failure_data;

	priv->evt_success_failure = event_register(&proto_eap_success_failure);
	if (!priv->evt_success_failure)
		goto err;

	return POM_OK;
	
err:
	proto_eap_cleanup(priv);
	return POM_ERR;
}

static int proto_eap_cleanup(void *proto_priv) {

	if (!proto_priv)
		return POM_OK;

	struct proto_eap_priv *priv = proto_priv;

	if (priv->p_timeout)
		ptype_cleanup(priv->p_timeout);

	if (priv->evt_identity)
		event_unregister(priv->evt_identity);
	if (priv->evt_md5_challenge)
		event_unregister(priv->evt_md5_challenge);
	if (priv->evt_success_failure)
		event_unregister(priv->evt_success_failure);

	free(priv);

	return POM_OK;
}

static int proto_eap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct eap_header) > s->plen)
		return PROTO_INVALID;

	struct proto_eap_priv *priv = proto_priv;

	struct eap_header *hdr = s->pload;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_eap_field_code], hdr->code);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_eap_field_identifier], hdr->identifier);

	
	if (hdr->code < 1 || hdr->code > 4)
		return PROTO_INVALID;

	uint16_t len = ntohs(hdr->length);

	if (len > s->plen)
		return PROTO_INVALID;

	// Keep only the payload lenght
	len -= sizeof(struct eap_header);
	
	if (conntrack_get(stack, stack_index) != POM_OK)
		return PROTO_ERR;

	if (conntrack_delayed_cleanup(s->ce, *PTYPE_UINT32_GETVAL(priv->p_timeout), p->ts) != POM_OK) {
		conntrack_unlock(s->ce);
		return PROTO_ERR;
	}
	conntrack_unlock(s->ce);

	if (hdr->code == 3 || hdr->code == 4) {
		// Content length is 0 for success and failure
		if (len != 4)
			return PROTO_INVALID;
		len = 0;

		if (!event_has_listener(priv->evt_success_failure))
			return PROTO_OK;

		struct event *evt = event_alloc(priv->evt_success_failure);
		if (!evt)
			return PROTO_ERR;
		struct data *evt_data = event_get_data(evt);
		PTYPE_UINT8_SETVAL(evt_data[evt_eap_common_identifier].value, hdr->identifier);
		data_set(evt_data[evt_eap_common_identifier]);
		PTYPE_BOOL_SETVAL(evt_data[evt_eap_success_failure_success].value, (hdr->code == 3 ? 1 : 0));
		data_set(evt_data[evt_eap_success_failure_success]);

		return event_process(evt, stack, stack_index, p->ts);
	}

	// At this point, code is either 1 or 2 (request/response)

	void *pload = s->pload + sizeof(struct eap_header);

	uint8_t type = 0;

	// There is at least 1 byte of data for request/response
	if (len < 1)
		return PROTO_INVALID;
	len--;

	type = *(uint8_t*)pload;
	pload++;

	struct event *evt = NULL;
	struct data *evt_data = NULL;
	
	switch (type) {
		case 1: // Identity
			
			if (!event_has_listener(priv->evt_identity))
				break;

			evt = event_alloc(priv->evt_identity);
			if (!evt)
				return PROTO_ERR;
			if (len) {
				evt_data = event_get_data(evt);
				PTYPE_STRING_SETVAL_N(evt_data[evt_eap_identity_identity].value, pload, len);
				data_set(evt_data[evt_eap_identity_identity]);
			}

			break;

		case 4: // MD5-Challenge
		
			if (!event_has_listener(priv->evt_md5_challenge))
				break;

			if (len < 17)
				return PROTO_INVALID;

			uint8_t value_size = *(uint8_t*)pload;
			if (value_size != 16)
				return PROTO_INVALID;

			pload++;
			len--;

			evt = event_alloc(priv->evt_md5_challenge);
			if (!evt)
				return PROTO_ERR;
			evt_data = event_get_data(evt);

			PTYPE_BYTES_SETLEN(evt_data[evt_eap_md5_challenge_value].value, 16);
			PTYPE_BYTES_SETVAL(evt_data[evt_eap_md5_challenge_value].value, pload);
			data_set(evt_data[evt_eap_md5_challenge_value]);
			
			if (len > 16) {
				PTYPE_STRING_SETVAL_N(evt_data[evt_eap_md5_challenge_name].value, pload + 16, len - 16);
				data_set(evt_data[evt_eap_md5_challenge_name]);
			}
			break;
	}
	
	if (evt) {
		if (!evt_data)
			evt_data = event_get_data(evt);
		PTYPE_UINT8_SETVAL(evt_data[evt_eap_common_identifier].value, hdr->identifier);
		data_set(evt_data[evt_eap_common_identifier]);
		PTYPE_UINT8_SETVAL(evt_data[evt_eap_common_code].value, hdr->code);
		data_set(evt_data[evt_eap_common_code]);

		if (event_process(evt, stack, stack_index, p->ts) != POM_OK)
			return PROTO_ERR;
	}


	return PROTO_OK;

}

static int proto_eap_mod_unregister() {

	return proto_unregister("eap");
}
