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

#include <pom-ng/analyzer.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_bytes.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/proto_ppp_pap.h>
#include <pom-ng/proto_vlan.h>

#include "analyzer_ppp_pap.h"

struct mod_reg_info* analyzer_ppp_pap_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_ppp_pap_mod_register;
	reg_info.unregister_func = analyzer_ppp_pap_mod_unregister;
	reg_info.dependencies = "proto_ppp_pap, ptype_bool, ptype_uint8, ptype_string";

	return &reg_info;
}


int analyzer_ppp_pap_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_ppp_pap;
	memset(&analyzer_ppp_pap, 0, sizeof(struct analyzer_reg));
	analyzer_ppp_pap.name = "ppp_pap";
	analyzer_ppp_pap.api_ver = ANALYZER_API_VER;
	analyzer_ppp_pap.mod = mod;
	analyzer_ppp_pap.init = analyzer_ppp_pap_init;
	analyzer_ppp_pap.cleanup = analyzer_ppp_pap_cleanup;

	return analyzer_register(&analyzer_ppp_pap);

}

int analyzer_ppp_pap_mod_unregister() {

	int res = analyzer_unregister("ppp_pap");

	return res;
}

int analyzer_ppp_pap_init(struct analyzer *analyzer) {


	struct analyzer_ppp_pap_priv *priv = malloc(sizeof(struct analyzer_ppp_pap_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_ppp_pap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_ppp_pap_priv));
	analyzer->priv = priv;

	priv->evt_request = event_find("ppp_pap_request");
	priv->evt_ack_nack = event_find("ppp_pap_ack_nack");
	if (!priv->evt_request || !priv->evt_ack_nack)
		goto err;

	static struct data_item_reg evt_auth_data_items[ANALYZER_PPP_PAP_AUTH_DATA_COUNT] = { { 0 } };

	evt_auth_data_items[analyzer_ppp_pap_auth_client].name = "client";
	evt_auth_data_items[analyzer_ppp_pap_auth_client].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_auth_data_items[analyzer_ppp_pap_auth_server].name = "server";
	evt_auth_data_items[analyzer_ppp_pap_auth_server].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_auth_data_items[analyzer_ppp_pap_auth_top_proto].name = "top_proto";
	evt_auth_data_items[analyzer_ppp_pap_auth_top_proto].value_type = ptype_get_type("string");

	evt_auth_data_items[analyzer_ppp_pap_auth_vlan].name = "vlan";
	evt_auth_data_items[analyzer_ppp_pap_auth_vlan].flags = DATA_REG_FLAG_NO_ALLOC;
	
	evt_auth_data_items[analyzer_ppp_pap_auth_identifier].name = "identifier";
	evt_auth_data_items[analyzer_ppp_pap_auth_identifier].value_type = ptype_get_type("uint8");

	evt_auth_data_items[analyzer_ppp_pap_auth_success].name = "success";
	evt_auth_data_items[analyzer_ppp_pap_auth_success].value_type = ptype_get_type("bool");

	evt_auth_data_items[analyzer_ppp_pap_auth_peer_id].name = "peer_id";
	evt_auth_data_items[analyzer_ppp_pap_auth_peer_id].value_type = ptype_get_type("string");

	evt_auth_data_items[analyzer_ppp_pap_auth_password].name = "password";
	evt_auth_data_items[analyzer_ppp_pap_auth_password].value_type = ptype_get_type("string");

	static struct data_reg evt_auth_data = {
		.items = evt_auth_data_items,
		.data_count = ANALYZER_PPP_PAP_AUTH_DATA_COUNT
	};

	static struct event_reg_info analyzer_ppp_pap_evt_auth = { 0 };
	analyzer_ppp_pap_evt_auth.source_name = "analyzer_ppp_pap";
	analyzer_ppp_pap_evt_auth.source_obj = analyzer;
	analyzer_ppp_pap_evt_auth.name = "ppp_pap_auth";
	analyzer_ppp_pap_evt_auth.description = "PPP PAP MD5 authentication";
	analyzer_ppp_pap_evt_auth.data_reg = &evt_auth_data;
	analyzer_ppp_pap_evt_auth.listeners_notify = analyzer_ppp_pap_event_listeners_notify;

	priv->evt_auth = event_register(&analyzer_ppp_pap_evt_auth);
	if (!priv->evt_auth)
		goto err;

	return POM_OK;

err:
	analyzer_ppp_pap_cleanup(analyzer);
	return POM_ERR;
}

int analyzer_ppp_pap_cleanup(struct analyzer *analyzer) {
	

	struct analyzer_ppp_pap_priv *priv = analyzer->priv;
	if (!priv)
		return POM_OK;

	int res = POM_OK;

	if (priv->evt_auth)
		res += event_unregister(priv->evt_auth);

	free(priv);

	return res;
}

int analyzer_ppp_pap_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_ppp_pap_priv *priv = analyzer->priv;

	if (has_listeners) {
		if (event_listener_register(priv->evt_request, analyzer, analyzer_ppp_pap_event_process_begin, NULL) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_ack_nack, analyzer, analyzer_ppp_pap_event_process_begin, NULL) != POM_OK) {
			event_listener_unregister(priv->evt_request, analyzer);
			return POM_ERR;
		}

	} else {
		if (event_listener_unregister(priv->evt_request, analyzer) != POM_OK || event_listener_unregister(priv->evt_ack_nack, analyzer) != POM_OK)
			return POM_ERR;
	}

	return POM_OK;

}


int analyzer_ppp_pap_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;

	struct analyzer_ppp_pap_priv *apriv = analyzer->priv;

	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce)
		return PROTO_ERR;

	conntrack_lock(s->ce);

	struct ptype *src = NULL, *dst = NULL;

	struct analyzer_ppp_pap_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);
	if (!cpriv) {
		cpriv = malloc(sizeof(struct analyzer_ppp_pap_ce_priv));
		if (!cpriv) {
			pom_oom(sizeof(struct analyzer_ppp_pap_ce_priv));
			goto err;
		}
		memset(cpriv, 0, sizeof(struct analyzer_ppp_pap_ce_priv));


		if (conntrack_add_priv(s->ce, analyzer, cpriv, analyzer_ppp_pap_ce_priv_cleanup) != POM_OK) {
			free(cpriv);
			goto err;
		}

		// Try to find the source and destination
		
		unsigned int i = 0;
		for (i = 1; i <= 4; i++) {
			struct proto_process_stack *prev_stack = &stack[stack_index - i];
			if (!prev_stack->proto)	
				break;

			struct proto_reg_info *info = proto_get_info(prev_stack->proto);
			if (!strcmp(info->name, "vlan")) {
				cpriv->vlan = ptype_alloc_from(prev_stack->pkt_info->fields_value[proto_vlan_field_vid]);
				if (!cpriv->vlan)
					return POM_ERR;
			}

			unsigned int j;
			for (j = 0; !src || !dst; j++) {
				struct proto_reg_info *prev_info = proto_get_info(prev_stack->proto);
				if (!prev_info->pkt_fields)
					break;
				char *name = prev_info->pkt_fields[j].name;
				if (!name)
					break;

				if (!src && !strcmp(name, "src"))
					src = prev_stack->pkt_info->fields_value[j];
				else if (!dst && !strcmp(name, "dst"))
					dst = prev_stack->pkt_info->fields_value[j];
			}

			if (src || dst)
				break;
		}

		struct proto_process_stack *prev_stack = &stack[stack_index - 2];
		if (prev_stack->proto) {
			struct proto_reg_info *info = proto_get_info(prev_stack->proto);
			cpriv->top_proto = info->name;
		}
	}

	struct event_reg *evt_reg = event_get_reg(evt);

	int dir = POM_DIR_UNK;

	if (evt_reg == apriv->evt_request) {

		if (!cpriv->evt_request) {
			event_refcount_inc(evt);
			cpriv->evt_request = evt;
		}
		dir = POM_DIR_FWD;

	} else {
		if (!cpriv->evt_ack_nack) {
			event_refcount_inc(evt);
			cpriv->evt_ack_nack = evt;
		}
		dir = POM_DIR_REV;
	}

	if (src && dst && dir != POM_DIR_UNK) {
		if (dir == POM_DIR_FWD) {
			cpriv->client = ptype_alloc_from(src);
			cpriv->server = ptype_alloc_from(dst);
		} else {
			cpriv->client = ptype_alloc_from(dst);
			cpriv->server = ptype_alloc_from(src);
		}
	}

	int res = POM_OK;

	if (cpriv->evt_request && cpriv->evt_ack_nack)
		res = analyzer_ppp_pap_finalize(apriv, cpriv);

	conntrack_unlock(s->ce);

	return res;

err:
	conntrack_unlock(s->ce);
	return POM_ERR;

}

int analyzer_ppp_pap_finalize(struct analyzer_ppp_pap_priv *apriv, struct analyzer_ppp_pap_ce_priv *cpriv) {

	if (!cpriv->evt_request)
		return POM_OK;

	struct event *evt = NULL;
	struct data *evt_data = NULL;

	struct data *evt_req_data = event_get_data(cpriv->evt_request);

	evt = event_alloc(apriv->evt_auth);
	if (!evt)
		return POM_ERR;

	evt_data = event_get_data(evt);

	if (ptype_copy(evt_data[analyzer_ppp_pap_auth_peer_id].value, evt_req_data[evt_ppp_pap_request_peer_id].value) != POM_OK)
		return POM_ERR;
	data_set(evt_data[analyzer_ppp_pap_auth_peer_id]);

	if (ptype_copy(evt_data[analyzer_ppp_pap_auth_password].value, evt_req_data[evt_ppp_pap_request_password].value) != POM_OK)
		return POM_ERR;
	data_set(evt_data[analyzer_ppp_pap_auth_password]);
	

	if (cpriv->client) {
		evt_data[analyzer_ppp_pap_auth_client].value = cpriv->client;
		data_set(evt_data[analyzer_ppp_pap_auth_client]);
		data_do_clean(evt_data[analyzer_ppp_pap_auth_client]);
		cpriv->client = NULL;
	}

	if (cpriv->server) {
		evt_data[analyzer_ppp_pap_auth_server].value = cpriv->server;
		data_set(evt_data[analyzer_ppp_pap_auth_server]);
		data_do_clean(evt_data[analyzer_ppp_pap_auth_server]);
		cpriv->server = NULL;
	}

	if (cpriv->vlan) {
		evt_data[analyzer_ppp_pap_auth_vlan].value = cpriv->vlan;
		data_set(evt_data[analyzer_ppp_pap_auth_vlan]);
		data_do_clean(evt_data[analyzer_ppp_pap_auth_vlan]);
		cpriv->vlan = NULL;
	}

	if (cpriv->top_proto) {
		PTYPE_STRING_SETVAL(evt_data[analyzer_ppp_pap_auth_top_proto].value, cpriv->top_proto);
		data_set(evt_data[analyzer_ppp_pap_auth_top_proto]);
	}

	if (ptype_copy(evt_data[analyzer_ppp_pap_auth_identifier].value, evt_req_data[evt_ppp_pap_request_identifier].value) != POM_OK)
		return POM_ERR;
	data_set(evt_data[analyzer_ppp_pap_auth_identifier]);

	if (cpriv->evt_ack_nack) {
		struct data *evt_ack_data = event_get_data(cpriv->evt_ack_nack);
		uint8_t code = *PTYPE_UINT8_GETVAL(evt_ack_data[evt_ppp_pap_ack_nack_code].value);
		
		if (code == 2) {
			PTYPE_BOOL_SETVAL(evt_data[analyzer_ppp_pap_auth_success].value, 1);
		} else {
			PTYPE_BOOL_SETVAL(evt_data[analyzer_ppp_pap_auth_success].value, 0);
		}
		data_set(evt_data[analyzer_ppp_pap_auth_success]);

		event_refcount_dec(cpriv->evt_ack_nack);
		cpriv->evt_ack_nack = NULL;
	}

	ptime ts = event_get_timestamp(cpriv->evt_request);

	event_refcount_dec(cpriv->evt_request);
	cpriv->evt_request = NULL;

	return event_process(evt, NULL, 0, ts);
}


int analyzer_ppp_pap_ce_priv_cleanup(void *obj, void *priv) {

	struct analyzer *analyzer = obj;

	struct analyzer_ppp_pap_ce_priv *cpriv = priv;

	int res = analyzer_ppp_pap_finalize(analyzer->priv, cpriv);
	
	if (cpriv->evt_request)
		event_refcount_dec(cpriv->evt_request);
	if (cpriv->evt_ack_nack)
		event_refcount_dec(cpriv->evt_ack_nack);

	if (cpriv->client)
		ptype_cleanup(cpriv->client);
	if (cpriv->server)
		ptype_cleanup(cpriv->server);
	if (cpriv->vlan)
		ptype_cleanup(cpriv->vlan);

	free(priv);

	return res;
}
