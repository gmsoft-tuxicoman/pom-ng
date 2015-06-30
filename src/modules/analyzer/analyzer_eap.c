/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2014 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/proto_eap.h>
#include <pom-ng/proto_vlan.h>

#include "analyzer_eap.h"

struct mod_reg_info* analyzer_eap_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_eap_mod_register;
	reg_info.unregister_func = analyzer_eap_mod_unregister;
	reg_info.dependencies = "proto_eap, ptype_bool, ptype_bytes, ptype_uint8, ptype_string";

	return &reg_info;
}


int analyzer_eap_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_eap;
	memset(&analyzer_eap, 0, sizeof(struct analyzer_reg));
	analyzer_eap.name = "eap";
	analyzer_eap.mod = mod;
	analyzer_eap.init = analyzer_eap_init;
	analyzer_eap.cleanup = analyzer_eap_cleanup;

	return analyzer_register(&analyzer_eap);

}

int analyzer_eap_mod_unregister() {

	int res = analyzer_unregister("eap");

	return res;
}

int analyzer_eap_init(struct analyzer *analyzer) {


	struct analyzer_eap_priv *priv = malloc(sizeof(struct analyzer_eap_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_eap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_eap_priv));
	analyzer->priv = priv;

	priv->evt_md5_challenge = event_find("eap_md5_challenge");
	priv->evt_success_failure = event_find("eap_success_failure");
	if (!priv->evt_md5_challenge || !priv->evt_success_failure)
		goto err;


	static struct data_item_reg evt_md5_auth_data_items[ANALYZER_EAP_MD5_AUTH_DATA_COUNT] = { { 0 } };

	evt_md5_auth_data_items[analyzer_eap_common_client].name = "client";
	evt_md5_auth_data_items[analyzer_eap_common_client].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_md5_auth_data_items[analyzer_eap_common_server].name = "server";
	evt_md5_auth_data_items[analyzer_eap_common_server].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_md5_auth_data_items[analyzer_eap_common_top_proto].name = "top_proto";
	evt_md5_auth_data_items[analyzer_eap_common_top_proto].value_type = ptype_get_type("string");

	evt_md5_auth_data_items[analyzer_eap_common_vlan].name = "vlan";
	evt_md5_auth_data_items[analyzer_eap_common_vlan].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_md5_auth_data_items[analyzer_eap_common_identifier].name = "identifier";
	evt_md5_auth_data_items[analyzer_eap_common_identifier].value_type = ptype_get_type("uint8");

	evt_md5_auth_data_items[analyzer_eap_common_username].name = "username";
	evt_md5_auth_data_items[analyzer_eap_common_username].value_type = ptype_get_type("string");

	evt_md5_auth_data_items[analyzer_eap_common_success].name = "success";
	evt_md5_auth_data_items[analyzer_eap_common_success].value_type = ptype_get_type("bool");

	evt_md5_auth_data_items[analyzer_eap_md5_challenge].name = "challenge";
	evt_md5_auth_data_items[analyzer_eap_md5_challenge].value_type = ptype_get_type("bytes");

	evt_md5_auth_data_items[analyzer_eap_md5_response].name = "response";
	evt_md5_auth_data_items[analyzer_eap_md5_response].value_type = ptype_get_type("bytes");


	static struct data_reg evt_md5_auth_data = {
		.items = evt_md5_auth_data_items,
		.data_count = ANALYZER_EAP_MD5_AUTH_DATA_COUNT
	};

	static struct event_reg_info analyzer_eap_evt_md5_auth = { 0 };
	analyzer_eap_evt_md5_auth.source_name = "analyzer_eap";
	analyzer_eap_evt_md5_auth.source_obj = analyzer;
	analyzer_eap_evt_md5_auth.name = "eap_md5_auth";
	analyzer_eap_evt_md5_auth.description = "PPP CHAP MD5 authentication";
	analyzer_eap_evt_md5_auth.data_reg = &evt_md5_auth_data;
	analyzer_eap_evt_md5_auth.listeners_notify = analyzer_eap_event_listeners_notify;

	priv->evt_md5_auth = event_register(&analyzer_eap_evt_md5_auth);
	if (!priv->evt_md5_auth)
		goto err;

	return POM_OK;

err:
	analyzer_eap_cleanup(analyzer);
	return POM_ERR;
}

int analyzer_eap_cleanup(struct analyzer *analyzer) {
	

	struct analyzer_eap_priv *priv = analyzer->priv;
	if (!priv)
		return POM_OK;

	int res = POM_OK;

	if (priv->evt_md5_auth)
		res += event_unregister(priv->evt_md5_auth);

	free(priv);

	return res;
}

int analyzer_eap_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_eap_priv *priv = analyzer->priv;

	if (event_has_listener(priv->evt_md5_auth)) {
		if (event_listener_register(priv->evt_md5_challenge, analyzer, analyzer_eap_event_process_begin, NULL) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_success_failure, analyzer, analyzer_eap_event_process_begin, NULL) != POM_OK) {
			event_listener_unregister(priv->evt_md5_challenge, analyzer);
			return POM_ERR;
		}

	} else {
		if (event_listener_unregister(priv->evt_md5_challenge, analyzer) != POM_OK || event_listener_unregister(priv->evt_success_failure, analyzer) != POM_OK)
			return POM_ERR;
	}

	return POM_OK;

}


int analyzer_eap_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;

	struct analyzer_eap_priv *apriv = analyzer->priv;

	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce)
		return PROTO_ERR;

	conntrack_lock(s->ce);

	struct ptype *src = NULL, *dst = NULL;

	struct analyzer_eap_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);
	if (!cpriv) {
		cpriv = malloc(sizeof(struct analyzer_eap_ce_priv));
		if (!cpriv) {
			pom_oom(sizeof(struct analyzer_eap_ce_priv));
			goto err;
		}
		memset(cpriv, 0, sizeof(struct analyzer_eap_ce_priv));


		if (conntrack_add_priv(s->ce, analyzer, cpriv, analyzer_eap_ce_priv_cleanup) != POM_OK) {
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
				if (!cpriv->vlan) {
					conntrack_unlock(s->ce);
					return POM_ERR;
				}
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
	struct data *evt_data = event_get_data(evt);

	int dir = POM_DIR_UNK;

	if (evt_reg == apriv->evt_md5_challenge) {
		uint8_t code = *PTYPE_UINT8_GETVAL(evt_data[evt_eap_common_code].value);

		if (code == 1) {
			if (!cpriv->evt_request) {
				event_refcount_inc(evt);
				cpriv->evt_request = evt;
			}
			dir = POM_DIR_REV;
		} else if (code == 2) {
			if (!cpriv->evt_response) {
				event_refcount_inc(evt);
				cpriv->evt_response = evt;
			}
			dir = POM_DIR_FWD;
		}


	} else {
		if (!cpriv->evt_result) {
			event_refcount_inc(evt);
			cpriv->evt_result = evt;
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

	if (cpriv->evt_request && cpriv->evt_response && cpriv->evt_result)
		res = analyzer_eap_finalize(apriv, cpriv);

	conntrack_unlock(s->ce);

	return res;

err:
	conntrack_unlock(s->ce);
	return POM_ERR;

}

int analyzer_eap_finalize(struct analyzer_eap_priv *apriv, struct analyzer_eap_ce_priv *cpriv) {

	if (!cpriv->evt_request || !cpriv->evt_response)
		return POM_OK;

	struct event *evt = NULL;
	struct data *evt_data = NULL;

	struct data *evt_req_data = event_get_data(cpriv->evt_request);
	struct data *evt_rsp_data = event_get_data(cpriv->evt_response);

	if (!data_is_set(evt_rsp_data[evt_eap_md5_challenge_value]))
		return POM_OK;
	if (!data_is_set(evt_req_data[evt_eap_md5_challenge_value]))
		return POM_OK;

	evt = event_alloc(apriv->evt_md5_auth);
	if (!evt)
		return POM_ERR;

	evt_data = event_get_data(evt);

	if (ptype_copy(evt_data[analyzer_eap_md5_challenge].value, evt_req_data[evt_eap_md5_challenge_value].value) != POM_OK) {
		event_cleanup(evt);
		return POM_ERR;
	}
	data_set(evt_data[analyzer_eap_md5_challenge]);
	if (ptype_copy(evt_data[analyzer_eap_md5_response].value, evt_rsp_data[evt_eap_md5_challenge_value].value) != POM_OK) {
		event_cleanup(evt);
		return POM_ERR;
	}
	data_set(evt_data[analyzer_eap_md5_response]);
		


	if (cpriv->client) {
		evt_data[analyzer_eap_common_client].value = cpriv->client;
		data_set(evt_data[analyzer_eap_common_client]);
		data_do_clean(evt_data[analyzer_eap_common_client]);
		cpriv->client = NULL;
	}

	if (cpriv->server) {
		evt_data[analyzer_eap_common_server].value = cpriv->server;
		data_set(evt_data[analyzer_eap_common_server]);
		data_do_clean(evt_data[analyzer_eap_common_server]);
		cpriv->server = NULL;
	}

	if (cpriv->vlan) {
		evt_data[analyzer_eap_common_vlan].value = cpriv->vlan;
		data_set(evt_data[analyzer_eap_common_vlan]);
		data_do_clean(evt_data[analyzer_eap_common_vlan]);
		cpriv->vlan = NULL;
	}

	if (cpriv->top_proto) {
		PTYPE_STRING_SETVAL(evt_data[analyzer_eap_common_top_proto].value, cpriv->top_proto);
		data_set(evt_data[analyzer_eap_common_top_proto]);
	}

	if (ptype_copy(evt_data[analyzer_eap_common_identifier].value, evt_req_data[evt_eap_common_identifier].value) != POM_OK) {
		event_cleanup(evt);
		return POM_ERR;
	}
	data_set(evt_data[analyzer_eap_common_identifier]);

	if (!data_is_set(evt_rsp_data[evt_eap_md5_challenge_name])) {
		event_cleanup(evt);
		return POM_OK;
	}

	if (ptype_copy(evt_data[analyzer_eap_common_username].value, evt_rsp_data[evt_eap_md5_challenge_name].value) != POM_OK) {
		event_cleanup(evt);
		return POM_ERR;
	}
	data_set(evt_data[analyzer_eap_common_username]);

	if (cpriv->evt_result) {
		struct data *evt_res_data = event_get_data(cpriv->evt_result);
		ptype_copy(evt_data[analyzer_eap_common_success].value, evt_res_data[evt_eap_success_failure_success].value);
		data_set(evt_data[analyzer_eap_common_success]);

		event_refcount_dec(cpriv->evt_result);
		cpriv->evt_result = NULL;
	}

	ptime ts = event_get_timestamp(cpriv->evt_response);

	event_refcount_dec(cpriv->evt_request);
	cpriv->evt_request = NULL;
	event_refcount_dec(cpriv->evt_response);
	cpriv->evt_response = NULL;

	return event_process(evt, NULL, 0, ts);
}


int analyzer_eap_ce_priv_cleanup(void *obj, void *priv) {

	struct analyzer *analyzer = obj;

	struct analyzer_eap_ce_priv *cpriv = priv;

	int res = analyzer_eap_finalize(analyzer->priv, cpriv);
	
	if (cpriv->evt_request)
		event_refcount_dec(cpriv->evt_request);
	if (cpriv->evt_response)
		event_refcount_dec(cpriv->evt_response);
	if (cpriv->evt_result)
		event_refcount_dec(cpriv->evt_result);

	if (cpriv->client)
		ptype_cleanup(cpriv->client);
	if (cpriv->server)
		ptype_cleanup(cpriv->server);
	if (cpriv->vlan)
		ptype_cleanup(cpriv->vlan);


	free(priv);

	return res;
}
