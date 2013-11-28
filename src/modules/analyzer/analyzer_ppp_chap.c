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
#include <pom-ng/proto_ppp_chap.h>

#include "analyzer_ppp_chap.h"

struct mod_reg_info* analyzer_ppp_chap_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_ppp_chap_mod_register;
	reg_info.unregister_func = analyzer_ppp_chap_mod_unregister;
	reg_info.dependencies = "proto_ppp_chap, ptype_bool, ptype_bytes, ptype_uint8, ptype_string";

	return &reg_info;
}


int analyzer_ppp_chap_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_ppp_chap;
	memset(&analyzer_ppp_chap, 0, sizeof(struct analyzer_reg));
	analyzer_ppp_chap.name = "ppp_chap";
	analyzer_ppp_chap.api_ver = ANALYZER_API_VER;
	analyzer_ppp_chap.mod = mod;
	analyzer_ppp_chap.init = analyzer_ppp_chap_init;
	analyzer_ppp_chap.cleanup = analyzer_ppp_chap_cleanup;

	return analyzer_register(&analyzer_ppp_chap);

}

int analyzer_ppp_chap_mod_unregister() {

	int res = analyzer_unregister("ppp_chap");

	return res;
}

int analyzer_ppp_chap_init(struct analyzer *analyzer) {


	struct analyzer_ppp_chap_priv *priv = malloc(sizeof(struct analyzer_ppp_chap_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_ppp_chap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_ppp_chap_priv));
	analyzer->priv = priv;

	priv->evt_challenge_response = event_find("ppp_chap_challenge_response");
	priv->evt_success_failure = event_find("ppp_chap_success_failure");
	if (!priv->evt_challenge_response || !priv->evt_success_failure)
		goto err;


	static struct data_item_reg evt_mschapv2_data_items[ANALYZER_PPP_CHAP_MSCHAPV2_DATA_COUNT] = { { 0 } };

	evt_mschapv2_data_items[analyzer_ppp_chap_common_src].name = "src";
	evt_mschapv2_data_items[analyzer_ppp_chap_common_src].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_mschapv2_data_items[analyzer_ppp_chap_common_dst].name = "dst";
	evt_mschapv2_data_items[analyzer_ppp_chap_common_dst].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_mschapv2_data_items[analyzer_ppp_chap_common_identifier].name = "identifier";
	evt_mschapv2_data_items[analyzer_ppp_chap_common_identifier].value_type = ptype_get_type("uint8");

	evt_mschapv2_data_items[analyzer_ppp_chap_common_username].name = "username";
	evt_mschapv2_data_items[analyzer_ppp_chap_common_username].value_type = ptype_get_type("string");

	evt_mschapv2_data_items[analyzer_ppp_chap_common_success].name = "success";
	evt_mschapv2_data_items[analyzer_ppp_chap_common_success].value_type = ptype_get_type("bool");

	evt_mschapv2_data_items[analyzer_ppp_chap_mschapv2_auth_challenge].name = "auth_challenge";
	evt_mschapv2_data_items[analyzer_ppp_chap_mschapv2_auth_challenge].value_type = ptype_get_type("bytes");

	evt_mschapv2_data_items[analyzer_ppp_chap_mschapv2_response].name = "response";
	evt_mschapv2_data_items[analyzer_ppp_chap_mschapv2_response].value_type = ptype_get_type("bytes");

	evt_mschapv2_data_items[analyzer_ppp_chap_mschapv2_peer_challenge].name = "peer_challenge";
	evt_mschapv2_data_items[analyzer_ppp_chap_mschapv2_peer_challenge].value_type = ptype_get_type("bytes");

	static struct data_reg evt_mschapv2_data = {
		.items = evt_mschapv2_data_items,
		.data_count = ANALYZER_PPP_CHAP_MSCHAPV2_DATA_COUNT
	};

	static struct event_reg_info analyzer_ppp_chap_evt_mschapv2 = { 0 };
	analyzer_ppp_chap_evt_mschapv2.source_name = "analyzer_ppp_chap";
	analyzer_ppp_chap_evt_mschapv2.source_obj = analyzer;
	analyzer_ppp_chap_evt_mschapv2.name = "mschapv2_auth";
	analyzer_ppp_chap_evt_mschapv2.description = "MS-CHAPv2 authentication";
	analyzer_ppp_chap_evt_mschapv2.data_reg = &evt_mschapv2_data;
	analyzer_ppp_chap_evt_mschapv2.listeners_notify = analyzer_ppp_chap_event_listeners_notify;

	priv->evt_mschapv2 = event_register(&analyzer_ppp_chap_evt_mschapv2);
	if (!priv->evt_mschapv2)
		goto err;

	return POM_OK;

err:
	analyzer_ppp_chap_cleanup(analyzer);
	return POM_ERR;
}

int analyzer_ppp_chap_cleanup(struct analyzer *analyzer) {
	

	struct analyzer_ppp_chap_priv *priv = analyzer->priv;
	if (!priv)
		return POM_OK;

	int res = POM_OK;

	if (priv->evt_mschapv2)
		res += event_unregister(priv->evt_mschapv2);

	free(priv);

	return res;
}

int analyzer_ppp_chap_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_ppp_chap_priv *priv = analyzer->priv;

	if (has_listeners) {
		if (event_listener_register(priv->evt_challenge_response, analyzer, analyzer_ppp_chap_event_process_begin, NULL) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_success_failure, analyzer, analyzer_ppp_chap_event_process_begin, NULL) != POM_OK) {
			event_listener_unregister(priv->evt_challenge_response, analyzer);
			return POM_ERR;
		}

	} else {
		if (event_listener_unregister(priv->evt_challenge_response, analyzer) != POM_OK || event_listener_unregister(priv->evt_success_failure, analyzer) != POM_OK)
			return POM_ERR;
	}

	return POM_OK;

}


int analyzer_ppp_chap_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;

	struct analyzer_ppp_chap_priv *apriv = analyzer->priv;

	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce)
		return PROTO_ERR;

	conntrack_lock(s->ce);

	struct analyzer_ppp_chap_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);
	if (!cpriv) {
		cpriv = malloc(sizeof(struct analyzer_ppp_chap_ce_priv));
		if (!cpriv) {
			pom_oom(sizeof(struct analyzer_ppp_chap_ce_priv));
			goto err;
		}
		memset(cpriv, 0, sizeof(struct analyzer_ppp_chap_ce_priv));


		if (conntrack_add_priv(s->ce, analyzer, cpriv, analyzer_ppp_chap_ce_priv_cleanup) != POM_OK) {
			free(cpriv);
			goto err;
		}

	}

	struct event_reg *evt_reg = event_get_reg(evt);
	struct data *evt_data = event_get_data(evt);

	if (evt_reg == apriv->evt_challenge_response) {
		uint8_t code = *PTYPE_UINT8_GETVAL(evt_data[evt_ppp_chap_challenge_response_code].value);

		if (code == 1) {
			if (!cpriv->evt_challenge) {
				event_refcount_inc(evt);
				cpriv->evt_challenge = evt;
			}
		} else if (code == 2) {
			if (!cpriv->evt_response) {
				event_refcount_inc(evt);
				cpriv->evt_response = evt;
			}
		}


	} else {
		uint8_t code = *PTYPE_UINT8_GETVAL(evt_data[evt_ppp_chap_success_failure_code].value);
		
		if (code == 3) {
			if (!cpriv->evt_result) {
				event_refcount_inc(evt);
				cpriv->evt_result = evt;
			}
		} else if (code == 4) {
			if (!cpriv->evt_result) {
				event_refcount_inc(evt);
				cpriv->evt_result = evt;
			}
		}
	}

	int res = POM_OK;

	if (cpriv->evt_challenge && cpriv->evt_response && cpriv->evt_result)
		res = analyzer_ppp_chap_finalize(apriv, cpriv);

	conntrack_unlock(s->ce);

	return res;

err:
	conntrack_unlock(s->ce);
	return POM_ERR;

}

int analyzer_ppp_chap_finalize(struct analyzer_ppp_chap_priv *apriv, struct analyzer_ppp_chap_ce_priv *cpriv) {

	if (!cpriv->evt_challenge || !cpriv->evt_response)
		return POM_OK;

	struct event *evt = NULL;
	struct data *evt_data = NULL;

	struct data *evt_chl_data = event_get_data(cpriv->evt_challenge);
	struct data *evt_rsp_data = event_get_data(cpriv->evt_response);

	enum analyzer_ppp_chap_auth_type auth_type = analyzer_ppp_chap_auth_unknown;

	if (!data_is_set(evt_rsp_data[evt_ppp_chap_challenge_response_value]))
		return POM_OK;

	size_t len = PTYPE_BYTES_GETLEN(evt_rsp_data[evt_ppp_chap_challenge_response_value].value);
	unsigned char *value = PTYPE_BYTES_GETVAL(evt_rsp_data[evt_ppp_chap_challenge_response_value].value);
	if (len == 16) {
		// TODO : CHAP-MD5
		return POM_OK;
	} else if (len == 49 && !value[16] && !value[17] && !value[18] && !value[19] &&
		!value[20] && !value[21] && !value[22] && !value[23] &&
		!value[48]) {

		evt = event_alloc(apriv->evt_mschapv2);
		if (!evt)
			return POM_ERR;

		evt_data = event_get_data(evt);
		PTYPE_BYTES_SETLEN(evt_data[analyzer_ppp_chap_mschapv2_response].value, 24);
		PTYPE_BYTES_SETVAL(evt_data[analyzer_ppp_chap_mschapv2_response].value, value + 24);
		data_set(evt_data[analyzer_ppp_chap_mschapv2_response]);
		PTYPE_BYTES_SETLEN(evt_data[analyzer_ppp_chap_mschapv2_peer_challenge].value, 16);
		PTYPE_BYTES_SETVAL(evt_data[analyzer_ppp_chap_mschapv2_peer_challenge].value, value);
		data_set(evt_data[analyzer_ppp_chap_mschapv2_peer_challenge]);

		auth_type = analyzer_ppp_chap_auth_mschapv2;
	} else {
		// Unknown auth mechanism
		return POM_OK;
	}


	if (ptype_copy(evt_data[analyzer_ppp_chap_common_identifier].value, evt_chl_data[evt_ppp_chap_challenge_response_identifier].value) != POM_OK)
		return POM_ERR;
	data_set(evt_data[analyzer_ppp_chap_common_identifier]);

	if (!data_is_set(evt_rsp_data[evt_ppp_chap_challenge_response_name]))
		return POM_OK;

	if (ptype_copy(evt_data[analyzer_ppp_chap_common_username].value, evt_rsp_data[evt_ppp_chap_challenge_response_name].value) != POM_OK)
		return POM_ERR;
	data_set(evt_data[analyzer_ppp_chap_common_username]);

	switch (auth_type) {
		case analyzer_ppp_chap_auth_mschapv2:
			if (!data_is_set(evt_chl_data[evt_ppp_chap_challenge_response_value]))
				return POM_OK;
			if (ptype_copy(evt_data[analyzer_ppp_chap_mschapv2_auth_challenge].value, evt_chl_data[evt_ppp_chap_challenge_response_value].value) != POM_OK)
				return POM_ERR;
			data_set(evt_data[analyzer_ppp_chap_mschapv2_auth_challenge]);
			break;
		default:
			return POM_OK;
	}

	if (cpriv->evt_result) {
		struct data *evt_res_data = event_get_data(cpriv->evt_result);
		uint8_t code = *PTYPE_UINT8_GETVAL(evt_res_data[evt_ppp_chap_success_failure_code].value);
		
		if (code == 3) {
			PTYPE_BOOL_SETVAL(evt_data[analyzer_ppp_chap_common_success].value, 1);
		} else {
			PTYPE_BOOL_SETVAL(evt_data[analyzer_ppp_chap_common_success].value, 0);
		}
		data_set(evt_data[analyzer_ppp_chap_common_success]);

		event_refcount_dec(cpriv->evt_result);
		cpriv->evt_result = NULL;
	}

	ptime ts = event_get_timestamp(cpriv->evt_response);

	event_refcount_dec(cpriv->evt_challenge);
	cpriv->evt_challenge = NULL;
	event_refcount_dec(cpriv->evt_response);
	cpriv->evt_response = NULL;

	return event_process(evt, NULL, 0, ts);
}


int analyzer_ppp_chap_ce_priv_cleanup(void *obj, void *priv) {

	struct analyzer *analyzer = obj;

	struct analyzer_ppp_chap_ce_priv *cpriv = priv;

	int res = analyzer_ppp_chap_finalize(analyzer->priv, cpriv);
	
	if (cpriv->evt_challenge)
		event_refcount_dec(cpriv->evt_challenge);
	if (cpriv->evt_response)
		event_refcount_dec(cpriv->evt_response);
	if (cpriv->evt_result)
		event_refcount_dec(cpriv->evt_result);


	free(priv);

	return res;
}
