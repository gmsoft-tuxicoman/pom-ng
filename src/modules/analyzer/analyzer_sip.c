/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/proto_sip.h>
#include <pom-ng/ptype_string.h>

#include "analyzer_sip.h"


#if 0
#define debug_sip(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_sip(x ...)
#endif

struct analyzer_sip_call *analyzer_sip_calls = NULL;

struct mod_reg_info* analyzer_sip_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_sip_mod_register;
	reg_info.unregister_func = analyzer_sip_mod_unregister;
	reg_info.dependencies = "analyzer_sdp, proto_sip, ptype_string";

	return &reg_info;
}

static int analyzer_sip_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_sip;
	memset(&analyzer_sip, 0, sizeof(struct analyzer_reg));
	analyzer_sip.name = "sip";
	analyzer_sip.mod = mod;
	analyzer_sip.init = analyzer_sip_init;
	analyzer_sip.cleanup = analyzer_sip_cleanup;

	return analyzer_register(&analyzer_sip);

}

static int analyzer_sip_mod_unregister() {

	return analyzer_unregister("sip");
}

static int analyzer_sip_init(struct analyzer *analyzer) {

	struct analyzer_sip_priv *priv = malloc(sizeof(struct analyzer_sip_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_sip_priv));
		return POM_ERR;
	}

	memset(priv, 0, sizeof(struct analyzer_sip_priv));
	analyzer->priv = priv;

	priv->evt_sip_req = event_find("sip_req");
	priv->evt_sip_rsp = event_find("sip_rsp");
	if (!priv->evt_sip_req || !priv->evt_sip_rsp)
		goto err;


	static struct data_item_reg evt_sip_call_data_items[ANALYZER_SIP_CALL_DATA_COUNT] = { { 0 } };

	evt_sip_call_data_items[analyzer_sip_call_from_display].name = "from_display";
	evt_sip_call_data_items[analyzer_sip_call_from_display].value_type = ptype_get_type("string");

	evt_sip_call_data_items[analyzer_sip_call_to_display].name = "to_display";
	evt_sip_call_data_items[analyzer_sip_call_to_display].value_type = ptype_get_type("string");

	evt_sip_call_data_items[analyzer_sip_call_id].name = "call_id";
	evt_sip_call_data_items[analyzer_sip_call_id].value_type = ptype_get_type("string");

	static struct data_reg evt_sip_call_data = {
		.items = evt_sip_call_data_items,
		.data_count = ANALYZER_SIP_CALL_DATA_COUNT
	};

	static struct event_reg_info analyzer_sip_evt_call = { 0 };
	analyzer_sip_evt_call.source_name = "analyzer_sip";
	analyzer_sip_evt_call.source_obj = analyzer;
	analyzer_sip_evt_call.name = "sip_call";
	analyzer_sip_evt_call.description = "Complete SIP call";
	analyzer_sip_evt_call.data_reg = &evt_sip_call_data;
	analyzer_sip_evt_call.flags = EVENT_REG_FLAG_PAYLOAD;
	analyzer_sip_evt_call.listeners_notify = analyzer_sip_event_listeners_notify;
//	analyzer_sip_evt_call.cleanup = analyzer_sip_call_event_cleanup;

	priv->evt_sip_call = event_register(&analyzer_sip_evt_call);
	if (!priv->evt_sip_call)
		goto err;

	priv->proto_sip = proto_get("sip");
	if (!priv->proto_sip)
		goto err;

	return POM_OK;
err:
	analyzer_sip_cleanup(analyzer);
	return POM_ERR;
}

static int analyzer_sip_cleanup(struct analyzer *analyzer) {

	struct analyzer_sip_priv *priv = analyzer->priv;

	if (priv->listening) {
		pload_listen_stop(analyzer, ANALYZER_SIP_SDP_PLOAD_TYPE);
		event_listener_unregister(priv->evt_sip_req, analyzer);
		event_listener_unregister(priv->evt_sip_rsp, analyzer);
	}


	struct analyzer_sip_call *cur_call, *tmp;
	HASH_ITER(hh, analyzer_sip_calls, cur_call, tmp) {
		HASH_DEL(analyzer_sip_calls, cur_call);
		analyzer_sip_call_cleanup(analyzer, cur_call);
	}

	if (priv->evt_sip_call)
		event_unregister(priv->evt_sip_call);

	free(priv);

	return POM_OK;

}

static int analyzer_sip_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {


	struct analyzer *analyzer = obj;
	struct analyzer_sip_priv *priv = analyzer->priv;

	if (has_listeners) {
		if (event_listener_register(priv->evt_sip_req, analyzer, analyzer_sip_event_process_begin, analyzer_sip_event_process_end) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_sip_rsp, analyzer, analyzer_sip_event_process_begin, analyzer_sip_event_process_end) != POM_OK) {
			event_listener_unregister(priv->evt_sip_req, analyzer);
			return POM_ERR;
		}

		if (pload_listen_start(obj, ANALYZER_SIP_SDP_PLOAD_TYPE, NULL, analyzer_sip_sdp_open, analyzer_sip_sdp_write, analyzer_sip_sdp_close) != POM_OK) {
			event_listener_unregister(priv->evt_sip_req, analyzer);
			event_listener_unregister(priv->evt_sip_rsp, analyzer);
			return POM_ERR;
		}
		priv->listening = 1;
	} else {
		int res = POM_OK;
		res += pload_listen_stop(obj, ANALYZER_SIP_SDP_PLOAD_TYPE);
		res += event_listener_unregister(priv->evt_sip_req, analyzer);
		res += event_listener_unregister(priv->evt_sip_rsp, analyzer);
		if (res != POM_OK)
			return POM_ERR;
		priv->listening = 0;
	}

	return POM_OK;
}

static struct analyzer_sip_call* analyzer_sip_event_get_call(struct analyzer *a, struct event *evt) {

	struct data *evt_data = event_get_data(evt);
	if (!data_is_set(evt_data[proto_sip_msg_call_id]))
		return NULL;
	char *call_id = PTYPE_STRING_GETVAL(evt_data[proto_sip_msg_call_id].value);

	struct analyzer_sip_call *call = NULL;
	HASH_FIND_STR(analyzer_sip_calls, call_id, call);

	if (call)
		return call;

	struct conntrack_entry *ce = event_get_conntrack(evt);
	if (!ce)
		return NULL;

	call = malloc(sizeof(struct analyzer_sip_call));
	if (!call) {
		pom_oom(sizeof(struct analyzer_sip_call));
		return NULL;
	}
	memset(call, 0, sizeof(struct analyzer_sip_call));

	call->call_id = strdup(call_id);
	if (!call->call_id) {
		free(call);
		pom_oom(strlen(call_id) + 1);
		return NULL;
	}

	// The conntrack is already locked while processing the event
	struct conntrack_session *sess = conntrack_session_get(ce);
	if (!sess) {
		free(call);
		return NULL;
	}

	call->sess = sess;

	if (conntrack_session_add_priv(sess, a, call, analyzer_sip_call_cleanup) != POM_OK) {
		conntrack_session_unlock(sess);
		free(call);
		return NULL;
	}

	conntrack_session_unlock(sess);

	HASH_ADD_STR(analyzer_sip_calls, call_id, call);


	return call;
}

static int analyzer_sip_call_cleanup(void *obj, void *priv) {

	struct analyzer_sip_call *call = priv;

	HASH_DEL(analyzer_sip_calls, call);

	if (call->call_id)
		free(call->call_id);
	free(call);

	return POM_OK;
}

static int analyzer_sip_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer_sip_call *call = analyzer_sip_event_get_call(obj, evt);
	if (!call)
		return POM_OK;

	// TODO record some info about the call

	return POM_OK;

}

static int analyzer_sip_event_process_end(struct event *evt, void *obj) {

	return POM_OK;
}


static int analyzer_sip_sdp_open(void *obj, void **priv, struct pload *pload) {

	struct analyzer *analyzer = obj;
	struct analyzer_sip_priv *apriv = analyzer->priv;

	struct event *evt = pload_get_related_event(pload);
	if (!evt)
		return PLOAD_OPEN_STOP;

	struct event_reg *evt_reg = event_get_reg(evt);
	if (evt_reg != apriv->evt_sip_req && evt_reg != apriv->evt_sip_rsp)
		return PLOAD_OPEN_STOP;

	struct conntrack_entry *ce = event_get_conntrack(evt);
	if (!ce)
		return PLOAD_OPEN_STOP;

	struct conntrack_session *sess = conntrack_session_get(ce);
	struct analyzer_sip_call *call = conntrack_session_get_priv(sess, obj);
	conntrack_session_unlock(sess);
	if (!call) // Call not found or the current conntrack session
		return PLOAD_OPEN_ERR;

	struct analyzer_sip_sdp_priv *sdp_priv = malloc(sizeof(struct analyzer_sip_sdp_priv));
	if (!sdp_priv) {
		pom_oom(sizeof(struct analyzer_sip_sdp_priv));
		return PLOAD_OPEN_ERR;
	}
	memset(sdp_priv, 0, sizeof(struct analyzer_sip_sdp_priv));

	sdp_priv->sdp = telephony_sdp_alloc();

	if (!sdp_priv->sdp) {
		free(sdp_priv);
		return PLOAD_OPEN_ERR;
	}

	sdp_priv->call = call;
	sdp_priv->ts = event_get_timestamp(evt);

	*priv = sdp_priv;

	return PLOAD_OPEN_CONTINUE;
}

static int analyzer_sip_sdp_write(void *obj, void *priv, void *data, size_t len) {

	struct analyzer_sip_sdp_priv *p = priv;
	return telephony_sdp_parse(p->sdp, data, len);
}


static int analyzer_sip_sdp_close(void *obj, void *priv) {

	struct analyzer_sip_sdp_priv *p = priv;

	if (telephony_sdp_parse_end(p->sdp) != POM_OK)
		return POM_ERR;

	if (telephony_sdp_add_expectations(p->sdp, p->call->sess, p->ts) != POM_OK)
		return POM_ERR;

	telephony_sdp_cleanup(p->sdp);

	free(p);

	return POM_OK;
}
