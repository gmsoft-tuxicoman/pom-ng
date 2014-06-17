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

#include "analyzer_sip.h"


#if 0
#define debug_sip(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_sip(x ...)
#endif

struct mod_reg_info* analyzer_sip_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_sip_mod_register;
	reg_info.unregister_func = analyzer_sip_mod_unregister;
	reg_info.dependencies = "proto_sip, ptype_string";

	return &reg_info;
}

static int analyzer_sip_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_sip;
	memset(&analyzer_sip, 0, sizeof(struct analyzer_reg));
	analyzer_sip.name = "sip";
	analyzer_sip.mod = mod;
	analyzer_sip.init = analyzer_sip_init;

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

		priv->sip_packet_listener = proto_packet_listener_register(priv->proto_sip, PROTO_PACKET_LISTENER_PLOAD_ONLY, analyzer, analyzer_sip_proto_packet_process, NULL);
		if (!priv->sip_packet_listener) {
			event_listener_unregister(priv->evt_sip_req, analyzer);
			event_listener_unregister(priv->evt_sip_rsp, analyzer);
			return POM_ERR;
		}
	} else {
		int res = POM_OK;
		res += event_listener_unregister(priv->evt_sip_req, analyzer);
		res += event_listener_unregister(priv->evt_sip_rsp, analyzer);
		res += proto_packet_listener_unregister(priv->sip_packet_listener);
		if (res != POM_OK)
			return POM_ERR;
	}

	return POM_OK;
}

static int analyzer_sip_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	return POM_OK;

}

static int analyzer_sip_event_process_end(struct event *evt, void *obj) {

	return POM_OK;
}

int analyzer_sip_proto_packet_process(void *object, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	return POM_OK;
}
