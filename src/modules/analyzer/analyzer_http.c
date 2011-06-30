/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#include <sys/time.h>
#include <stdio.h>
#include "analyzer_http.h"
#include <pom-ng/proto_http.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_string.h>

struct mod_reg_info* analyzer_http_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_http_mod_register;
	reg_info.unregister_func = analyzer_http_mod_unregister;

	return &reg_info;
}


static int analyzer_http_mod_register(struct mod_reg *mod) {

	static struct analyzer_data_reg evt_request_data[ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT];
	memset(&evt_request_data, 0, sizeof(struct analyzer_data_reg) * ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT);
	evt_request_data[analyzer_http_request_server_name].name = "server_name";
	evt_request_data[analyzer_http_request_server_addr].name = "server_addr";
	evt_request_data[analyzer_http_request_server_port].name = "server_port";
	evt_request_data[analyzer_http_request_client_addr].name = "client_addr";
	evt_request_data[analyzer_http_request_client_port].name = "client_port";
	evt_request_data[analyzer_http_request_request_proto].name = "request_proto";
	evt_request_data[analyzer_http_request_request_method].name = "request_method";
	evt_request_data[analyzer_http_request_first_line].name = "first_line";
	evt_request_data[analyzer_http_request_url].name = "url";
	evt_request_data[analyzer_http_request_query_time].name = "query_time";
	evt_request_data[analyzer_http_request_response_time].name = "response_time";
	evt_request_data[analyzer_http_request_username].name = "username";
	evt_request_data[analyzer_http_request_password].name = "password";
	evt_request_data[analyzer_http_request_status].name = "status";
	evt_request_data[analyzer_http_request_query_headers].name = "query_headers";
	evt_request_data[analyzer_http_request_response_headers].name = "response_headers";

	static struct analyzer_event_reg analyzer_http_events[ANALYZER_HTTP_EVT_COUNT + 1];
	memset(&analyzer_http_events, 0, sizeof(struct proto_event_reg) * (ANALYZER_HTTP_EVT_COUNT + 1));
	analyzer_http_events[analyzer_http_evt_request].name = "http_request";
	analyzer_http_events[analyzer_http_evt_request].data = evt_request_data;
	analyzer_http_events[analyzer_http_evt_request].data_count = ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT;
	analyzer_http_events[analyzer_http_evt_request].listeners_notify = analyzer_http_event_listeners_notify;

	static struct analyzer_reg_info analyzer_http;
	memset(&analyzer_http, 0, sizeof(struct analyzer_reg_info));
	analyzer_http.name = "http";
	analyzer_http.api_ver = ANALYZER_API_VER;
	analyzer_http.mod = mod;
	analyzer_http.events = analyzer_http_events;
	analyzer_http.init = analyzer_http_init;
	analyzer_http.cleanup = analyzer_http_cleanup;

	return analyzer_register(&analyzer_http);

}

static int analyzer_http_mod_unregister() {

	int res = analyzer_unregister("http");

	return res;
}


static int analyzer_http_init(struct analyzer_reg *analyzer) {

	struct analyzer_http_priv *priv = malloc(sizeof(struct analyzer_http_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_http_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_http_priv));

	priv->proto_http = proto_add_dependency("http");
	if (!priv->proto_http) {
		free(priv);
		return POM_ERR;
	}
	analyzer->priv = priv;

	return POM_OK;

}

static int analyzer_http_cleanup(struct analyzer_reg *analyzer) {

	struct analyzer_http_priv *priv = analyzer->priv;
	
	proto_remove_dependency(priv->proto_http);

	free(priv);

	return POM_OK;
}

static int analyzer_http_ce_priv_cleanup(void *obj, void *priv) {

	struct analyzer_http_ce_priv *p = priv;
	analyzer_http_event_reset(&p->evt);
	free(p->evt.data);
	free(p);

	return POM_OK;
}

static int analyzer_http_event_listeners_notify(struct analyzer_reg *analyzer, struct analyzer_event_reg *event, int has_listeners) {

	struct analyzer_http_priv *priv = analyzer->priv;

	if (has_listeners) {
		static struct proto_event_analyzer_reg analyzer_reg;
		analyzer_reg.analyzer = analyzer;
		analyzer_reg.process = analyzer_http_proto_event_process;
		analyzer_reg.expire = analyzer_http_proto_event_expire;
		return proto_event_analyzer_register(priv->proto_http->proto, &analyzer_reg);

	} else {
		return proto_event_analyzer_unregister(priv->proto_http->proto, analyzer);
	}

	return POM_OK;
}

static int analyzer_http_event_reset(struct analyzer_event *evt) {

	// Free possibly allocated stuff
	struct analyzer_data *data = evt->data;
	if (data[analyzer_http_request_server_addr].value)
		ptype_cleanup(data[analyzer_http_request_server_addr].value);
	if (data[analyzer_http_request_server_port].value)
		ptype_cleanup(data[analyzer_http_request_server_port].value);
	if (data[analyzer_http_request_client_addr].value)
		ptype_cleanup(data[analyzer_http_request_client_addr].value);
	if (data[analyzer_http_request_client_port].value)
		ptype_cleanup(data[analyzer_http_request_client_port].value);

	memset(data, 0, sizeof(struct analyzer_data) * (ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT + 1));

	return POM_OK;
}

static int analyzer_http_proto_event_process(struct analyzer_reg *analyzer, struct proto_event *evt, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce)
		return POM_ERR;

	struct analyzer_http_ce_priv *priv = conntrack_get_priv(s->ce, analyzer);
	if (!priv) {
		priv = malloc(sizeof(struct analyzer_http_ce_priv));
		if (!priv) {
			pom_oom(sizeof(struct analyzer_http_ce_priv));
			return POM_ERR;
		}
		memset(priv, 0, sizeof(struct analyzer_http_ce_priv));

		priv->evt.info = &analyzer->info->events[analyzer_http_evt_request];

		struct analyzer_data *data = malloc(sizeof(struct analyzer_data) * (ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT + 1));
		if (!data) {
			free(priv);
			pom_oom(sizeof(struct analyzer_data) * (ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT + 1));
			return POM_ERR;
		}
		memset(data, 0, sizeof(struct analyzer_data) * (ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT + 1));
		priv->evt.data = data;

		if (conntrack_add_priv(s->ce, analyzer, priv, analyzer_http_ce_priv_cleanup) != POM_OK)
			return POM_ERR;

	}

	// Do the mapping, no flag checking or other, we just know how :)

	struct proto_event_data *src_data = evt->data;
	struct analyzer_data *dst_data = priv->evt.data;

	if (evt->evt_reg->id == proto_http_evt_query) {

		priv->flags |= ANALYZER_HTTP_GOT_QUERY_EVT;

		// Copy data contained into the query event
		if (src_data[proto_http_query_first_line].set)
			dst_data[analyzer_http_request_first_line].value = src_data[proto_http_query_first_line].value;
		if (src_data[proto_http_query_proto].set)
			dst_data[analyzer_http_request_request_proto].value = src_data[proto_http_query_proto].value;
		if (src_data[proto_http_query_method].set)
			dst_data[analyzer_http_request_request_method].value = src_data[proto_http_query_method].value;
		if (src_data[proto_http_query_url].set)
			dst_data[analyzer_http_request_url].value = src_data[proto_http_query_url].value;
		if (src_data[proto_http_query_start_time].set)
			dst_data[analyzer_http_request_query_time].value = src_data[proto_http_query_start_time].value;

		dst_data[analyzer_http_request_query_headers].items = src_data[proto_http_query_headers].items;

		analyzer_data_item_t *headers = src_data[proto_http_query_headers].items;
		while (headers) {
			if (!dst_data[analyzer_http_request_server_name].value && !strcasecmp(headers->key, "Host"))
				dst_data[analyzer_http_request_server_name].value = headers->value;
	
			// TODO username and password
			headers = headers->next;
		}


	} else if (evt->evt_reg->id == proto_http_evt_response) {

		priv->flags |= ANALYZER_HTTP_GOT_RESPONSE_EVT;

		if (src_data[proto_http_response_status].set)
			dst_data[analyzer_http_request_status].value = src_data[proto_http_response_status].value;
		if (!dst_data[analyzer_http_request_request_proto].value && src_data[proto_http_response_proto].set)
			dst_data[analyzer_http_request_request_proto].value = src_data[proto_http_response_proto].value;
		if (src_data[proto_http_response_start_time].set)
			dst_data[analyzer_http_request_response_time].value = src_data[proto_http_response_start_time].value;

		dst_data[analyzer_http_request_response_headers].items = src_data[proto_http_response_headers].items;


	} else {
		pomlog(POMLOG_ERR "Unknown event ID %u", evt->evt_reg->id);
		return POM_ERR;
	}


	// Get client/server ports if not fetched yet
	if (stack_index > 1 && (!dst_data[analyzer_http_request_client_port].value || !dst_data[analyzer_http_request_server_port].value)) {
		struct proto_process_stack *l4_stack = &stack[stack_index - 1];
		struct ptype *sport = NULL, *dport = NULL;
		unsigned int i;
		for (i = 0; !sport || !dport; i++) {
			char *name = l4_stack->proto->info->pkt_fields[i].name;
			if (!name)
				break;
			if (!sport && !strcmp(name, "sport"))
				sport = l4_stack->pkt_info->fields_value[i];
			else if (!dport && !strcmp(name, "dport"))
				dport = l4_stack->pkt_info->fields_value[i];
		}

		if (evt->evt_reg->id == proto_http_evt_query) {
			if (sport && !dst_data[analyzer_http_request_client_port].value)
				dst_data[analyzer_http_request_client_port].value = ptype_alloc_from(sport);
			if (dport && !dst_data[analyzer_http_request_server_port].value)
				dst_data[analyzer_http_request_server_port].value = ptype_alloc_from(dport);
		} else {
			if (sport && !dst_data[analyzer_http_request_server_port].value)
				dst_data[analyzer_http_request_server_port].value = ptype_alloc_from(sport);
			if (dport && !dst_data[analyzer_http_request_client_port].value)
				dst_data[analyzer_http_request_client_port].value = ptype_alloc_from(dport);
		}
	}

	if (stack_index > 2 && (!dst_data[analyzer_http_request_client_addr].value || !dst_data[analyzer_http_request_server_addr].value)) {
		struct ptype *src = NULL, *dst = NULL;
		struct proto_process_stack *l3_stack = &stack[stack_index - 2];
		unsigned int i;
		for (i = 0; !src || !dst ; i++) {
			char *name = l3_stack->proto->info->pkt_fields[i].name;
			if (!name)
				break;

			if (!src && !strcmp(name, "src"))
				src = l3_stack->pkt_info->fields_value[i];
			else if (!dst && !strcmp(name, "dst"))
				dst = l3_stack->pkt_info->fields_value[i];
		}

		if (evt->evt_reg->id == proto_http_evt_query) {
			if (src && !dst_data[analyzer_http_request_client_addr].value)
				dst_data[analyzer_http_request_client_addr].value = ptype_alloc_from(src);
			if (dst && !dst_data[analyzer_http_request_server_addr].value)
				dst_data[analyzer_http_request_server_addr].value = ptype_alloc_from(dst);
		} else {
			if (src && !dst_data[analyzer_http_request_server_addr].value)
				dst_data[analyzer_http_request_server_addr].value = ptype_alloc_from(src);
			if (dst && !dst_data[analyzer_http_request_client_addr].value)
				dst_data[analyzer_http_request_client_addr].value = ptype_alloc_from(dst);
		}
	}

	if ((priv->flags & (ANALYZER_HTTP_GOT_QUERY_EVT | ANALYZER_HTTP_GOT_RESPONSE_EVT)) == (ANALYZER_HTTP_GOT_QUERY_EVT | ANALYZER_HTTP_GOT_RESPONSE_EVT)) {
		// We got both events, process our composite event
		int result = analyzer_event_process(&priv->evt);
		priv->flags &= ~(ANALYZER_HTTP_GOT_QUERY_EVT | ANALYZER_HTTP_GOT_RESPONSE_EVT);
		analyzer_http_event_reset(&priv->evt);
		return result;
	}

	return POM_OK;
}

static int analyzer_http_proto_event_expire(struct analyzer_reg *analyzer, struct proto_event *evt, struct conntrack_entry *ce) {


	struct analyzer_http_ce_priv *priv = conntrack_get_priv(ce, analyzer);
	if (!priv)
		return POM_OK;

	if (priv->flags & (ANALYZER_HTTP_GOT_QUERY_EVT | ANALYZER_HTTP_GOT_RESPONSE_EVT)) {
		// We either got a request or a query. Process
		int result = analyzer_event_process(&priv->evt);
		priv->flags &= ~(ANALYZER_HTTP_GOT_QUERY_EVT | ANALYZER_HTTP_GOT_RESPONSE_EVT);
		analyzer_http_event_reset(&priv->evt);
		return result;
	}


	return POM_OK;
}
