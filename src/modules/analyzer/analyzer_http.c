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
#include "analyzer_http_post.h"
#include <pom-ng/proto_http.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_string.h>

struct mod_reg_info* analyzer_http_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_http_mod_register;
	reg_info.unregister_func = analyzer_http_mod_unregister;
	reg_info.dependencies = "proto_http, ptype_uint16, ptype_string";

	return &reg_info;
}


int analyzer_http_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_http;
	memset(&analyzer_http, 0, sizeof(struct analyzer_reg));
	analyzer_http.name = "http";
	analyzer_http.api_ver = ANALYZER_API_VER;
	analyzer_http.mod = mod;
	analyzer_http.init = analyzer_http_init;
	analyzer_http.cleanup = analyzer_http_cleanup;

	return analyzer_register(&analyzer_http);

}

int analyzer_http_mod_unregister() {

	int res = analyzer_unregister("http");

	return res;
}


int analyzer_http_init(struct analyzer *analyzer) {

	struct analyzer_http_priv *priv = malloc(sizeof(struct analyzer_http_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_http_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_http_priv));
	analyzer->priv = priv;

	priv->evt_query = event_find("http_query");
	priv->evt_response = event_find("http_response");
	if (!priv->evt_query || !priv->evt_response)
		goto err;

	priv->ptype_string = ptype_alloc("string");
	if (!priv->ptype_string)
		goto err;

	static struct event_data_reg evt_request_data[ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT];
	memset(&evt_request_data, 0, sizeof(struct event_data_reg) * ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT);

	evt_request_data[analyzer_http_request_server_name].name = "server_name";
	evt_request_data[analyzer_http_request_server_name].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_server_name].value_template = priv->ptype_string;

	evt_request_data[analyzer_http_request_server_addr].name = "server_addr";
	evt_request_data[analyzer_http_request_server_addr].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_server_addr].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_server_port].name = "server_port";
	evt_request_data[analyzer_http_request_server_port].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_server_port].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_client_addr].name = "client_addr";
	evt_request_data[analyzer_http_request_client_addr].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_client_addr].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_client_port].name = "client_port";
	evt_request_data[analyzer_http_request_client_port].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_client_port].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_request_proto].name = "request_proto";
	evt_request_data[analyzer_http_request_request_proto].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_request_proto].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_request_method].name = "request_method";
	evt_request_data[analyzer_http_request_request_method].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_request_method].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_first_line].name = "first_line";
	evt_request_data[analyzer_http_request_first_line].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_first_line].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_url].name = "url";
	evt_request_data[analyzer_http_request_url].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_url].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_query_time].name = "query_time";
	evt_request_data[analyzer_http_request_query_time].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_query_time].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_response_time].name = "response_time";
	evt_request_data[analyzer_http_request_response_time].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_response_time].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_username].name = "username";
	evt_request_data[analyzer_http_request_username].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_username].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_password].name = "password";
	evt_request_data[analyzer_http_request_password].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_password].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_status].name = "status";
	evt_request_data[analyzer_http_request_status].flags = EVENT_DATA_REG_FLAG_NO_ALLOC;
	evt_request_data[analyzer_http_request_status].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_query_headers].name = "query_headers";
	evt_request_data[analyzer_http_request_query_headers].flags = EVENT_DATA_REG_FLAG_LIST;
	evt_request_data[analyzer_http_request_query_headers].value_template = priv->ptype_string;

	evt_request_data[analyzer_http_request_response_headers].name = "response_headers";
	evt_request_data[analyzer_http_request_response_headers].flags = ANALYZER_DATA_FLAG_LIST;
	evt_request_data[analyzer_http_request_response_headers].value_template = priv->ptype_string;
	
	evt_request_data[analyzer_http_request_post_data].name = "post_data";
	evt_request_data[analyzer_http_request_post_data].flags = EVENT_DATA_REG_FLAG_LIST;
	evt_request_data[analyzer_http_request_post_data].value_template = priv->ptype_string;


	static struct event_reg_info analyzer_http_evt_request;
	memset(&analyzer_http_evt_request, 0, sizeof(struct event_reg_info));
	analyzer_http_evt_request.source_name = "analyzer_http";
	analyzer_http_evt_request.source_obj = analyzer;
	analyzer_http_evt_request.name = "http_request";
	analyzer_http_evt_request.description = "HTTP request (compound event of http_query and http_response)";
	analyzer_http_evt_request.data_reg = evt_request_data;
	analyzer_http_evt_request.data_count = ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT;
	analyzer_http_evt_request.listeners_notify = analyzer_http_event_listeners_notify;
	analyzer_http_evt_request.cleanup = analyzer_http_request_event_cleanup;

	priv->evt_request = event_register(&analyzer_http_evt_request);
	if (!priv->evt_request)
		goto err;

	priv->proto_http = proto_add_dependency("http");
	if (!priv->proto_http)
		goto err;

	return analyzer_http_post_init(analyzer);

err:
	analyzer_http_cleanup(analyzer);
	return POM_ERR;


}

int analyzer_http_cleanup(struct analyzer *analyzer) {

	struct analyzer_http_priv *priv = analyzer->priv;
	proto_remove_dependency(priv->proto_http);

	if (priv->ptype_string)
		ptype_cleanup(priv->ptype_string);

	if (priv->evt_request)
		event_unregister(priv->evt_request);

	free(priv);

	return POM_OK;
}

int analyzer_http_ce_priv_cleanup(void *obj, void *priv) {

	struct analyzer_http_ce_priv *cpriv = priv;

	int res = POM_OK;
	if (cpriv->evt)
		res = analyzer_http_event_finalize_process(cpriv);

	free(priv);
	return res;
}

int analyzer_http_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_http_priv *priv = analyzer->priv;

	if (has_listeners) {
		static struct event_listener analyzer_reg;
		memset(&analyzer_reg, 0, sizeof(struct event_listener));
		analyzer_reg.obj = analyzer;
		analyzer_reg.process_begin = analyzer_http_event_process_begin;
		analyzer_reg.process_end = analyzer_http_event_process_end;
		if (event_listener_register(priv->evt_query, &analyzer_reg) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_response, &analyzer_reg) != POM_OK) {
			event_listener_unregister(priv->evt_query, analyzer);
			return POM_ERR;
		}

		priv->http_packet_listener = proto_packet_listener_register(priv->proto_http->proto, PROTO_PACKET_LISTENER_PLOAD_ONLY, analyzer, analyzer_http_proto_packet_process);
		if (!priv->http_packet_listener) {
			event_listener_unregister(priv->evt_query, analyzer);
			event_listener_unregister(priv->evt_response, analyzer);
			return POM_ERR;
		}

	} else {
		if (event_listener_unregister(priv->evt_query, analyzer) != POM_OK || event_listener_unregister(priv->evt_response, analyzer) != POM_OK)
			return POM_ERR;
		if (proto_packet_listener_unregister(priv->http_packet_listener) != POM_OK)
			return POM_ERR;
	}

	return POM_OK;
}

int analyzer_http_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct analyzer_http_priv *apriv = analyzer->priv;

	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce)
		return POM_ERR;

	struct analyzer_http_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);
	if (!cpriv) {
		cpriv = malloc(sizeof(struct analyzer_http_ce_priv));
		if (!cpriv) {
			pom_oom(sizeof(struct analyzer_http_ce_priv));
			return POM_ERR;
		}
		memset(cpriv, 0, sizeof(struct analyzer_http_ce_priv));

		if (conntrack_add_priv(s->ce, analyzer, cpriv, analyzer_http_ce_priv_cleanup) != POM_OK) {
			free(cpriv);
			return POM_ERR;
		}

	}

	if (!cpriv->evt) {
		cpriv->evt = event_alloc(apriv->evt_request);
		
		if (!cpriv->evt)
			return POM_ERR;
	}

	struct analyzer_http_request_event_priv *epriv = cpriv->evt->priv;

	if (!epriv) {
		epriv = malloc(sizeof(struct analyzer_http_request_event_priv));
		if (!epriv) {
			event_cleanup(cpriv->evt);
			cpriv->evt = NULL;
			pom_oom(sizeof(struct analyzer_http_request_event_priv));
			return POM_ERR;
		}
		memset(epriv, 0, sizeof(struct analyzer_http_request_event_priv));
		cpriv->evt->priv = epriv;
	}

	if ((epriv->response_event && evt->reg == apriv->evt_response) || (epriv->query_event && evt->reg == apriv->evt_query)) {
		if (analyzer_http_event_finalize_process(cpriv) != POM_OK)
			return POM_ERR;
		cpriv->evt = event_alloc(apriv->evt_request);
		
		if (!cpriv->evt)
			return POM_ERR;

		epriv = malloc(sizeof(struct analyzer_http_request_event_priv));
		if (!epriv) {
			event_cleanup(cpriv->evt);
			cpriv->evt = NULL;
			pom_oom(sizeof(struct analyzer_http_request_event_priv));
			return POM_ERR;
		}
		memset(epriv, 0, sizeof(struct analyzer_http_request_event_priv));
		cpriv->evt->priv = epriv;
	}

	// Do the mapping, no flag checking or other, we just know how :)

	struct event_data *src_data = evt->data;
	struct event_data *dst_data = cpriv->evt->data;

	struct event_data_item *headers = NULL;

	if (evt->reg == apriv->evt_query) {

		event_refcount_inc(evt);
		epriv->query_event = evt;
		epriv->query_dir = s->direction;

		// Copy data contained into the query event
		dst_data[analyzer_http_request_first_line].value = src_data[proto_http_query_first_line].value;
		dst_data[analyzer_http_request_request_proto].value = src_data[proto_http_query_proto].value;
		dst_data[analyzer_http_request_request_method].value = src_data[proto_http_query_method].value;
		dst_data[analyzer_http_request_url].value = src_data[proto_http_query_url].value;
		dst_data[analyzer_http_request_query_time].value = src_data[proto_http_query_start_time].value;

		dst_data[analyzer_http_request_query_headers].items = src_data[proto_http_query_headers].items;
		dst_data[analyzer_http_request_query_headers].flags = EVENT_DATA_FLAG_NO_CLEAN;

		headers = src_data[proto_http_query_headers].items;


	} else if (evt->reg == apriv->evt_response) {

		event_refcount_inc(evt);
		epriv->response_event = evt;
		epriv->query_dir = POM_DIR_REVERSE(s->direction);

		dst_data[analyzer_http_request_status].value = src_data[proto_http_response_status].value;
		dst_data[analyzer_http_request_request_proto].value = src_data[proto_http_response_proto].value;
		dst_data[analyzer_http_request_response_time].value = src_data[proto_http_response_start_time].value;

		dst_data[analyzer_http_request_response_headers].items = src_data[proto_http_response_headers].items;
		dst_data[analyzer_http_request_response_headers].flags = EVENT_DATA_FLAG_NO_CLEAN;

		headers = src_data[proto_http_response_headers].items;


	} else {
		pomlog(POMLOG_ERR "Unexpected event %s", evt->reg->info->name);
		return POM_ERR;
	}

	// Parse the info we need from the header
	for (; headers; headers = headers->next) {
		if (evt->reg == apriv->evt_query) {

			if (!dst_data[analyzer_http_request_server_name].value && !strcasecmp(headers->key, "Host")) {
				dst_data[analyzer_http_request_server_name].value = headers->value;
				continue;
			}
	
			// TODO username and password
		}


		if (!strcasecmp(headers->key, "Content-Length")) {
			size_t content_len = 0;
			if (sscanf(PTYPE_STRING_GETVAL(headers->value), "%zu", &content_len) != 1) {
				pomlog(POMLOG_DEBUG "Could not parse Content-Length \"%s\"", PTYPE_STRING_GETVAL(headers->value));
				continue;
			}
			epriv->content_len[s->direction] = content_len;
		} else if (!strcasecmp(headers->key, "Content-Type")) {
			epriv->content_type[s->direction] = PTYPE_STRING_GETVAL(headers->value);
		} else if (!strcasecmp(headers->key, "Content-Encoding")) {
			char *val = PTYPE_STRING_GETVAL(headers->value);
			if (!strcasecmp(val, "gzip"))
				epriv->content_flags[s->direction] |= ANALYZER_PLOAD_BUFFER_IS_GZIP;
			else if (!strcasecmp(val, "deflate"))
				epriv->content_flags[s->direction] |= ANALYZER_PLOAD_BUFFER_IS_DEFLATE;
		}
		


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

		if (evt->reg == apriv->evt_query) {
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

		if (evt->reg == apriv->evt_query) {
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

	if (!(epriv->query_event && epriv->response_event)) {
		// We have one of the two event, event processing begins
		return event_process_begin(cpriv->evt, stack, stack_index);
	}

	return POM_OK;
}

int analyzer_http_event_process_end(struct event *evt, void *obj) {


	struct analyzer *analyzer = obj;
	struct analyzer_http_priv *apriv = analyzer->priv;

	struct analyzer_http_ce_priv *cpriv = conntrack_get_priv(evt->ce, obj);
	if (!cpriv) {
		pomlog(POMLOG_WARN "Internal error, analyzer_http_event_process_end() called without _begin().");
		return POM_OK;
	}

	if (evt->reg == apriv->evt_query)
		cpriv->flags |= ANALYZER_HTTP_EVT_QUERY_END;
	else
		cpriv->flags |= ANALYZER_HTTP_EVT_RESPONSE_END;

	if (cpriv->flags == (ANALYZER_HTTP_EVT_QUERY_END | ANALYZER_HTTP_EVT_RESPONSE_END))
		return analyzer_http_event_finalize_process(cpriv);

	return POM_OK;
}

int analyzer_http_event_finalize_process(struct analyzer_http_ce_priv *cpriv) {

	struct event *evt = cpriv->evt;

	if (event_process_end(evt) != POM_OK)
		return POM_ERR;

	cpriv->evt = NULL;
	cpriv->flags = 0;

	return POM_OK;
}


int analyzer_http_request_event_cleanup(struct event *evt) {

	struct analyzer_http_request_event_priv *priv = evt->priv;

	if (priv->query_event) {
		event_refcount_dec(priv->query_event);
		priv->query_event = NULL;
	}

	if (priv->response_event) {
		event_refcount_dec(priv->response_event);
		priv->response_event = NULL;
	}

	if (evt->data[analyzer_http_request_server_addr].value)
		ptype_cleanup(evt->data[analyzer_http_request_server_addr].value);
	if (evt->data[analyzer_http_request_server_port].value)
		ptype_cleanup(evt->data[analyzer_http_request_server_port].value);
	if (evt->data[analyzer_http_request_client_addr].value)
		ptype_cleanup(evt->data[analyzer_http_request_client_addr].value);
	if (evt->data[analyzer_http_request_client_port].value)
		ptype_cleanup(evt->data[analyzer_http_request_client_port].value);

	int i;
	for (i = 0; i < 2; i++) {
		if (priv->pload[i]) {
			analyzer_pload_buffer_cleanup(priv->pload[i]);
			priv->pload[i] = NULL;
		}
		priv->content_len[i] = 0;
		priv->content_type[i] = NULL;
	}

	free(priv);

	return POM_OK;
}

int analyzer_http_proto_packet_process(void *object, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = object;

	struct proto_process_stack *pload_stack = &stack[stack_index];

	struct proto_process_stack *s = &stack[stack_index - 1];
	if (!s->ce)
		return POM_ERR;

	struct analyzer_http_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);
	if (!cpriv) {
		pomlog(POMLOG_ERR "No private data attached to this connection. Ignoring payload.");
		return POM_ERR;
	}

	int dir = s->direction;

	struct analyzer_http_request_event_priv *epriv = cpriv->evt->priv;

	struct analyzer_pload_type *type = NULL;
	if (epriv->content_type[dir])
		type = analyzer_pload_type_get_by_mime_type(epriv->content_type[dir]);

	if (!epriv->pload[dir]) {
		epriv->pload[dir] = analyzer_pload_buffer_alloc(type, epriv->content_len[dir], ANALYZER_PLOAD_BUFFER_NEED_MAGIC | epriv->content_flags[dir]);
		if (!epriv->pload[dir])
			return POM_ERR;

		epriv->pload[dir]->rel_event = cpriv->evt;

	}

	if (analyzer_pload_buffer_append(epriv->pload[dir], pload_stack->pload, pload_stack->plen) != POM_OK)
		return POM_ERR;

	return POM_OK;
}
