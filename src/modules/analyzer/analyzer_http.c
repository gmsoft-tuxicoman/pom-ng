/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2012 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_uint64.h>
#include <pom-ng/ptype_string.h>

struct mod_reg_info* analyzer_http_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_http_mod_register;
	reg_info.unregister_func = analyzer_http_mod_unregister;
	reg_info.dependencies = "proto_http, ptype_uint16, ptype_uint64, ptype_string";

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

	static struct data_item_reg evt_request_data_items[ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT] = { { 0 } };

	evt_request_data_items[analyzer_http_request_server_name].name = "server_name";
	evt_request_data_items[analyzer_http_request_server_name].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_server_name].value_type = ptype_get_type("string");

	evt_request_data_items[analyzer_http_request_server_addr].name = "server_addr";
	evt_request_data_items[analyzer_http_request_server_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_server_addr].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_server_port].name = "server_port";
	evt_request_data_items[analyzer_http_request_server_port].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_server_port].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_client_addr].name = "client_addr";
	evt_request_data_items[analyzer_http_request_client_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_client_addr].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_client_port].name = "client_port";
	evt_request_data_items[analyzer_http_request_client_port].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_client_port].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_request_proto].name = "request_proto";
	evt_request_data_items[analyzer_http_request_request_proto].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_request_proto].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_request_method].name = "request_method";
	evt_request_data_items[analyzer_http_request_request_method].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_request_method].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_first_line].name = "first_line";
	evt_request_data_items[analyzer_http_request_first_line].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_first_line].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_url].name = "url";
	evt_request_data_items[analyzer_http_request_url].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_url].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_query_time].name = "query_time";
	evt_request_data_items[analyzer_http_request_query_time].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_query_time].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_response_time].name = "response_time";
	evt_request_data_items[analyzer_http_request_response_time].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_response_time].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_username].name = "username";
	evt_request_data_items[analyzer_http_request_username].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_username].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_password].name = "password";
	evt_request_data_items[analyzer_http_request_password].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_password].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_status].name = "status";
	evt_request_data_items[analyzer_http_request_status].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_request_data_items[analyzer_http_request_status].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_query_headers].name = "query_headers";
	evt_request_data_items[analyzer_http_request_query_headers].flags = DATA_REG_FLAG_LIST;
	evt_request_data_items[analyzer_http_request_query_headers].value_type = ptype_get_type("string");

	evt_request_data_items[analyzer_http_request_response_headers].name = "response_headers";
	evt_request_data_items[analyzer_http_request_response_headers].flags = ANALYZER_DATA_FLAG_LIST;
	evt_request_data_items[analyzer_http_request_response_headers].value_type = ptype_get_type("string");
	
	evt_request_data_items[analyzer_http_request_post_data].name = "post_data";
	evt_request_data_items[analyzer_http_request_post_data].flags = DATA_REG_FLAG_LIST;
	evt_request_data_items[analyzer_http_request_post_data].value_type = ptype_get_type("string");

	evt_request_data_items[analyzer_http_request_query_size].name = "query_size";
	evt_request_data_items[analyzer_http_request_query_size].value_type = ptype_get_type("uint64");

	evt_request_data_items[analyzer_http_request_response_size].name = "response_size";
	evt_request_data_items[analyzer_http_request_response_size].value_type = ptype_get_type("uint64");

	static struct data_reg evt_request_data = {
		.items = evt_request_data_items,
		.data_count = ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT
	};

	static struct event_reg_info analyzer_http_evt_request = { 0 };
	analyzer_http_evt_request.source_name = "analyzer_http";
	analyzer_http_evt_request.source_obj = analyzer;
	analyzer_http_evt_request.name = "http_request";
	analyzer_http_evt_request.description = "HTTP request (compound event of http_query and http_response)";
	analyzer_http_evt_request.data_reg = &evt_request_data;
	analyzer_http_evt_request.flags = EVENT_REG_FLAG_PAYLOAD;
	analyzer_http_evt_request.listeners_notify = analyzer_http_event_listeners_notify;
	analyzer_http_evt_request.cleanup = analyzer_http_request_event_cleanup;

	priv->evt_request = event_register(&analyzer_http_evt_request);
	if (!priv->evt_request)
		goto err;

	priv->proto_http = proto_get("http");
	if (!priv->proto_http)
		goto err;

	return analyzer_http_post_init(analyzer);

err:
	analyzer_http_cleanup(analyzer);
	return POM_ERR;


}

int analyzer_http_cleanup(struct analyzer *analyzer) {

	struct analyzer_http_priv *priv = analyzer->priv;

	if (priv->evt_request)
		event_unregister(priv->evt_request);

	free(priv);

	return POM_OK;
}

int analyzer_http_ce_priv_cleanup(void *obj, void *priv) {

	struct analyzer_http_ce_priv *cpriv = priv;

	int res = POM_OK;

	while (cpriv->evt_head)
		res += analyzer_http_event_finalize_process(cpriv);

	free(priv);

	return res;
}

int analyzer_http_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_http_priv *priv = analyzer->priv;

	if (has_listeners) {
		if (event_listener_register(priv->evt_query, analyzer, analyzer_http_event_process_begin, analyzer_http_event_process_end) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_response, analyzer, analyzer_http_event_process_begin, analyzer_http_event_process_end) != POM_OK) {
			event_listener_unregister(priv->evt_query, analyzer);
			return POM_ERR;
		}

		priv->http_packet_listener = proto_packet_listener_register(priv->proto_http, PROTO_PACKET_LISTENER_PLOAD_ONLY, analyzer, analyzer_http_proto_packet_process);
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
		cpriv->client_direction = POM_DIR_UNK;


		if (conntrack_add_priv(s->ce, analyzer, cpriv, analyzer_http_ce_priv_cleanup) != POM_OK) {
			free(cpriv);
			return POM_ERR;
		}

	}

	if (cpriv->conversation_error) {
		pomlog(POMLOG_DEBUG "Not accepting more events after conversation error");
		return POM_OK;
	}

	// Remember if we created a new event of not
	int start_process = 0; 

	struct analyzer_http_event_list *elist = cpriv->evt_head;

	if (evt->reg == apriv->evt_response && elist) {
		// Skip requests which already have a response
		struct analyzer_http_request_event_priv *epriv = elist->evt->priv;
		if (epriv->response_event && elist->next) {
			cpriv->conversation_error = 1;
			pomlog(POMLOG_DEBUG "Conversation error. Received second response without query.");
			return POM_OK;
		}
	}

	// If it's a new query or if there is no ongoing query and we got a response, allocate a new event
	if (evt->reg == apriv->evt_query || !elist) {

		elist = malloc(sizeof(struct analyzer_http_event_list));
		if (!elist) {
			pom_oom(sizeof(struct analyzer_http_event_list));
			return POM_ERR;
		}
		memset(elist, 0, sizeof(struct analyzer_http_event_list));

		elist->prev = cpriv->evt_tail;
		if (elist->prev)
			elist->prev->next = elist;
		else
			cpriv->evt_head = elist;

		cpriv->evt_tail = elist;

		elist->evt = event_alloc(apriv->evt_request);
		if (!elist->evt)
			return POM_ERR;

		start_process = 1;

	}

	struct analyzer_http_request_event_priv *epriv = elist->evt->priv;

	if (!epriv) {
		epriv = malloc(sizeof(struct analyzer_http_request_event_priv));
		if (!epriv) {
			pom_oom(sizeof(struct analyzer_http_request_event_priv));
			return POM_ERR;
		}
		memset(epriv, 0, sizeof(struct analyzer_http_request_event_priv));
		elist->evt->priv = epriv;
	}

	// Do the mapping, no flag checking or other, we just know how :)

	struct data *src_data = evt->data;
	struct data *dst_data = elist->evt->data;

	struct data_item *headers = NULL;

	if (evt->reg == apriv->evt_query) {

		if (cpriv->client_direction == POM_DIR_UNK)
			cpriv->client_direction = s->direction;

		event_refcount_inc(evt);
		epriv->query_event = evt;

		// Copy data contained into the query event
		dst_data[analyzer_http_request_first_line].value = src_data[proto_http_query_first_line].value;
		dst_data[analyzer_http_request_request_proto].value = src_data[proto_http_query_proto].value;
		dst_data[analyzer_http_request_request_method].value = src_data[proto_http_query_method].value;
		dst_data[analyzer_http_request_url].value = src_data[proto_http_query_url].value;
		dst_data[analyzer_http_request_query_time].value = src_data[proto_http_query_start_time].value;

		dst_data[analyzer_http_request_query_headers].items = src_data[proto_http_query_headers].items;
		dst_data[analyzer_http_request_query_headers].flags = DATA_FLAG_NO_CLEAN;

		headers = src_data[proto_http_query_headers].items;


	} else if (evt->reg == apriv->evt_response) {

		if (cpriv->client_direction == POM_DIR_UNK)
			cpriv->client_direction = POM_DIR_REVERSE(s->direction);

		event_refcount_inc(evt);
		epriv->response_event = evt;

		dst_data[analyzer_http_request_status].value = src_data[proto_http_response_status].value;
		dst_data[analyzer_http_request_request_proto].value = src_data[proto_http_response_proto].value;
		dst_data[analyzer_http_request_response_time].value = src_data[proto_http_response_start_time].value;

		if (!dst_data[analyzer_http_request_query_time].value) // If we don't know when we started, use the reply time instead
			dst_data[analyzer_http_request_query_time].value = src_data[proto_http_response_start_time].value;

		dst_data[analyzer_http_request_response_headers].items = src_data[proto_http_response_headers].items;
		dst_data[analyzer_http_request_response_headers].flags = DATA_FLAG_NO_CLEAN;

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

	if (!dst_data[analyzer_http_request_server_name].value)
		dst_data[analyzer_http_request_server_name].value = dst_data[analyzer_http_request_server_addr].value;
	
	// Start processing our meta-event
	if (start_process)
		return event_process_begin(elist->evt, stack, stack_index);

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

	struct analyzer_http_event_list *elist = cpriv->evt_head;
	if (!elist) {
		pomlog(POMLOG_ERR "No event found !");
		return POM_ERR;
	}

	struct analyzer_http_request_event_priv *epriv = elist->evt->priv;

	// Rarely, reponse are not parsed entirely and response are already sent
	if (evt->reg == apriv->evt_query) {

		if (!epriv->response_event || !(epriv->response_event->flags & EVENT_FLAG_PROCESS_DONE)) {
			// Do not process as there was no finalized response to this event
			// It will be finalized when the response is received
			return POM_OK;
		}

	} else {
		if (epriv->response_event != evt) {
			pomlog(POMLOG_ERR "Internal error, not the response event expected");
			return POM_ERR;
		}
		
		// Server replied without waiting for the end of the query
		if (epriv->query_event && !(epriv->query_event->flags & EVENT_FLAG_PROCESS_DONE))
			return POM_OK;
	}

	return analyzer_http_event_finalize_process(cpriv);
}

int analyzer_http_event_finalize_process(struct analyzer_http_ce_priv *cpriv) {


	struct analyzer_http_event_list *elist = cpriv->evt_head;
	struct event *evt = elist->evt;
	struct analyzer_http_request_event_priv *epriv = evt->priv;

	if (!epriv->query_event || !epriv->response_event)
		pomlog(POMLOG_DEBUG "Processing incomplete event !");

	cpriv->evt_head = cpriv->evt_head->next;
	if (cpriv->evt_head)
		cpriv->evt_head->prev = NULL;
	else
		cpriv->evt_tail = NULL;
	
	free(elist);

	if (event_process_end(evt) != POM_OK)
		return POM_ERR;

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
	if (!cpriv || !cpriv->evt_head || !cpriv->evt_tail) {
		pomlog(POMLOG_ERR "No private data attached to this connection. Ignoring payload.");
		return POM_ERR;
	}
	
	int dir = s->direction;
	struct event *evt = NULL;
	if (dir == cpriv->client_direction) {
		// We need to use the latest query we've received
		evt = cpriv->evt_tail->evt;

		uint64_t *query_size = PTYPE_UINT64_GETVAL(evt->data[analyzer_http_request_query_size].value);
		*query_size += pload_stack->plen;
	} else {
		// We need to use the first response
		evt = cpriv->evt_head->evt;

		uint64_t *response_size = PTYPE_UINT64_GETVAL(evt->data[analyzer_http_request_response_size].value);
		*response_size += pload_stack->plen;
	}

	struct analyzer_http_request_event_priv *epriv = evt->priv;

	struct analyzer_pload_type *type = NULL;
	if (epriv->content_type[dir])
		type = analyzer_pload_type_get_by_mime_type(epriv->content_type[dir]);

	if (!epriv->pload[dir]) {
		epriv->pload[dir] = analyzer_pload_buffer_alloc(type, epriv->content_len[dir], ANALYZER_PLOAD_BUFFER_NEED_MAGIC | epriv->content_flags[dir]);
		if (!epriv->pload[dir])
			return POM_ERR;

		epriv->pload[dir]->rel_event = evt;

	}

	if (analyzer_pload_buffer_append(epriv->pload[dir], pload_stack->pload, pload_stack->plen) != POM_OK)
		return POM_ERR;

	return POM_OK;
}
