/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/core.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_timestamp.h>

#include "proto_http.h"

#include <string.h>
#include <stdio.h>


#if 0
#define debug_http(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_http(x ...)
#endif

struct mod_reg_info* proto_http_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_http_mod_register;
	reg_info.unregister_func = proto_http_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_uint16, ptype_timestamp";

	return &reg_info;
}


static int proto_http_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_http = { 0 };
	proto_http.name = "http";
	proto_http.api_ver = PROTO_API_VER;
	proto_http.mod = mod;

	static struct conntrack_info ct_info = { 0 };

	ct_info.default_table_size = 1; // No hashing done here
	ct_info.cleanup_handler = proto_http_conntrack_cleanup;
	proto_http.ct_info = &ct_info;
	
	proto_http.init = proto_http_init;
	proto_http.process = proto_http_process;
	proto_http.post_process = proto_http_post_process;
	proto_http.cleanup = proto_http_cleanup;

	if (proto_register(&proto_http) == POM_OK)
		return POM_OK;

	proto_http_mod_unregister();
	return POM_ERR;

}

static int proto_http_init(struct proto *proto, struct registry_instance *ri) {

	struct proto_http_priv *priv = malloc(sizeof(struct proto_http_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_http_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_http_priv));

	proto_set_priv(proto, priv);

	// Register the http_query event
	static struct data_item_reg evt_query_data_items[PROTO_HTTP_EVT_QUERY_DATA_COUNT] = { { 0 } };
	evt_query_data_items[proto_http_query_first_line].name = "first_line";
	evt_query_data_items[proto_http_query_first_line].value_type = ptype_get_type("string");
	evt_query_data_items[proto_http_query_proto].name = "proto_version";
	evt_query_data_items[proto_http_query_proto].value_type = ptype_get_type("string");
	evt_query_data_items[proto_http_query_method].name = "method";
	evt_query_data_items[proto_http_query_method].value_type = ptype_get_type("string");
	evt_query_data_items[proto_http_query_url].name = "url";
	evt_query_data_items[proto_http_query_url].value_type = ptype_get_type("string");
	evt_query_data_items[proto_http_query_start_time].name = "start_time";
	evt_query_data_items[proto_http_query_start_time].value_type = ptype_get_type("timestamp");
	evt_query_data_items[proto_http_query_end_time].name = "end_time";
	evt_query_data_items[proto_http_query_end_time].value_type = ptype_get_type("timestamp");
	evt_query_data_items[proto_http_query_headers].name = "headers";
	evt_query_data_items[proto_http_query_headers].value_type = ptype_get_type("string");
	evt_query_data_items[proto_http_query_headers].flags = DATA_REG_FLAG_LIST;

	static struct data_reg evt_query_data = {
		.items = evt_query_data_items,
		.data_count = PROTO_HTTP_EVT_QUERY_DATA_COUNT
	};

	
	static struct event_reg_info proto_http_evt_query = { 0 };
	proto_http_evt_query.source_name = "proto_http";
	proto_http_evt_query.source_obj = proto;
	proto_http_evt_query.name = "http_query";
	proto_http_evt_query.description = "HTTP query (client side only)";
	proto_http_evt_query.data_reg = &evt_query_data;

	priv->evt_query = event_register(&proto_http_evt_query);
	if (!priv->evt_query)
		goto err;

	// Register the http_response event
	static struct data_item_reg evt_response_data_items[PROTO_HTTP_EVT_RESPONSE_DATA_COUNT] = { { 0 } };
	evt_response_data_items[proto_http_response_status].name = "status";
	evt_response_data_items[proto_http_response_status].value_type = ptype_get_type("uint16");
	evt_response_data_items[proto_http_response_proto].name = "proto_version";
	evt_response_data_items[proto_http_response_proto].value_type = ptype_get_type("string");
	evt_response_data_items[proto_http_response_start_time].name = "start_time";
	evt_response_data_items[proto_http_response_start_time].value_type = ptype_get_type("timestamp");
	evt_response_data_items[proto_http_response_end_time].name = "end_time";
	evt_response_data_items[proto_http_response_end_time].value_type = ptype_get_type("timestamp");
	evt_response_data_items[proto_http_response_headers].name = "headers";
	evt_response_data_items[proto_http_response_headers].value_type = ptype_get_type("string");
	evt_response_data_items[proto_http_response_headers].flags = DATA_REG_FLAG_LIST;

	static struct data_reg evt_response_data = {
		.items = evt_response_data_items,
		.data_count = PROTO_HTTP_EVT_RESPONSE_DATA_COUNT
	};

	static struct event_reg_info proto_http_evt_response = { 0 };
	proto_http_evt_response.source_name = "proto_http";
	proto_http_evt_response.source_obj = proto;
	proto_http_evt_response.name = "http_response";
	proto_http_evt_response.description = "HTTP response (server side only)";
	proto_http_evt_response.data_reg = &evt_response_data;

	priv->evt_response = event_register(&proto_http_evt_response);
	if (!priv->evt_response)
		goto err;


	return POM_OK;

err:
	proto_http_cleanup(priv);
	return POM_ERR;
}

int proto_http_cleanup(void *proto_priv) {

	if (proto_priv) {
		struct proto_http_priv *priv = proto_priv;
		if (priv->evt_query)
			event_unregister(priv->evt_query);
		if (priv->evt_response)
			event_unregister(priv->evt_response);

		free(priv);
	}

	return POM_OK;
}

static int proto_http_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK) {
		pomlog(POMLOG_ERR "Could not get conntrack entry");
		return PROTO_ERR;
	}

	// There should be no need to keep the lock here since we are in the packet_stream lock from proto_tcp
	conntrack_unlock(s->ce);
	
	struct proto_http_conntrack_priv *priv = s->ce->priv;
	if (!priv) {
		priv = malloc(sizeof(struct proto_http_conntrack_priv));
		if (!priv) {
			pom_oom(sizeof(struct proto_http_conntrack_priv));
			return PROTO_ERR;
		}
		memset(priv, 0, sizeof(struct proto_http_conntrack_priv));
		priv->state[POM_DIR_FWD] = HTTP_STATE_FIRST_LINE;
		priv->state[POM_DIR_REV] = HTTP_STATE_FIRST_LINE;
		priv->client_direction = POM_DIR_UNK;

		s->ce->priv = priv;

	}

	debug_http("entry %p, current state %u, packet %u.%u", s->ce, priv->state[s->direction], (int)p->ts.tv_sec, (int)p->ts.tv_usec);

	if (priv->is_invalid) {
		debug_http("entry %p, packet %u.%u : invalid", s->ce, (int)p->ts.tv_sec, (int)p->ts.tv_usec);
		return PROTO_INVALID;
	}

	if (!priv->parser[s->direction]) {
		priv->parser[s->direction] = packet_stream_parser_alloc(HTTP_MAX_HEADER_LINE);
		if (!priv->parser[s->direction])
			return PROTO_ERR;
	}
	
	struct packet_stream_parser *parser = priv->parser[s->direction];
	if (packet_stream_parser_add_payload(parser, s->pload, s->plen) != POM_OK)
		return PROTO_ERR;

	char *line = NULL;
	unsigned int len = 0;

	while (1) {

		switch (priv->state[s->direction]) {
			case HTTP_STATE_FIRST_LINE:
				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
					return PROTO_ERR;

				if (!line) // No more full lines in this packet
					return PROTO_OK;

				if (!len) // Ignore empty lines at this stage
					break;

				int res = proto_http_parse_query_response(s->ce, line, len, s->direction, p);
				if (res == PROTO_INVALID) {
					priv->is_invalid = 1;
					return PROTO_INVALID;
				}
				break;

			case HTTP_STATE_HEADERS: {
				// Parse headers
				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
					return PROTO_ERR;
				if (!line) // No more full lines in this packet
					return PROTO_OK;

				if (!len) {
					// Header are parsed
					struct http_info *info = &priv->info[s->direction];
					
					if ((info->flags & (HTTP_FLAG_CHUNKED | HTTP_FLAG_HAVE_CLEN)) == (HTTP_FLAG_CHUNKED | HTTP_FLAG_HAVE_CLEN)) {
						pomlog(POMLOG_DEBUG "Ignoring Content-Length because transfer type is chunked");
						info->flags &= ~HTTP_FLAG_HAVE_CLEN;
						info->content_len = 0;
					}
					
					// If there is no payload
					if ( ((info->flags & HTTP_FLAG_HAVE_CLEN) && !info->content_len) ||
						// Or if the response is not supposed to contain any payload
						(s->direction == POM_DIR_REVERSE(priv->client_direction) && ((info->last_err_code >= 100 && info->last_err_code < 200) || info->last_err_code == 204 || info->last_err_code == 304)) ||
						
						// Or if its a query, forget about having CLEN
						(s->direction == priv->client_direction && (!(info->flags & HTTP_FLAG_HAVE_CLEN)))
						
						) {
							struct data *evt_data = event_get_data(priv->event[s->direction]);
							if (s->direction == priv->client_direction) {
								PTYPE_TIMESTAMP_SETVAL(evt_data[proto_http_query_end_time].value, p->ts);
								data_set(evt_data[proto_http_query_end_time]);
							} else {
								PTYPE_TIMESTAMP_SETVAL(evt_data[proto_http_response_end_time].value, p->ts);
								data_set(evt_data[proto_http_response_end_time]);
							}

							// Process the event
							event_process_begin(priv->event[s->direction], stack, stack_index);
							event_process_end(priv->event[s->direction]);
							priv->event[s->direction] = NULL;
						
							proto_http_conntrack_reset(s->ce, s->direction);
							break;
					} 

					// There is some payload, switch to the right state and process the begining of the event
					priv->state[s->direction]++;
					event_process_begin(priv->event[s->direction], stack, stack_index);

					continue;
				}


				char *colon = memchr(line, ':', len);
				if (!colon) {
					pomlog(POMLOG_DEBUG "Header line without colon");
					priv->is_invalid = 1;
					return PROTO_INVALID;
				}

				unsigned int name_len = colon - line ;

				char *name = malloc(name_len  + 1);
				if (!name) {
					pom_oom(name_len + 1);
					return PROTO_ERR;
				}
				strncpy(name, line, name_len);
				name[name_len] = 0;
			
				colon++;
				while (colon < line + len && *colon == ' ')
					colon++;
				unsigned int value_len = len - (colon - line);
				char *value = malloc(value_len + 1);
				if (!value) {
					free(name);
					pom_oom(value_len + 1);
					return PROTO_ERR;
				}

				strncpy(value, colon, value_len);
				value[value_len] = 0;

				struct ptype *data_val = event_data_item_add(priv->event[s->direction], (priv->client_direction == s->direction ? proto_http_query_headers : proto_http_response_headers), name);
				if (!data_val) {
					free(name);
					free(value);
					return PROTO_ERR;
				}

				PTYPE_STRING_SETVAL_P(data_val, value);

				
				// Parse a few useful headers
				if (!(priv->info[s->direction].flags & HTTP_FLAG_HAVE_CLEN) && !strcasecmp(name, "Content-Length")) {
					if (sscanf(value, "%zu", &priv->info[s->direction].content_len) != 1) {
						pomlog(POMLOG_DEBUG "Invalid Content-Length : \"%s\"", value);
						return PROTO_INVALID;
					}
					priv->info[s->direction].flags |= HTTP_FLAG_HAVE_CLEN;
				} else if (!(priv->info[s->direction].flags & HTTP_FLAG_CHUNKED) && !strcasecmp(name, "Transfer-Encoding")) {
					if (!strcasecmp(value, "chunked"))
						priv->info[s->direction].flags |= HTTP_FLAG_CHUNKED;
				}


				break;
			}

			case HTTP_STATE_BODY: {
				if (priv->client_direction == POM_DIR_REVERSE(s->direction) && priv->info[s->direction].content_pos == 0) {
					// If it was a HEAD request, we might think there is some payload
					// while there actually isn't any. Check for that
					unsigned int remaining_size = 0;
					void *pload = NULL;
					packet_stream_parser_get_remaining(parser, &pload, &remaining_size);
					if (remaining_size >= strlen("HTTP/") && !strncasecmp(pload, "HTTP/", strlen("HTTP/"))) {
						debug_http("entry %p, found reply to HEAD request", s->ce);
						event_process_end(priv->event[s->direction]);
						priv->event[s->direction] = NULL;
						if (proto_http_conntrack_reset(s->ce, s->direction) != POM_OK)
							return PROTO_ERR;
						break;
					}
				}

				if (priv->info[s->direction].flags & HTTP_FLAG_CHUNKED) {
					unsigned int remaining_size = 0;
					void *pload = NULL;
					if (!priv->info[s->direction].chunk_len) {

						if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
							return PROTO_ERR;
						if (!line) // No more full line in this packet
							return PROTO_OK;

						// Remove trailing spaces
						for (; len > 0 && line[len - 1] == ' '; len--);

						// Remove leading '0' and spaces
						for (; len > 1 && (*line == '0' || *line == ' '); len--, line++);

						char int_str[10] = {0};
						if (len >= sizeof(int_str) || !len) {
							pomlog(POMLOG_DEBUG "Invalid chunk size of len %u", len);
							priv->is_invalid = 1;
							return PROTO_INVALID;
						}

						memcpy(int_str, line, len);
						if (sscanf(int_str, "%x", &priv->info[s->direction].chunk_len) != 1) {
							pomlog(POMLOG_DEBUG "Unparseable chunk size provided : %s", int_str);
							priv->is_invalid = 1;
							return PROTO_INVALID;
						}

						if (!priv->info[s->direction].chunk_len) {
							// This is the last chunk
							// Skip the last two bytes
							packet_stream_parser_get_remaining(parser, &pload, &remaining_size);
							if (remaining_size >= 2) {
								remaining_size -= 2;
								if (packet_stream_parser_skip_bytes(parser, 2) != POM_OK) {
									pomlog(POMLOG_ERR "Error while skipping 2 bytes from the stream");
									return PROTO_ERR;
								}
							}
							priv->info[s->direction].flags |= HTTP_FLAG_LAST_CHUNK;
							if (proto_http_post_process(priv, p, stack, stack_index) != POM_OK)
								return PROTO_ERR;
							continue;
						}
					}

					packet_stream_parser_get_remaining(parser, &pload, &remaining_size);
					unsigned int chunk_remaining = priv->info[s->direction].chunk_len - priv->info[s->direction].chunk_pos;
					s_next->pload = pload;
					if (remaining_size > chunk_remaining) {
						// There is the start of another chunk in this packet
						s_next->plen = chunk_remaining;
						remaining_size -= chunk_remaining;
						pload += chunk_remaining;
						if (remaining_size >= 2) {
							// Remove last CRLF
							remaining_size -= 2;
							pload += 2;
							chunk_remaining += 2;
						}
						if (packet_stream_parser_skip_bytes(parser, chunk_remaining) != POM_OK) {
							pomlog(POMLOG_ERR "Error while skipping %u bytes from the stream", chunk_remaining);
							return PROTO_ERR;
						}

						debug_http("entry %p, got %u bytes of chunked payload", s->ce, s_next->plen);
						
						priv->info[s->direction].chunk_pos = 0;
						priv->info[s->direction].chunk_len = 0;

						int res = core_process_multi_packet(stack, stack_index + 1, p);
						if (res == PROTO_ERR)
							return PROTO_ERR;


						// Continue parsing the next chunk
						continue;
					}

					packet_stream_parser_empty(parser);
					s_next->plen = remaining_size;
					priv->info[s->direction].chunk_pos += remaining_size;
					return POM_OK; // Nothing left to process

				}  else {

					// Set the right payload in the next stack index
					packet_stream_parser_get_remaining(parser, &s_next->pload, &s_next->plen);

					unsigned int pload_remaining = priv->info[s->direction].content_len - priv->info[s->direction].content_pos;
					if ((priv->info[s->direction].flags & HTTP_FLAG_HAVE_CLEN) && (pload_remaining < s_next->plen)) {
						if (packet_stream_parser_skip_bytes(parser, pload_remaining) != POM_OK) {
							pomlog(POMLOG_ERR "Error while skipping %u bytes from the stream", pload_remaining);
							return PROTO_ERR;
						}
						s_next->plen = pload_remaining;
						priv->info[s->direction].content_pos = priv->info[s->direction].content_pos;
						debug_http("entry %p, got %u bytes of payload", s->ce, s_next->plen);

						// Do the post processing
						if (proto_http_post_process(priv, p, stack, stack_index) != POM_OK)
							return PROTO_ERR;
					} else {
						packet_stream_parser_empty(parser);
						priv->info[s->direction].content_pos += s_next->plen;
						debug_http("entry %p, got %u bytes of payload", s->ce, s_next->plen);
						return PROTO_OK;
					}
				}
				break;
			}
		}
	}


	return PROTO_OK;
}


static int proto_http_post_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct conntrack_entry *ce = stack[stack_index].ce;
	int direction = stack[stack_index].direction;

	struct proto_http_conntrack_priv *priv = ce->priv;
	struct http_info *info = &priv->info[direction];

	if (priv->state[direction] == HTTP_STATE_BODY && (
		((info->flags & HTTP_FLAG_HAVE_CLEN) && (info->content_pos >= info->content_len)) // End of payload reached
		|| (info->flags & (HTTP_FLAG_CHUNKED & HTTP_FLAG_LAST_CHUNK))) // Last chunk was processed
		) {
		struct data *evt_data = event_get_data(priv->event[direction]);
		if (direction == priv->client_direction) {
			PTYPE_TIMESTAMP_SETVAL(evt_data[proto_http_query_end_time].value, p->ts);
			data_set(evt_data[proto_http_query_end_time]);
		} else {
			PTYPE_TIMESTAMP_SETVAL(evt_data[proto_http_response_end_time].value, p->ts);
			data_set(evt_data[proto_http_response_end_time]);
		}
		// Payload done
		event_process_end(priv->event[direction]);
		priv->event[direction] = NULL;

		proto_http_conntrack_reset(ce, direction);

	}
	return PROTO_OK;
}

static int proto_http_conntrack_reset(struct conntrack_entry *ce, int direction) {

	struct proto_http_conntrack_priv *priv = ce->priv;

	debug_http("entry %p, reset", ce);

	priv->state[direction] = HTTP_STATE_FIRST_LINE;
	memset(&priv->info[direction], 0, sizeof(struct http_info));

	if (priv->event[direction]) {
		event_cleanup(priv->event[direction]);
		priv->event[direction] = NULL;
	}

	return POM_OK;
}

static int proto_http_conntrack_cleanup(void *ce_priv) {

	struct proto_http_conntrack_priv *priv = ce_priv;
	if (!priv)
		return POM_OK;

	int i;
	for (i = 0; i < POM_DIR_TOT; i++) {
		if (priv->parser[i])
			packet_stream_parser_cleanup(priv->parser[i]);
	}


	for (i = 0; i < POM_DIR_TOT; i++) {
		// We must cleanup the client direction first
		int direction = i;
		if (priv->client_direction != POM_DIR_UNK) {
			if (i == 0)
				direction = priv->client_direction;
			else
				direction = POM_DIR_REVERSE(priv->client_direction);
		}

		if (priv->event[direction]) {
			if (event_is_started(priv->event[direction])) {
				debug_http("entry %p, processing event on cleanup !", ce);
				event_process_end(priv->event[direction]);
			} else {
				event_cleanup(priv->event[direction]);
			}
		}
	}
	
	free(priv);

	return POM_OK;

}

static int proto_http_mod_unregister() {

	return proto_unregister("http");

}


int proto_http_parse_query_response(struct conntrack_entry *ce, char *line, unsigned int len, int direction, struct packet *p) {

	if (len < strlen("HTTP/"))
		return PROTO_INVALID;

	struct proto_http_priv *ppriv = proto_get_priv(ce->proto);
	struct proto_http_conntrack_priv *priv = ce->priv;

	int tok_num = 0;
	char *token = line, *space = NULL;;
	unsigned int line_len = len;

	// Response protocol
	char *response_proto = NULL;

	while (len) {
		space = memchr(token, ' ', len);
		
		size_t tok_len;
		if (space)
			tok_len = space - token;
		else
			tok_len = len;

		switch (tok_num) {
			case 0:
				
				if (priv->event[direction]) {
					pomlog(POMLOG_WARN "Internal error : http event still exist for direction %u", direction);
					event_cleanup(priv->event[direction]);
				}

				if (!strncasecmp(token, "HTTP/", strlen("HTTP/"))) {

					// Check the response direction
					if (priv->client_direction == POM_DIR_UNK) {
						priv->client_direction = POM_DIR_REVERSE(direction);
					} else {
						if (priv->client_direction != POM_DIR_REVERSE(direction)) {
							debug_http("Received response in the wrong direction !");
							return PROTO_INVALID;
						}
					}

					response_proto = malloc(tok_len + 1);
					if (!response_proto) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(response_proto, token, tok_len);
					response_proto[tok_len] = 0;
				} else {

					priv->event[direction] = event_alloc(ppriv->evt_query);
					if (!priv->event[direction])
						return POM_ERR;

					unsigned int i;
					for (i = 0; i < tok_len; i++) {
						if ((token[i]) < 'A' || (token[i] > 'Z' && token[i] < 'a') || (token[i] > 'z')) {
							// Definitely not a HTTP method
							pomlog(POMLOG_DEBUG "Not identified as an HTTP method");
							return PROTO_INVALID;
						}
					}

					// Check the query direction
					if (priv->client_direction == POM_DIR_UNK) {
						priv->client_direction = direction;
					} else {
						if (priv->client_direction != direction) {
							debug_http("Received query in the wrong direction !");
							return PROTO_INVALID;
						}
					}


					char *request_method = malloc(tok_len + 1);
					if (!request_method) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(request_method, token, tok_len);
					request_method[tok_len] = 0;

					struct data *evt_data = event_get_data(priv->event[direction]);

					PTYPE_STRING_SETVAL_P(evt_data[proto_http_query_method].value, request_method);
					data_set(evt_data[proto_http_query_method]);
				}
				break;
			case 1: {
				if (priv->client_direction == direction) {
					char *url = malloc(tok_len + 1);
					if (!url) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(url, token, tok_len);
					url[tok_len] = 0;
					struct data *evt_data = event_get_data(priv->event[direction]);
					PTYPE_STRING_SETVAL_P(evt_data[proto_http_query_url].value, url);
					data_set(evt_data[proto_http_query_url]);
				} else {
					// Get the status code
					uint16_t err_code = 0;
					char errcode[4];
					errcode[3] = 0;
					strncpy(errcode, token, 3);
					if (sscanf(errcode, "%hu", &err_code) != 1 || err_code == 0) {
						pomlog(POMLOG_DEBUG "Invalid code in HTTP response");
						return PROTO_INVALID;
					}

					// Do not save stuff about 100 Continue replies as it's not an response in itself
					if (err_code == 100) {
						if (response_proto)
							free(response_proto);
						return POM_OK;
					}

					priv->event[direction] = event_alloc(ppriv->evt_response);
					if (!priv->event[direction])
						return PROTO_ERR;

					struct data *evt_data = event_get_data(priv->event[direction]);
					PTYPE_UINT16_SETVAL(evt_data[proto_http_response_status].value, err_code);
					data_set(evt_data[proto_http_response_status]);
					priv->info[direction].last_err_code = err_code;

					PTYPE_STRING_SETVAL_P(evt_data[proto_http_response_proto].value, response_proto);
					data_set(evt_data[proto_http_response_proto]);
					response_proto = NULL;
				}

				break;
			}
			case 2:
				if (priv->client_direction == direction) {
					// This payload was identified as a possible query
					if (tok_len < strlen("HTTP/")) {
						pomlog(POMLOG_DEBUG "HTTP version string too short");
						return PROTO_INVALID;
					}
					if (strncasecmp(token, "HTTP/", strlen("HTTP/"))) {
						// Doesn't seem to be a valid HTTP version
						pomlog(POMLOG_DEBUG "Invalid HTTP version string");
						return PROTO_INVALID;
					}

					char *request_proto = malloc(tok_len + 1);
					if (!request_proto) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(request_proto, token, tok_len);
					request_proto[tok_len] = 0;
					
					struct data *evt_data = event_get_data(priv->event[direction]);
					PTYPE_STRING_SETVAL_P(evt_data[proto_http_query_proto].value, request_proto);
					data_set(evt_data[proto_http_query_proto]);
				}

				break;
			default:
				if (priv->client_direction == direction) {
					// No more than 3 tokens are expected for a query
					pomlog(POMLOG_DEBUG "More than 3 tokens found in the HTTP query");
					// FIXME do the cleanup
					return PROTO_INVALID;
				}
				break;
		}
		token += tok_len;
		len -= tok_len;
		while (*token == ' ' && len) {
			token++;
			len--;
		}
		tok_num++;
	}

	if (tok_num < 2) {

		if (response_proto)
			free(response_proto);

		pomlog(POMLOG_DEBUG "Unable to parse the query/response");
		return PROTO_INVALID;
	}

	struct data *evt_data = event_get_data(priv->event[direction]);
	if (priv->client_direction == direction) {
		
		if (tok_num < 3) {
			pomlog(POMLOG_DEBUG "Missing token for query");
			return PROTO_INVALID;
		}
		
		char *first_line = malloc(line_len + 1);
		if (!first_line) {
			pom_oom(line_len + 1);
			return PROTO_ERR;
		}

		memcpy(first_line, line, line_len);
		first_line[line_len] = 0;
		PTYPE_STRING_SETVAL_P(evt_data[proto_http_query_first_line].value, first_line);
		data_set(evt_data[proto_http_query_first_line]);

		PTYPE_TIMESTAMP_SETVAL(evt_data[proto_http_query_start_time].value, p->ts);
		data_set(evt_data[proto_http_query_start_time]);

		debug_http("entry %p, found query : \"%s\"", ce, first_line);

	} else {
		debug_http("entry %p, response with status %u", ce, priv->info[direction].last_err_code);

		PTYPE_TIMESTAMP_SETVAL(evt_data[proto_http_response_start_time].value, p->ts);
		data_set(evt_data[proto_http_response_start_time]);
	}

	priv->state[direction]++;

	return PROTO_OK;
}

