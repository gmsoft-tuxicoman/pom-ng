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
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_http_mod_register;
	reg_info.unregister_func = proto_http_mod_unregister;
	reg_info.dependencies = "proto_tcp, ptype_string, ptype_uint16, ptype_timestamp";

	return &reg_info;
}


static int proto_http_mod_register(struct mod_reg *mod) {



	static struct proto_reg_info proto_http;
	memset(&proto_http, 0, sizeof(struct proto_reg_info));
	proto_http.name = "http";
	proto_http.api_ver = PROTO_API_VER;
	proto_http.mod = mod;

	proto_http.ct_info.default_table_size = 1; // No hashing done here
	proto_http.ct_info.cleanup_handler = proto_http_conntrack_cleanup;
	
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

	proto->priv = priv;

	priv->ptype_string = ptype_alloc("string");
	priv->ptype_uint16 = ptype_alloc("uint16");
	priv->ptype_timestamp = ptype_alloc("timestamp");
	if (!priv->ptype_string || !priv->ptype_uint16 || !priv->ptype_timestamp)
		goto err;

	// Register the http_query event
	static struct event_data_reg evt_query_data[PROTO_HTTP_EVT_QUERY_DATA_COUNT];
	memset(evt_query_data, 0, sizeof(struct event_data_reg) * PROTO_HTTP_EVT_QUERY_DATA_COUNT);
	evt_query_data[proto_http_query_first_line].name = "first_line";
	evt_query_data[proto_http_query_first_line].value_template = priv->ptype_string;
	evt_query_data[proto_http_query_proto].name = "proto_version";
	evt_query_data[proto_http_query_proto].value_template = priv->ptype_string;
	evt_query_data[proto_http_query_method].name = "method";
	evt_query_data[proto_http_query_method].value_template = priv->ptype_string;
	evt_query_data[proto_http_query_url].name = "url";
	evt_query_data[proto_http_query_url].value_template = priv->ptype_string;
	evt_query_data[proto_http_query_start_time].name = "start_time";
	evt_query_data[proto_http_query_start_time].value_template = priv->ptype_timestamp;
	evt_query_data[proto_http_query_end_time].name = "end_time";
	evt_query_data[proto_http_query_end_time].value_template = priv->ptype_timestamp;
	evt_query_data[proto_http_query_headers].name = "headers";
	evt_query_data[proto_http_query_headers].value_template = priv->ptype_string;
	evt_query_data[proto_http_query_headers].flags = EVENT_DATA_REG_FLAG_LIST;

	
	static struct event_reg_info proto_http_evt_query;
	memset(&proto_http_evt_query, 0, sizeof(struct event_reg_info));
	proto_http_evt_query.source_name = "proto_http";
	proto_http_evt_query.source_obj = proto;
	proto_http_evt_query.name = "http_query";
	proto_http_evt_query.description = "HTTP query (client side only)";
	proto_http_evt_query.data_reg = evt_query_data;
	proto_http_evt_query.data_count = PROTO_HTTP_EVT_QUERY_DATA_COUNT;

	priv->evt_query = event_register(&proto_http_evt_query);
	if (!priv->evt_query)
		goto err;

	// Register the http_response event
	static struct event_data_reg evt_response_data[PROTO_HTTP_EVT_RESPONSE_DATA_COUNT];
	memset(evt_response_data, 0, sizeof(struct event_data_reg) * PROTO_HTTP_EVT_RESPONSE_DATA_COUNT);
	evt_response_data[proto_http_response_status].name = "status";
	evt_response_data[proto_http_response_status].value_template = priv->ptype_uint16;
	evt_response_data[proto_http_response_proto].name = "proto_version";
	evt_response_data[proto_http_response_proto].value_template = priv->ptype_string;
	evt_response_data[proto_http_response_start_time].name = "start_time";
	evt_response_data[proto_http_response_start_time].value_template = priv->ptype_timestamp;
	evt_response_data[proto_http_response_end_time].name = "end_time";
	evt_response_data[proto_http_response_end_time].value_template = priv->ptype_timestamp;
	evt_response_data[proto_http_response_headers].name = "headers";
	evt_response_data[proto_http_response_headers].value_template = priv->ptype_string;
	evt_response_data[proto_http_response_headers].flags = EVENT_DATA_REG_FLAG_LIST;

	static struct event_reg_info proto_http_evt_response;
	memset(&proto_http_evt_response, 0, sizeof(struct event_reg_info));
	proto_http_evt_response.source_name = "proto_http";
	proto_http_evt_response.source_obj = proto;
	proto_http_evt_response.name = "http_response";
	proto_http_evt_response.description = "HTTP response (server side only)";
	proto_http_evt_response.data_reg = evt_response_data;
	proto_http_evt_response.data_count = PROTO_HTTP_EVT_RESPONSE_DATA_COUNT;

	priv->evt_response = event_register(&proto_http_evt_response);
	if (!priv->evt_response)
		goto err;


	return POM_OK;

err:
	proto_http_cleanup(proto);
	return POM_ERR;
}

int proto_http_cleanup(struct proto * proto) {

	if (proto->priv) {
		struct proto_http_priv *priv = proto->priv;
		if (priv->ptype_string)
			ptype_cleanup(priv->ptype_string);
		if (priv->ptype_uint16)
			ptype_cleanup(priv->ptype_uint16);
		if (priv->ptype_timestamp)
			ptype_cleanup(priv->ptype_timestamp);
		
		if (priv->evt_query)
			event_unregister(priv->evt_query);
		if (priv->evt_response)
			event_unregister(priv->evt_response);

		free(priv);
	}

	return POM_OK;
}

static int proto_http_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_prev = &stack[stack_index - 1];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	s->ce = conntrack_get_unique_from_parent(s->proto, s_prev->ce);
	if (!s->ce) {
		pomlog(POMLOG_ERR "Could not get conntrack entry");
		return PROTO_ERR;
	}

	// There should be no need to lock here since we are in the packet_stream lock from proto_tcp

	
	struct proto_http_conntrack_priv *priv = s->ce->priv;
	if (!priv) {
		priv = malloc(sizeof(struct proto_http_conntrack_priv));
		if (!priv) {
			pom_oom(sizeof(struct proto_http_conntrack_priv));
			return PROTO_ERR;
		}
		memset(priv, 0, sizeof(struct proto_http_conntrack_priv));
		priv->state = HTTP_QUERY_HEADER;
		priv->client_direction = CT_DIR_UNK;

		s->ce->priv = priv;

	}

	debug_http("entry %p, current state %u, packet %u.%u", s->ce, priv->state, (int)p->ts.tv_sec, (int)p->ts.tv_usec);

	if (priv->state == HTTP_INVALID)
		return PROTO_INVALID;

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

		switch (priv->state) {
			case HTTP_QUERY_HEADER: 
				if (proto_http_conntrack_reset(s->ce) != POM_OK)
					return PROTO_ERR;
			case HTTP_RESPONSE_HEADER: {

				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
					return PROTO_ERR;

				if (!line) // No more full lines in this packet
					return PROTO_OK;

				int res = proto_http_parse_query_response(s->ce, line, len, s->direction, p);
				if (res == PROTO_INVALID) {
					priv->state = HTTP_INVALID;
					return PROTO_INVALID;
				}
				break;
			}

			case HTTP_RESPONSE:
			case HTTP_QUERY: {
				// Parse headers
				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
					return PROTO_ERR;
				if (!line) // No more full lines in this packet
					return PROTO_OK;

				if (!len) {
					// Header are parsed
					
					if ((priv->info.flags & (HTTP_FLAG_CHUNKED | HTTP_FLAG_HAVE_CLEN)) == (HTTP_FLAG_CHUNKED | HTTP_FLAG_HAVE_CLEN)) {
						pomlog(POMLOG_DEBUG "Ignoring Content-Length because transfer type is chunked");
						priv->info.flags &= ~HTTP_FLAG_HAVE_CLEN;
						priv->info.content_len = 0;
					}
					
					// If there is no payload
					if ( ((priv->info.flags & HTTP_FLAG_HAVE_CLEN) && !priv->info.content_len) ||
						// Or if the response is not supposed to contain any payload
						(priv->state == HTTP_RESPONSE && ((priv->info.last_err_code >= 100 && priv->info.last_err_code < 200) || priv->info.last_err_code == 204 || priv->info.last_err_code == 304)) ||
						
						// Or if its a query, forget about having CLEN
						(priv->state == HTTP_QUERY && (!(priv->info.flags & HTTP_FLAG_HAVE_CLEN)))
						
						) {
							// Process the event
							event_process_begin(priv->event, stack, stack_index);
							event_process_end(priv->event);
							priv->event = NULL;
						
							int old_state = priv->state;
							proto_http_conntrack_reset(s->ce);
							if (old_state == HTTP_QUERY) {
								priv->state = HTTP_RESPONSE_HEADER;
							} else {
								priv->state = HTTP_QUERY_HEADER;
							}
							return POM_OK;
					} 

					// There is some payload, switch to the right state and process the begining of the event
					priv->state++;
					event_process_begin(priv->event, stack, stack_index);

					continue;
				}


				char *colon = memchr(line, ':', len);
				if (!colon) {
					pomlog(POMLOG_DEBUG "Header line without colon");
					priv->state = HTTP_INVALID;
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


				struct ptype *data_val = event_data_item_add(priv->event, (priv->state == HTTP_QUERY ? proto_http_query_headers : proto_http_response_headers), name);
				if (!data_val) {
					free(name);
					free(value);
					return PROTO_ERR;
				}

				PTYPE_STRING_SETVAL_P(data_val, value);

				
				// Parse a few useful headers
				if (!(priv->info.flags & HTTP_FLAG_HAVE_CLEN) && !strcasecmp(name, "Content-Length")) {
					if (sscanf(value, "%zu", &priv->info.content_len) != 1)
						return PROTO_INVALID;
					priv->info.flags |= HTTP_FLAG_HAVE_CLEN;
				} else if (!(priv->info.flags & HTTP_FLAG_CHUNKED) && !strcasecmp(name, "Transfer-Encoding")) {
					if (!strcasecmp(value, "chunked"))
						priv->info.flags |= HTTP_FLAG_CHUNKED;
				}


				break;
			}

			case HTTP_BODY_QUERY: 
			case HTTP_BODY_RESPONSE : {

				unsigned int remaining_size = 0;
				void *pload = NULL;

				// If it was a HEAD request, we might think there is some payload
				// while there actually isn't any. Check for that
				if (priv->client_direction == s->direction) {
					packet_stream_parser_get_remaining(parser, &pload, &remaining_size);
					if (remaining_size >= strlen("HTTP/") && !strncasecmp(pload, "HTTP/", sizeof("HTTP/"))) {
						debug_http("Found reply to HEAD request");
						if (proto_http_conntrack_reset(s->ce) != POM_OK)
							return PROTO_ERR;
						priv->state = HTTP_RESPONSE_HEADER;
						break;
					}
				}

				if (priv->info.flags & HTTP_FLAG_CHUNKED) {
					if (!priv->info.chunk_len) {

						if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
							return PROTO_ERR;
						if (!line) // No more full line in this packet
							return PROTO_OK;

						char int_str[6] = {0};
						if (len >= sizeof(int_str) || !len) {
							pomlog(POMLOG_DEBUG "Invalid chunk size of len %u", len);
							priv->state = HTTP_INVALID;
							return PROTO_INVALID;
						}

						memcpy(int_str, line, len);
						if (sscanf(int_str, "%x", &priv->info.chunk_len) != 1) {
							pomlog(POMLOG_DEBUG "Unparseable chunk size provided : %s", int_str);
							priv->state = HTTP_INVALID;
							return PROTO_INVALID;
						}
					}

					packet_stream_parser_get_remaining(parser, &pload, &remaining_size);
					packet_stream_parser_empty(parser);
					unsigned int chunk_remaining = priv->info.chunk_len - priv->info.chunk_pos;
					s_next->pload = pload;
					if (remaining_size > chunk_remaining) {
						// There is the start of another chunk in this packet
						s_next->plen = chunk_remaining;
						remaining_size -= chunk_remaining;
						pload += chunk_remaining; if
						(remaining_size >= 2) {
							// Remove last CRLF
							remaining_size -= 2;
							pload += 2;
						}
						debug_http("entry %p, got %u bytes of chunked payload", s->ce, s_next->plen);
						
						priv->info.chunk_pos = 0;
						priv->info.chunk_len = 0;

						if (s_next->plen) {

							int res = core_process_multi_packet(stack, stack_index + 1, p);
							if (res == PROTO_ERR)
								return PROTO_ERR;

							packet_stream_parser_add_payload(parser, pload, remaining_size);
						} else {
							// This is the last chunk
							return PROTO_OK;
						}

						// Continue parsing the next chunk
						continue;
					} else {
						s_next->plen = remaining_size;
					}
					priv->info.chunk_pos += remaining_size;

				}  else {

					// Set the right payload in the next stack index
					packet_stream_parser_get_remaining(parser, &s_next->pload, &s_next->plen);
					packet_stream_parser_empty(parser);
					priv->info.content_pos += s_next->plen;
				}

				debug_http("entry %p, got %u bytes of payload", s->ce, s_next->plen);


				return PROTO_OK;

			}

			default:
				return PROTO_OK;
		}
	}


	return PROTO_OK;
}


static int proto_http_post_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct conntrack_entry *ce = stack[stack_index].ce;

	struct proto_http_conntrack_priv *priv = ce->priv;

	if (
		((priv->info.flags & HTTP_FLAG_HAVE_CLEN) && (priv->info.content_pos >= priv->info.content_len)) // End of payload reached
		|| ((priv->info.flags & HTTP_FLAG_CHUNKED) && !priv->info.chunk_len) // Last chunk was processed
		
		) {
		// Payload done
		event_process_end(priv->event);
		priv->event = NULL;

		if (priv->state == HTTP_BODY_QUERY) {
			proto_http_conntrack_reset(ce);
			priv->state = HTTP_RESPONSE_HEADER;

		} else { // HTTP_BODY_RESPONSE
			proto_http_conntrack_reset(ce);
			priv->state = HTTP_QUERY_HEADER;

		}

	}
	return PROTO_OK;
}

static int proto_http_conntrack_reset(struct conntrack_entry *ce) {

	struct proto_http_conntrack_priv *priv = ce->priv;

	debug_http("entry %p, reset", ce);
	
	priv->state = HTTP_QUERY_HEADER;
	memset(&priv->info, 0, sizeof(struct http_info));

	if (priv->event) {
		event_cleanup(priv->event);
		priv->event = NULL;
	}

	return POM_OK;
}

static int proto_http_conntrack_cleanup(struct conntrack_entry *ce) {

	struct proto_http_conntrack_priv *priv = ce->priv;
	if (!priv)
		return POM_OK;

	int i;
	for (i = 0; i < CT_DIR_TOT; i++) {
		if (priv->parser[i])
			packet_stream_parser_cleanup(priv->parser[i]);
	}

	if (priv->event) {
		if (priv->event->flags & EVENT_FLAG_PROCESS_BEGAN) {
			pomlog(POMLOG_DEBUG "Processing event on cleanup !");
			event_process_end(priv->event);
		} else {
			event_cleanup(priv->event);
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

	struct proto_http_priv *ppriv = ce->proto->priv;
	struct proto_http_conntrack_priv *priv = ce->priv;

	int tok_num = 0;
	char *token = line, *space = NULL;;
	unsigned int line_len = len;

	while (len) {
		space = memchr(token, ' ', len);
		
		size_t tok_len;
		if (space)
			tok_len = space - token;
		else
			tok_len = len;

		switch (tok_num) {
			case 0:
				
				if (priv->event) {
					pomlog(POMLOG_WARN "Internal error : http event still exist");
					event_cleanup(priv->event);
				}

				if (!strncasecmp(token, "HTTP/", strlen("HTTP/"))) {

					// Check the response direction
					if (priv->client_direction == CT_DIR_UNK) {
						priv->client_direction = direction;
					} else {
						if (priv->client_direction != direction) {
							debug_http("Received response in the wrong direction !");
							return PROTO_INVALID;
						}
					}

					priv->state = HTTP_RESPONSE;
					priv->event = event_alloc(ppriv->evt_response);
					if (!priv->event)
						return PROTO_ERR;

					char *request_proto = malloc(tok_len + 1);
					if (!request_proto) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(request_proto, token, tok_len);
					request_proto[tok_len] = 0;
					PTYPE_STRING_SETVAL_P(priv->event->data[proto_http_response_proto].value, request_proto);
				} else {

					priv->event = event_alloc(ppriv->evt_query);
					if (!priv->event)
						return POM_ERR;

					int i;
					for (i = 0; i < tok_len; i++) {
						if ((token[i]) < 'A' || (token[i] > 'Z' && token[i] < 'a') || (token[i] > 'z')) {
							// Definitely not a HTTP method
							return PROTO_INVALID;
						}
					}

					// Check the query direction
					if (priv->client_direction == CT_DIR_UNK) {
						priv->client_direction = CT_OPPOSITE_DIR(direction);
					} else {
						if (priv->client_direction != CT_OPPOSITE_DIR(direction)) {
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
					PTYPE_STRING_SETVAL_P(priv->event->data[proto_http_query_method].value, request_method);
					priv->state = HTTP_QUERY;
				}
				break;
			case 1:
				if (priv->state == HTTP_RESPONSE) {
					// Get the status code
					uint16_t err_code = 0;
					char errcode[4];
					errcode[3] = 0;
					strncpy(errcode, token, 3);
					if (sscanf(errcode, "%hu", &err_code) != 1 || err_code == 0) {
						pomlog(POMLOG_DEBUG "Invalid code in HTTP response");
						return PROTO_INVALID;
					}

					PTYPE_UINT16_SETVAL(priv->event->data[proto_http_response_status].value, err_code);
					priv->info.last_err_code = err_code;

				} else if (priv->state == HTTP_QUERY) {
					char *url = malloc(tok_len + 1);
					if (!url) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(url, token, tok_len);
					url[tok_len] = 0;
					PTYPE_STRING_SETVAL_P(priv->event->data[proto_http_query_url].value, url);

				}
				break;
			case 2:
				if (priv->state == HTTP_QUERY) {
					// This payload was identified as a possible query
					if (tok_len < strlen("HTTP/"))
						return PROTO_INVALID;
					if (strncasecmp(token, "HTTP/", strlen("HTTP/"))) {
						// Doesn't seem to be a valid HTTP version
						return PROTO_INVALID;
					}

					char *request_proto = malloc(tok_len + 1);
					if (!request_proto) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(request_proto, token, tok_len);
					request_proto[tok_len] = 0;
					PTYPE_STRING_SETVAL_P(priv->event->data[proto_http_query_proto].value, request_proto);

				}
				break;
			default:
				if (priv->state == HTTP_QUERY) {
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
		pomlog(POMLOG_DEBUG "Unable to parse the query/response");
		return PROTO_INVALID;
	}

	if (priv->state == HTTP_QUERY) {
		
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
		PTYPE_STRING_SETVAL_P(priv->event->data[proto_http_query_first_line].value, first_line);

		PTYPE_TIMESTAMP_SETVAL(priv->event->data[proto_http_query_start_time].value, p->ts);

		debug_http("entry %p, found query : \"%s\"", ce, first_line);

	} else {
		debug_http("entry %p, response with status %u", ce, priv->info.last_err_code);

		PTYPE_TIMESTAMP_SETVAL(priv->event->data[proto_http_response_start_time].value, p->ts);
	}

	return PROTO_OK;
}

