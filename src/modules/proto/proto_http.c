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
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>

#include "proto_http.h"

#include <string.h>
#include <stdio.h>


// ptype for fields value template
static struct ptype *ptype_string = NULL, *ptype_uint16 = NULL;

struct mod_reg_info* proto_http_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_http_mod_register;
	reg_info.unregister_func = proto_http_mod_unregister;

	return &reg_info;
}


static int proto_http_mod_register(struct mod_reg *mod) {

	ptype_string = ptype_alloc("string");
	ptype_uint16 = ptype_alloc("uint16");
	if (!ptype_string || !ptype_uint16)
		return POM_ERR;

	static struct conntrack_con_info_reg fields[PROTO_HTTP_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct conntrack_con_info_reg) * (PROTO_HTTP_FIELD_NUM + 1));
	fields[proto_http_field_host].name = "host";
	fields[proto_http_field_host].value_template = ptype_string;
	fields[proto_http_field_host].flags = CT_CONNTRACK_INFO_BIDIR;
	fields[proto_http_field_host].description = "Client and server host";
	fields[proto_http_field_first_line].name = "first_line";
	fields[proto_http_field_first_line].value_template = ptype_string;
	fields[proto_http_field_first_line].description = "First line of the request";
	fields[proto_http_field_err_code].name = "error_code";
	fields[proto_http_field_err_code].value_template = ptype_uint16;
	fields[proto_http_field_err_code].description = "Error code returned by the server";
	fields[proto_http_field_request_proto].name = "http_protocol";
	fields[proto_http_field_request_proto].flags = CT_CONNTRACK_INFO_BIDIR;
	fields[proto_http_field_request_proto].value_template = ptype_string;
	fields[proto_http_field_request_proto].description = "HTTP protocol version of the request (1.0 or 1.1)";
	fields[proto_http_field_request_method].name = "http_method";
	fields[proto_http_field_request_method].value_template = ptype_string;
	fields[proto_http_field_request_method].description = "HTTP method of the request (e.g. GET, POST, PROPFIND)";
	fields[proto_http_field_url].name = "url";
	fields[proto_http_field_url].value_template = ptype_string;
	fields[proto_http_field_url].description = "Requested URL";
	fields[proto_http_field_headers].name = "headers";
	fields[proto_http_field_headers].value_template = ptype_string;
	fields[proto_http_field_headers].flags = CT_CONNTRACK_INFO_BIDIR | CT_CONNTRACK_INFO_LIST | CT_CONNTRACK_INFO_LIST_FREE_KEY;
	fields[proto_http_field_headers].description = "HTTP headers";
	fields[proto_http_field_request_dir].name = "request_dir";
	fields[proto_http_field_request_dir].value_template = ptype_uint16;
	fields[proto_http_field_request_dir].description = "Request direction, indicates the drection of the server";
	


	static struct proto_reg_info proto_http;
	memset(&proto_http, 0, sizeof(struct proto_reg_info));
	proto_http.name = "http";
	proto_http.api_ver = PROTO_API_VER;
	proto_http.mod = mod;

	proto_http.ct_info.default_table_size = 1; // No hashing done here
	proto_http.ct_info.cleanup_handler = proto_http_conntrack_cleanup;
	proto_http.ct_info.con_info = fields;

	proto_http.process = proto_http_process;

	if (proto_register(&proto_http) == POM_OK)
		return POM_OK;

	proto_http_mod_unregister();
	return POM_ERR;

}

static int proto_http_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_prev = &stack[stack_index - 1];

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

		s->ce->priv = priv;

	}

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

				int res = proto_http_parse_query_response(s->ce, line, len, s->direction);
				if (res == PROTO_INVALID) {
					priv->state = HTTP_INVALID;
					return PROTO_INVALID;
				}

				PTYPE_UINT16_SETVAL(s->ce->con_info[proto_http_field_request_dir].val[0].value, s->direction);
				s->ce->con_info[proto_http_field_request_dir].val[0].set = 1;
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
					//parsed headers
			
					if ((priv->state == HTTP_QUERY && !(priv->info.flags & HTTP_FLAG_HAVE_CLEN)) ||
						((priv->info.flags & HTTP_FLAG_HAVE_CLEN) && !priv->info.content_len)) {
						// Request without body
						priv->state = (priv->state == HTTP_QUERY ? HTTP_RESPONSE_HEADER : HTTP_QUERY_HEADER); // Switch to the corresponding expected header
						return PROTO_OK;
					}
					
					priv->state++; // Switch to corresponding BODY state
					printf("Done parsing query headers\n");
					if (conntrack_con_info_process(stack, stack_index) != POM_OK)
						return PROTO_ERR;
					continue;
				}

				char *colon = memchr(line, ':', len);
				if (!colon) {
					pomlog(POMLOG_DEBUG "Header line without coma");
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

				struct ptype *info_val = conntrack_con_info_lst_add(s->ce, proto_http_field_headers, name, s->direction);
				if (!info_val) {
					free(name);
					free(value);
					return PROTO_ERR;
				}

				PTYPE_STRING_SETVAL_P(info_val, value);

				
				// Parse a few useful headers
				if (!(priv->info.flags & HTTP_FLAG_HAVE_CLEN) && !strcasecmp(name, "Content-Length")) {
					if (sscanf(value, "%u", &priv->info.content_len) != 1)
						return PROTO_INVALID;
					priv->info.flags |= HTTP_FLAG_HAVE_CLEN;
				} else if (!(priv->info.flags & (HTTP_FLAG_GZIP|HTTP_FLAG_DEFLATE)) && !strcasecmp(name, "Content-Encoding")) {
					if (!strcasecmp(value, "gzip"))
						priv->info.flags |= HTTP_FLAG_GZIP;
					else if (!strcasecmp(value, "deflate"))
						priv->info.flags |= HTTP_FLAG_DEFLATE;
				} else if (!(priv->info.flags & HTTP_FLAG_CHUNKED) && !strcasecmp(name, "Transfer-Encoding")) {
					if (!strcasecmp(value, "chunked"))
						priv->info.flags |= HTTP_FLAG_CHUNKED;
				}


				break;
			}

			case HTTP_BODY_QUERY: 
			case HTTP_BODY_RESPONSE : {

				// Add the remaining buffer if any
				unsigned int len = 0;
				void *pload = NULL;
				packet_stream_parser_get_remaining(parser, &pload, &len);
				if (len) {
					priv->info.content_pos += len;
				}

				if ((priv->info.flags & HTTP_FLAG_HAVE_CLEN) && (priv->info.content_pos >= priv->info.content_len)) {
					// Payload done
					priv->state = (priv->state == HTTP_BODY_QUERY ? HTTP_RESPONSE_HEADER : HTTP_QUERY_HEADER);
					return PROTO_OK;
				}
			}

			default:
				return PROTO_OK;
		}
	}


	return PROTO_OK;
}

static int proto_http_conntrack_reset(struct conntrack_entry *ce) {

	struct proto_http_conntrack_priv *priv = ce->priv;

	priv->state = HTTP_QUERY_HEADER;
	memset(&priv->info, 0, sizeof(struct http_info));
	return conntrack_con_info_reset(ce);
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
	
	free(priv);

	return POM_OK;

}

static int proto_http_mod_unregister() {

	int res = proto_unregister("http");

	if (ptype_string) {
		ptype_cleanup(ptype_string);
		ptype_string = NULL;
	}

	if (ptype_uint16) {
		ptype_cleanup(ptype_uint16);
		ptype_uint16 = NULL;
	}
		

	return res;
}


int proto_http_parse_query_response(struct conntrack_entry *ce, char *line, unsigned int len, int direction) {

	if (len < strlen("HTTP/"))
		return PROTO_INVALID;

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
				if (!strncasecmp(token, "HTTP/", strlen("HTTP/"))) {
					priv->state = HTTP_RESPONSE;
					char *request_proto = malloc(tok_len + 1);
					if (!request_proto) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(request_proto, token, tok_len);
					request_proto[tok_len] = 0;
					PTYPE_STRING_SETVAL_P(ce->con_info[proto_http_field_request_proto].val[direction].value, request_proto);
					ce->con_info[proto_http_field_request_proto].val[direction].set = 1;
				} else {
					int i;
					for (i = 0; i < tok_len; i++) {
						if ((token[i]) < 'A' || (token[i] > 'Z' && token[i] < 'a') || (token[i] > 'z')) {
							// Definitely not a HTTP method
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
					PTYPE_STRING_SETVAL_P(ce->con_info[proto_http_field_request_method].val[0].value, request_method);
					ce->con_info[proto_http_field_request_method].val[0].set = 1;
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

					PTYPE_UINT16_SETVAL(ce->con_info[proto_http_field_err_code].val[0].value, err_code);
					ce->con_info[proto_http_field_err_code].val[0].set = 1;

				} else if (priv->state == HTTP_QUERY) {
					char *url = malloc(tok_len + 1);
					if (!url) {
						pom_oom(tok_len + 1);
						return PROTO_ERR;
					}
					memcpy(url, token, tok_len);
					url[tok_len] = 0;
					PTYPE_STRING_SETVAL_P(ce->con_info[proto_http_field_url].val[0].value, url);
					ce->con_info[proto_http_field_url].val[0].set = 1;

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
					PTYPE_STRING_SETVAL_P(ce->con_info[proto_http_field_request_proto].val[direction].value, request_proto);
					ce->con_info[proto_http_field_request_proto].val[direction].set = 1;


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

	if (tok_num < 3) {
		pomlog(POMLOG_DEBUG "Unable to parse the query/response");
		return PROTO_INVALID;
	}

	if (priv->state == HTTP_QUERY) {
		
		char *first_line = malloc(line_len + 1);
		if (!first_line) {
			pom_oom(line_len + 1);
			return PROTO_ERR;
		}
		memcpy(first_line, line, line_len);
		first_line[line_len] = 0;
		PTYPE_STRING_SETVAL_P(ce->con_info[proto_http_field_first_line].val[0].value, first_line);
		ce->con_info[proto_http_field_first_line].val[0].set = 1;

	}

	return PROTO_OK;
}

