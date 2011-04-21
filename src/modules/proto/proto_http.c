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

#include "proto_http.h"

#include <string.h>
#include <stdio.h>


// ptype for fields value template
static struct ptype *ptype_uint8 = NULL;

struct mod_reg_info* proto_http_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_http_mod_register;
	reg_info.unregister_func = proto_http_mod_unregister;

	return &reg_info;
}


static int proto_http_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_HTTP_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_HTTP_FIELD_NUM + 1));

	static struct proto_reg_info proto_http;
	memset(&proto_http, 0, sizeof(struct proto_reg_info));
	proto_http.name = "http";
	proto_http.api_ver = PROTO_API_VER;
	proto_http.mod = mod;
	proto_http.pkt_fields = fields;

	proto_http.ct_info.default_table_size = 1; // No hashing done here
	proto_http.ct_info.cleanup_handler = proto_http_conntrack_cleanup;

	proto_http.process = proto_http_process;

	if (proto_register(&proto_http) == POM_OK)
		return POM_OK;

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
		priv->state = HTTP_HEADER;

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
			case HTTP_HEADER: {
				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
					return PROTO_ERR;

				if (!line) // No more full lines in this packet
					return PROTO_OK;

				int res = proto_http_parse_query_response(priv, line, len);
				if (res == PROTO_INVALID) {
					priv->state = HTTP_INVALID;
					return PROTO_INVALID;
				}
					

				break;
			}
			case HTTP_QUERY: {
				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
					return PROTO_ERR;
				if (!line) // No more full lines in this packet
					return PROTO_OK;

				if (!len) {
					//parsed headers
					priv->state = HTTP_BODY_QUERY;
					printf("Done parsing query headers\n");
					return PROTO_OK;
				}
				char *tmp = malloc(len + 1);
				memset(tmp, 0, len + 1);
				strncpy(tmp, line, len);
				printf("Got query header : %s\n", tmp);
				free(tmp);
				break;
			}
			case HTTP_BODY_QUERY: {
				return PROTO_OK;
			}

			case HTTP_RESPONSE: {
				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
					return PROTO_ERR;
				if (!line) // No more full lines in this packet
					return PROTO_OK;

				if (!len) {
					//parsed headers
					priv->state = HTTP_BODY_RESPONSE;
					printf("Done parsing response headers\n");
					return PROTO_OK;
				}
				char *tmp = malloc(len + 1);
				memset(tmp, 0, len + 1);
				strncpy(tmp, line, len);
				printf("Got response header : %s\n", tmp);
				free(tmp);
				break;
			}
			default:
				return PROTO_OK;
		}
	}


	return PROTO_OK;
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

	ptype_cleanup(ptype_uint8);
	ptype_uint8 = NULL;

	return res;
}


int proto_http_parse_query_response(struct proto_http_conntrack_priv *priv, char *line, unsigned int len) {

	if (len < strlen("HTTP/"))
		return PROTO_INVALID;

	int tok_num = 0;
	char *token = line, *space = NULL;;

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
				} else {
					int i;
					for (i = 0; i < tok_len; i++) {
						if ((token[i]) < 'A' || (token[i] > 'Z' && token[i] < 'a') || (token[i] > 'z')) {
							// Definitely not a HTTP method
							return PROTO_INVALID;
						}
					}
					priv->state = HTTP_QUERY;
				}
				break;
			case 1:
				if (priv->state == HTTP_RESPONSE) {
					// Get the status code
					unsigned int err_code = 0;
					if (sscanf(token, "%u", &err_code) != 1 || err_code == 0) {
						pomlog(POMLOG_DEBUG "Invalid code in HTTP response");
						return PROTO_INVALID;
					}

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

					if (priv->info.headers_num > 0) {
						// New query but headers are present -> reset
						priv->state = HTTP_QUERY;
						// FIXME need to actually do the cleanup :)
					}
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

	return PROTO_OK;
}
