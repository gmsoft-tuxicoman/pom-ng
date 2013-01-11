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

#ifndef __PROTO_HTTP_H__
#define __PROTO_HTTP_H__

#include <pom-ng/conntrack.h>
#include <pom-ng/packet.h>
#include <pom-ng/proto_http.h>

#define HTTP_STATE_FIRST_LINE	1 // First line of a query/response
#define HTTP_STATE_HEADERS	2 // Receiving the headers of the query/response
#define HTTP_STATE_BODY		3 // Receiving the body (payload) of a query/response

#define HTTP_FLAG_HAVE_CLEN	0x01
#define HTTP_FLAG_CHUNKED	0x04
#define HTTP_FLAG_LAST_CHUNK	0x08

#define HTTP_MAX_HEADER_LINE	4096


struct http_info {
	size_t content_len, content_pos;
	unsigned int chunk_pos, chunk_len;
	unsigned int flags;
	unsigned int last_err_code;
};

struct proto_http_priv {

	struct event_reg *evt_query;
	struct event_reg *evt_response;

};

struct proto_http_conntrack_priv {

	struct packet_stream_parser *parser[POM_DIR_TOT];
	struct http_info info[POM_DIR_TOT];
	unsigned int state[POM_DIR_TOT];
	struct event *event[POM_DIR_TOT];
	int client_direction;
	int is_invalid;
};

struct mod_reg_info* proto_http_reg_info();
static int proto_http_mod_register(struct mod_reg *mod);
static int proto_http_init(struct proto *proto, struct registry_instance *ri);
int proto_http_cleanup(void *proto_priv);
static int proto_http_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_http_post_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_http_conntrack_reset(struct conntrack_entry *ce, int direction);
static int proto_http_conntrack_cleanup(void *ce_priv);
static int proto_http_mod_unregister();

int proto_http_parse_query_response(struct conntrack_entry *ce, char *line, unsigned int len, int direction, struct packet *p);

#endif
