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

#ifndef __PROTO_HTTP_H__
#define __PROTO_HTTP_H__

#include <pom-ng/conntrack.h>
#include <pom-ng/packet.h>
#include <pom-ng/proto_http.h>

#define HTTP_QUERY_HEADER	1 ///< Looking for the query line
#define HTTP_QUERY		2 ///< This is a query
#define HTTP_BODY_QUERY		3 ///< Handling the body
#define HTTP_RESPONSE_HEADER	4 ///< Looking for the response line
#define HTTP_RESPONSE		5 ///< This is a response
#define HTTP_BODY_RESPONSE	6 ///< Handling the body of a response (e.g. POST)
#define HTTP_INVALID		9 ///< Invalid HTTP message, will discard the rest of the connection

#define HTTP_FLAG_HAVE_CLEN	0x01
#define HTTP_FLAG_CHUNKED	0x04

#define HTTP_MAX_HEADER_LINE	4096


struct http_info {
	size_t content_len, content_pos;
	unsigned int chunk_pos, chunk_len;
	unsigned int flags;
	unsigned int last_err_code;
};

struct proto_http_priv {
	struct ptype *ptype_string;
	struct ptype *ptype_uint16;
	struct ptype *ptype_timestamp;

	struct event_reg *evt_query;
	struct event_reg *evt_response;

};

struct proto_http_conntrack_priv {

	struct packet_stream_parser *parser[POM_DIR_TOT];
	struct http_info info;
	unsigned int state;
	int client_direction;
	struct event *event;
};

struct mod_reg_info* proto_http_reg_info();
static int proto_http_mod_register(struct mod_reg *mod);
static int proto_http_init(struct proto *proto, struct registry_instance *ri);
int proto_http_cleanup(struct proto *proto);
static int proto_http_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_http_post_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_http_conntrack_reset(struct conntrack_entry *ce);
static int proto_http_conntrack_cleanup(struct conntrack_entry *ce);
static int proto_http_mod_unregister();

int proto_http_parse_query_response(struct conntrack_entry *ce, char *line, unsigned int len, int direction, struct packet *p);

#endif
