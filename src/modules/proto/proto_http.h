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

#define HTTP_HEADER		1 ///< Looking for a header
#define HTTP_QUERY		2 ///< This is a query
#define HTTP_RESPONSE		3 ///< This is a response
#define HTTP_BODY_QUERY		4 ///< Handling the body
#define HTTP_BODY_RESPONSE	5 ///< Handling the body of a response (e.g. POST)
#define HTTP_INVALID		9 ///< Invalid HTTP message, will discard the rest of the connection

#define HTTP_MAX_HEADER_LINE	4096

#define PROTO_HTTP_FIELD_NUM	0

struct http_header {
	
	char *name;
	char *value;
	int type; // either HTTP_QUERY or HTTP_RESPONSE

};

struct http_info {
	
	struct http_header *header;
	unsigned int headers_num;
	unsigned int err_code;
//	unsigned int content_len, content_pos;
	unsigned int flags;


};

struct proto_http_conntrack_priv {

	struct packet_stream_parser *parser[CT_DIR_TOT];
	struct http_info info;
	unsigned int state;
};

struct mod_reg_info* proto_http_reg_info();
static int proto_http_mod_register(struct mod_reg *mod);
static int proto_http_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_http_conntrack_cleanup(struct conntrack_entry *ce);
static int proto_http_mod_unregister();

int proto_http_parse_query_response(struct proto_http_conntrack_priv *priv, char *line, unsigned int len);

#endif
