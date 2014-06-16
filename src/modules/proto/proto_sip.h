/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __PROTO_SIP_H__
#define __PROTO_SIP_H__

struct proto_sip_priv {

	struct event_reg *evt_sip_req;
	struct event_reg *evt_sip_rsp;

};

#define PROTO_SIP_EVT_MSG_DATA_COUNT 15

enum {
	proto_sip_req_method = 0,
	proto_sip_req_uri
};

enum {
	proto_sip_rsp_status = 0,
	proto_sip_rsp_reason
};

enum {
	proto_sip_msg_first_line = 2,
	proto_sip_msg_call_id,
	proto_sip_msg_cseq_num,
	proto_sip_msg_cseq_method,
	proto_sip_msg_content_type,
	proto_sip_msg_content_len,
	proto_sip_msg_from_display,
	proto_sip_msg_from_uri,
	proto_sip_msg_from_tag,
	proto_sip_msg_to_display,
	proto_sip_msg_to_uri,
	proto_sip_msg_to_tag,
	proto_sip_msg_other_headers,
};

#define SIP_STATE_FIRST_LINE	1 // First line of a query/response
#define SIP_STATE_HEADERS	2 // Receving the haders
#define SIP_STATE_BODY		3 // Receving the body

#define SIP_MAX_HEADER_LINE	4096

struct proto_sip_conntrack_priv {

	struct packet_stream_parser *parser[POM_DIR_TOT];
	unsigned int state[POM_DIR_TOT];
	struct event *event[POM_DIR_TOT];
	int is_invalid;
	size_t content_len[POM_DIR_TOT];
	size_t content_pos[POM_DIR_TOT];

};

struct proto_sip_header_handler {
	char *header;
	int (*handler) (struct data *data, char *value, size_t value_len, int field_id);
	int field_id;
};

static int proto_sip_mod_register(struct mod_reg *mod);
static int proto_sip_mod_unregister();

static int proto_sip_init(struct proto *proto, struct registry_instance *ri);
static int proto_sip_cleanup(void *proto_priv);

static int proto_sip_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_sip_post_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);

static int proto_sip_conntrack_reset(struct conntrack_entry *ce, int direction);

static int proto_sip_parse_request_response(struct conntrack_entry *ce, char *line, unsigned int len, int direction, struct packet *p);

static int proto_sip_parse_cseq(struct data *data, char *value, size_t value_len, int field_id);
static int proto_sip_parse_string_header(struct data *data, char *value, size_t value_len, int field_id);
static int proto_sip_parse_content_len(struct data *data, char *value, size_t value_len, int field_id);
static int proto_sip_parse_to_from(struct data *data, char *value, size_t value_len, int field_id);

static int proto_sip_conntrack_cleanup(void *ce_priv);

#endif
