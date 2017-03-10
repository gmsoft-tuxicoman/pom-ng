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

#include <pom-ng/proto.h>
#include <pom-ng/event.h>
#include <pom-ng/core.h>
#include <pom-ng/pload.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/ptype_uint64.h>

#include "proto_sip.h"

#include <stdio.h>


struct proto_sip_header_handler {
	char *header;
	int (*handler) (struct data *data, char *value, size_t value_len, int field_id);
	int field_id;
} proto_sip_header_handlers[] = {

	{ "cseq", proto_sip_parse_cseq, proto_sip_msg_cseq_num },
	{ "call-id", proto_sip_parse_string_header, proto_sip_msg_call_id },
	{ "via", proto_sip_parse_via, proto_sip_msg_top_branch },
	{ "i", proto_sip_parse_string_header, proto_sip_msg_call_id },
	{ "content-type", proto_sip_parse_string_header, proto_sip_msg_content_type },
	{ "c", proto_sip_parse_string_header, proto_sip_msg_content_type },
	{ "content-length", proto_sip_parse_content_len, proto_sip_msg_content_len },
	{ "l", proto_sip_parse_content_len, proto_sip_msg_content_len },
	{ "to", proto_sip_parse_to_from, proto_sip_msg_to_display },
	{ "t", proto_sip_parse_to_from, proto_sip_msg_to_display },
	{ "from", proto_sip_parse_to_from, proto_sip_msg_from_display },
	{ "f", proto_sip_parse_to_from, proto_sip_msg_from_display },


	{ NULL, NULL},
};

struct mod_reg_info* proto_sip_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_sip_mod_register;
	reg_info.unregister_func = proto_sip_mod_unregister;
	reg_info.dependencies = "proto_udp, ptype_string, ptype_uint16, ptype_uint32, ptype_uint64";

	return &reg_info;
}


static int proto_sip_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_sip = { 0 };
	proto_sip.name = "sip";
	proto_sip.api_ver = PROTO_API_VER;
	proto_sip.mod = mod;

	static struct conntrack_info ct_info = { 0 };

	ct_info.default_table_size = 1; // No hashing done here
	ct_info.cleanup_handler = proto_sip_conntrack_cleanup;
	proto_sip.ct_info = &ct_info;
	
	proto_sip.init = proto_sip_init;
	proto_sip.process = proto_sip_process;
	proto_sip.post_process = proto_sip_post_process;
	proto_sip.cleanup = proto_sip_cleanup;

	if (proto_register(&proto_sip) == POM_OK)
		return POM_OK;

	proto_sip_mod_unregister();
	return POM_ERR;

}

static int proto_sip_mod_unregister() {

	return proto_unregister("sip");

}

static int proto_sip_init(struct proto *proto, struct registry_instance *ri) {

	if (proto_number_register("udp", 5060, proto) != POM_OK)
		return POM_ERR;

	if (proto_number_register("tcp", 5060, proto) != POM_OK)
		return POM_ERR;

	struct proto_sip_priv *priv = malloc(sizeof(struct proto_sip_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_sip_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_sip_priv));

	proto_set_priv(proto, priv);

	static struct data_item_reg evt_req_data_items[PROTO_SIP_EVT_MSG_DATA_COUNT] = { { 0 } };
	evt_req_data_items[proto_sip_req_method].name = "method";
	evt_req_data_items[proto_sip_req_method].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_req_uri].name = "uri";
	evt_req_data_items[proto_sip_req_uri].value_type = ptype_get_type("string");

	evt_req_data_items[proto_sip_msg_first_line].name = "fist_line";
	evt_req_data_items[proto_sip_msg_first_line].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_call_id].name = "call_id";
	evt_req_data_items[proto_sip_msg_call_id].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_top_branch].name = "top_branch";
	evt_req_data_items[proto_sip_msg_top_branch].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_cseq_num].name = "cseq_num";
	evt_req_data_items[proto_sip_msg_cseq_num].value_type = ptype_get_type("uint32");
	evt_req_data_items[proto_sip_msg_cseq_method].name = "cseq_method";
	evt_req_data_items[proto_sip_msg_cseq_method].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_content_type].name = "content_type";
	evt_req_data_items[proto_sip_msg_content_type].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_content_len].name = "content_length";
	evt_req_data_items[proto_sip_msg_content_len].value_type = ptype_get_type("uint64");
	evt_req_data_items[proto_sip_msg_from_display].name = "from_display";
	evt_req_data_items[proto_sip_msg_from_display].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_from_uri].name = "from_uri";
	evt_req_data_items[proto_sip_msg_from_uri].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_from_tag].name = "from_tag";
	evt_req_data_items[proto_sip_msg_from_tag].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_to_display].name = "to_display";
	evt_req_data_items[proto_sip_msg_to_display].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_to_uri].name = "to_uri";
	evt_req_data_items[proto_sip_msg_to_uri].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_to_tag].name = "to_tag";
	evt_req_data_items[proto_sip_msg_to_tag].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_other_headers].name = "other_headers";
	evt_req_data_items[proto_sip_msg_other_headers].value_type = ptype_get_type("string");
	evt_req_data_items[proto_sip_msg_other_headers].flags = DATA_REG_FLAG_LIST;

	static struct data_reg evt_req_data = {
		.items = evt_req_data_items,
		.data_count = PROTO_SIP_EVT_MSG_DATA_COUNT
	};

	static struct event_reg_info proto_sip_evt_req = { 0 };
	proto_sip_evt_req.source_name = "proto_sip";
	proto_sip_evt_req.source_obj = proto;
	proto_sip_evt_req.name = "sip_req";
	proto_sip_evt_req.description = "SIP request";
	proto_sip_evt_req.data_reg = &evt_req_data;
	proto_sip_evt_req.flags = EVENT_REG_FLAG_PAYLOAD;

	priv->evt_sip_req = event_register(&proto_sip_evt_req);
	if (!priv->evt_sip_req)
		goto err;

	static struct data_item_reg evt_rsp_data_items[PROTO_SIP_EVT_MSG_DATA_COUNT] = { { 0 } };
	// Besides the first two items, everything is the same
	memcpy(&evt_rsp_data_items, &evt_req_data_items, sizeof(evt_rsp_data_items));
	evt_rsp_data_items[proto_sip_rsp_status].name = "status";
	evt_rsp_data_items[proto_sip_rsp_status].value_type = ptype_get_type("uint16");
	evt_rsp_data_items[proto_sip_rsp_reason].name = "reason";
	evt_rsp_data_items[proto_sip_rsp_reason].value_type = ptype_get_type("string");


	static struct data_reg evt_rsp_data = {
		.items = evt_rsp_data_items,
		.data_count = PROTO_SIP_EVT_MSG_DATA_COUNT
	};

	static struct event_reg_info proto_sip_evt_rsp = { 0 };
	proto_sip_evt_rsp.source_name = "proto_sip";
	proto_sip_evt_rsp.source_obj = proto;
	proto_sip_evt_rsp.name = "sip_rsp";
	proto_sip_evt_rsp.description = "SIP response";
	proto_sip_evt_rsp.data_reg = &evt_rsp_data;
	proto_sip_evt_rsp.flags = EVENT_REG_FLAG_PAYLOAD;

	priv->evt_sip_rsp = event_register(&proto_sip_evt_rsp);
	if (!priv->evt_sip_rsp)
		goto err;

	priv->proto_udp = proto_get("udp");
	if (!priv->proto_udp) {
		pomlog(POMLOG_ERR "Could not find proto UDP");
		goto err;
	}

	priv->p_udp_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!priv->p_udp_timeout)
		goto err;

	struct registry_param *p = registry_new_param("udp_timeout", "300", priv->p_udp_timeout, "Timeout for SIP over udp connections", 0);
	if (proto_add_param(proto, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}


	return POM_OK;
err:
	proto_sip_cleanup(priv);
	return POM_ERR;
}

static int proto_sip_cleanup(void *proto_priv) {

	if (!proto_priv)
		return POM_OK;

	struct proto_sip_priv *priv = proto_priv;
	if (priv->evt_sip_req)
		event_unregister(priv->evt_sip_req);

	if (priv->evt_sip_rsp)
		event_unregister(priv->evt_sip_rsp);

	if (priv->p_udp_timeout)
		ptype_cleanup(priv->p_udp_timeout);

	free(priv);

	return POM_OK;
}

static int proto_sip_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK) {
		pomlog(POMLOG_ERR "Could not get conntrack entry");
		return PROTO_ERR;
	}

	int res = PROTO_OK;

	struct proto_sip_conntrack_priv *priv = s->ce->priv;
	if (!priv) {
		priv = malloc(sizeof(struct proto_sip_conntrack_priv));
		if (!priv) {
			pom_oom(sizeof(struct proto_sip_conntrack_priv));
			res = PROTO_ERR;
			goto end;
		}
		memset(priv, 0, sizeof(struct proto_sip_conntrack_priv));
		priv->state[POM_DIR_FWD] = SIP_STATE_FIRST_LINE;
		priv->state[POM_DIR_REV] = SIP_STATE_FIRST_LINE;

		s->ce->priv = priv;

	}

	if (priv->is_invalid) {
		res = PROTO_INVALID;
		goto end;
	}

	struct proto_sip_priv *ppriv = proto_priv;
	if (stack[stack_index - 1].proto == ppriv->proto_udp) {
		if (conntrack_delayed_cleanup(s->ce, *PTYPE_UINT32_GETVAL(ppriv->p_udp_timeout), p->ts) != POM_OK) {
			res = PROTO_ERR;
			goto end;
		}
	}

	if (!priv->parser[s->direction]) {
		priv->parser[s->direction] = packet_stream_parser_alloc(SIP_MAX_HEADER_LINE, 0);
		if (!priv->parser[s->direction]) {
			res = PROTO_ERR;
			goto end;
		}
	}

	struct packet_stream_parser *parser = priv->parser[s->direction];
	if (packet_stream_parser_add_payload(parser, s->pload, s->plen) != POM_OK) {
		res = PROTO_ERR;
		goto end;
	}

	char *line = NULL;
	size_t len = 0;

	while (1) {
		
		switch (priv->state[s->direction]) {
			case SIP_STATE_FIRST_LINE:
				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK) {
					res = PROTO_ERR;
					goto end;
				}

				if (!line) // No more full lines in this packet
					goto end;

				if (!len) {
					// Ignore empty lines here
					continue;
				}

				res = proto_sip_parse_request_response(s->ce, line, len, s->direction, p);
				if (res != POM_OK)
					goto end;
				break;

			case SIP_STATE_HEADERS: 
				if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK) {
					res = PROTO_ERR;
					goto end;
				}

				if (!line) // No more full lines in this packet
					goto end;
				
				struct data *evt_data = event_get_data(priv->event[s->direction]);

				if (!len) {
					// Headers parsed
					if (data_is_set(evt_data[proto_sip_msg_content_len])) {
						priv->content_len[s->direction] = *PTYPE_UINT64_GETVAL(evt_data[proto_sip_msg_content_len].value);

						if (priv->content_len[s->direction] > 0 && priv->event[s->direction] && event_has_listener(event_get_reg(priv->event[s->direction]))) {
							priv->pload[s->direction] = pload_alloc(priv->event[s->direction], 0);
							if (!priv->pload[s->direction]) {
								res = PROTO_ERR;
								goto end;
							}

							if (data_is_set(evt_data[proto_sip_msg_content_type]))
								pload_set_mime_type(priv->pload[s->direction], PTYPE_STRING_GETVAL(evt_data[proto_sip_msg_content_type].value));
						}
					}
					priv->state[s->direction]++;
					event_process_begin(priv->event[s->direction], stack, stack_index, p->ts);
					continue;
				}

				char *colon = memchr(line, ':', len);
				if (!colon) {
					pomlog(POMLOG_DEBUG "Header line without colon");
					res = PROTO_INVALID;
					goto end;
				}

				unsigned int name_len = colon - line;

				for (name_len = colon - line; name_len > 1 && line[name_len - 1] == ' '; name_len--);


				colon++;
				while (colon < line + len && *colon == ' ')
					colon++;

				unsigned int value_len = len - (colon - line);
				
			

				int i;
				for (i = 0; proto_sip_header_handlers[i].header; i++) {
					if (!data_is_set(evt_data[proto_sip_header_handlers[i].field_id]) && !strncasecmp(proto_sip_header_handlers[i].header, line, name_len)) {
						res = (proto_sip_header_handlers[i].handler) (evt_data, colon, value_len, proto_sip_header_handlers[i].field_id);
						if (res != PROTO_OK)
							goto end;
						break;
					}

				}
				if (!proto_sip_header_handlers[i].header || proto_sip_header_handlers[i].field_id == proto_sip_msg_top_branch) {
					// Add to other headers if not parser or if it's the via header

					char *name = strndup(line, name_len);
					if (!name) {
						pom_oom(name_len + 1);
						res = PROTO_ERR;
						goto end;
					}

					struct ptype *data_val = event_data_item_add(priv->event[s->direction], proto_sip_msg_other_headers, name);
					if (!data_val) {
						free(name);
						res = PROTO_ERR;
						goto end;
					}

					PTYPE_STRING_SETVAL_N(data_val, colon, value_len);
				}

				break;

			case SIP_STATE_BODY:
				packet_stream_parser_get_remaining(parser, &s_next->pload, &s_next->plen);
				
				size_t pload_remaining = priv->content_len[s->direction] - priv->content_pos[s->direction];
				if (pload_remaining < s_next->plen) {

					if (priv->pload[s->direction]) {
						if (pload_append(priv->pload[s->direction], s_next->pload, pload_remaining) != POM_OK) {
							res = PROTO_ERR;
							goto end;
						}
					}

					if (packet_stream_parser_skip_bytes(parser, pload_remaining) != POM_OK) {
						pomlog(POMLOG_DEBUG "Error while skipping %u bytes from the stream", pload_remaining);
						res = PROTO_INVALID;
						goto end;
					}

					s_next->plen = pload_remaining;
					priv->content_pos[s->direction] = priv->content_len[s->direction];

					if (core_process_multi_packet(stack, stack_index + 1, p) == PROTO_ERR) {
						res = PROTO_ERR;
						goto end;
					}

					if (proto_sip_post_process(NULL, p, stack, stack_index) != POM_OK) {
						res = PROTO_ERR;
						goto end;
					}

				} else {
					if (priv->pload[s->direction]) {
						if (pload_append(priv->pload[s->direction], s_next->pload, s_next->plen) != POM_OK) {
							res = PROTO_ERR;
							goto end;
						}
					}
					packet_stream_parser_empty(parser);
					priv->content_pos[s->direction] += s_next->plen;
					goto end;
				}

				break;

		}

	}

end:
	if (res == PROTO_INVALID) {
		priv->is_invalid = 1;
	}

	if (res != PROTO_OK) {
		proto_sip_conntrack_reset(s->ce, s->direction);
		conntrack_unlock(s->ce);
	}

	return res;
}

static int proto_sip_post_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct conntrack_entry *ce = stack[stack_index].ce;
	int direction = stack[stack_index].direction;

	struct proto_sip_conntrack_priv *priv = ce->priv;
	if ((priv->state[direction] == SIP_STATE_BODY) && (priv->content_pos[direction] >= priv->content_len[direction])) {

		if (priv->pload[direction]) {
			pload_end(priv->pload[direction]);
			priv->pload[direction] = NULL;
		}


		event_process_end(priv->event[direction]);
		priv->event[direction] = NULL;

		proto_sip_conntrack_reset(ce, direction);
	}

	// If proto_priv is NULL, it was called by proto_sip_process and we must not unlock the conntrack
	if (proto_priv)
		conntrack_unlock(ce);

	return PROTO_OK;
}

static int proto_sip_conntrack_reset(struct conntrack_entry *ce, int direction) {

	struct proto_sip_conntrack_priv *priv = ce->priv;

	priv->state[direction] = SIP_STATE_FIRST_LINE;
	priv->content_len[direction] = 0;
	priv->content_pos[direction] = 0;

	if (priv->pload[direction]) {
		pload_end(priv->pload[direction]);
		priv->pload[direction] = NULL;
	}

	if (priv->event[direction]) {
		event_cleanup(priv->event[direction]);
		priv->event[direction] = NULL;
	}

	return POM_OK;
}

static int proto_sip_parse_request_response(struct conntrack_entry *ce, char *line, unsigned int len, int direction, struct packet *p) {

	if (len < strlen("SIP/2.0"))
		return PROTO_INVALID;

	struct proto_sip_priv *ppriv = proto_get_priv(ce->proto);
	struct proto_sip_conntrack_priv *priv = ce->priv;

	int tok_num = 0;
	char *token = line, *space = NULL;
	unsigned int line_len = len;


	int is_req = 0;

	struct data *evt_data = NULL;

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
					pomlog(POMLOG_WARN "Internal error : SIP event sill exists for direction %u", direction);
					event_cleanup(priv->event[direction]);
				}

				if (!strncasecmp(token, "SIP/2.0", strlen("SIP/2.0"))) {
					is_req = 0;
					priv->event[direction] = event_alloc(ppriv->evt_sip_rsp);
					if (!priv->event[direction])
						return PROTO_ERR;
					evt_data = event_get_data(priv->event[direction]);
				} else {
					is_req = 1;
					priv->event[direction] = event_alloc(ppriv->evt_sip_req);
					if (!priv->event[direction])
						return PROTO_ERR;
					
					evt_data = event_get_data(priv->event[direction]);
					PTYPE_STRING_SETVAL_N(evt_data[proto_sip_req_method].value, token, tok_len);
					data_set(evt_data[proto_sip_req_method]);
				}
				break;
			case 1:

				if (is_req) {
					PTYPE_STRING_SETVAL_N(evt_data[proto_sip_req_uri].value, token, tok_len);
					data_set(evt_data[proto_sip_req_uri]);

				} else {
					uint16_t status = 0;
					char status_str[4] = { 0 };
					strncpy(status_str, token, 3);
					if (sscanf(status_str, "%hu", &status) != 1 || status == 0) {
						pomlog(POMLOG_DEBUG "Invalid status code in SIP response");
						return PROTO_INVALID;
					}
					
					PTYPE_UINT16_SETVAL(evt_data[proto_sip_rsp_status].value, status);
					data_set(evt_data[proto_sip_rsp_status]);
				}
				break;

			case 2:
				if (is_req) {
					if (len < strlen("SIP/2.0")) {
						pomlog(POMLOG_DEBUG "SIP version string too short");
						return PROTO_INVALID;
					}

					if (strncasecmp(token, "SIP/2.0", strlen("SIP/2.0"))) {
						pomlog(POMLOG_DEBUG "Invalid SIP version string");
						return PROTO_INVALID;
					}
				} else {
					PTYPE_STRING_SETVAL_N(evt_data[proto_sip_rsp_reason].value, token, len);
					data_set(evt_data[proto_sip_rsp_reason]);
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
		pomlog(POMLOG_DEBUG "Unable to parse the %s first line", (is_req ? "request" : "response"));
		return PROTO_INVALID;
	}

	PTYPE_STRING_SETVAL_N(evt_data[proto_sip_msg_first_line].value, line, line_len);
	data_set(evt_data[proto_sip_msg_first_line]);

	priv->state[direction]++;

	return PROTO_OK;

}


static int proto_sip_parse_cseq(struct data *data, char *value, size_t value_len, int field_id) {

	char *space = memchr(value, ' ', value_len);
	if (!space)
		return PROTO_INVALID;

	char seq_str[16] = { 0 };
	memcpy(seq_str, value, space - value);
	
	unsigned int seq;
	if (sscanf(seq_str, "%u", &seq) != 1 || seq == 0)
		return PROTO_INVALID;

	PTYPE_UINT32_SETVAL(data[proto_sip_msg_cseq_num].value, seq);
	data_set(data[proto_sip_msg_cseq_num]);

	int method_len = value_len - (space - value);
	while (method_len > 0 && *space == ' ') {
		space++;
		method_len--;
	}


	PTYPE_STRING_SETVAL_N(data[proto_sip_msg_cseq_method].value, space, method_len);
	data_set(data[proto_sip_msg_cseq_method]);

	return PROTO_OK;
}

static int proto_sip_parse_string_header(struct data *data, char *value, size_t value_len, int field_id) {

	PTYPE_STRING_SETVAL_N(data[field_id].value, value, value_len);
	data_set(data[field_id]);

	return PROTO_OK;
}

static int proto_sip_parse_content_len(struct data *data, char *value, size_t value_len, int field_id) {

	char len_str[32] = { 0 };
	if (value_len > 31)
		return PROTO_INVALID;
	memcpy(len_str, value, value_len);

	if (ptype_parse_val(data[proto_sip_msg_content_len].value, len_str) != POM_OK)
		return PROTO_INVALID;

	data_set(data[proto_sip_msg_content_len]);

	return PROTO_OK;
}

static int proto_sip_parse_to_from(struct data *data, char *value, size_t value_len, int field_id) {

	
	char *uri = value;
	size_t uri_len = value_len;
	char *sm = NULL;

	char *laquot = memchr(value, '<', value_len);
	if (laquot) {
		
		char *raquot = memchr(value, '>', value_len);
		if (!raquot || raquot < laquot) {
			pomlog(POMLOG_DEBUG "No matching '>' in SIP header");
			return PROTO_INVALID;
		}

		char *name = value;
		size_t name_len = laquot - name;
		if (name_len > 0 && *name == '"') {
			name_len--;
			name++;
		}

		while (name_len > 0 && name[name_len - 1] == ' ')
			name_len--;

		if (name_len > 0 && name[name_len - 1] == '"')
			name_len--;

		if (name_len > 0) {
			PTYPE_STRING_SETVAL_N(data[field_id].value, name, name_len);
			data_set(data[field_id]);
		}
		
		sm = memchr(raquot, ';', value_len - (raquot - value));
		uri = laquot + 1;
		uri_len = raquot - laquot - 1;

	} else {
		// URI only
		sm = memchr(value, ';', value_len);
		uri_len = sm - uri - 1;
	}

	if (sm) {
		sm++;
		size_t sm_len = value_len - (sm - value);
		char *tag = pom_strnstr(sm, "tag=", sm_len);
		if (tag) {
			tag += strlen("tag=");
			size_t tag_len = sm_len - (tag - sm);
			char *sm = memchr(tag, ';', tag_len);
			if (sm)
				tag_len = sm - tag;

			PTYPE_STRING_SETVAL_N(data[field_id + 2].value, tag, tag_len);
			data_set(data[field_id + 2]);
		}
	}
	
	PTYPE_STRING_SETVAL_N(data[field_id + 1].value, uri, uri_len);
	data_set(data[field_id + 1]);

	return POM_OK;
}

static int proto_sip_parse_via(struct data *data, char *value, size_t value_len, int field_id) {

	// Start at the first semicolon
	char *sc = memchr(value, ';', value_len);
	if (!sc) {
		pomlog(POMLOG_DEBUG "No parameter found in Via header");
		return POM_OK;
	}


	size_t branch_eq_len = strlen("branch=");

	while (sc && value_len) {
		value_len -= sc - value + 1;
		value = sc + 1;


		sc = memchr(value, ';', value_len);

		size_t param_len = value_len;
		if (sc)
			param_len = sc - value;

		if (!strncasecmp(value, "branch=", branch_eq_len)) {
			param_len -= branch_eq_len;
			value += branch_eq_len;

			PTYPE_STRING_SETVAL_N(data[field_id].value, value, param_len);
			data_set(data[field_id]);

			return POM_OK;
		}
	}

	pomlog(POMLOG_DEBUG "Parameter branch not found in Via header");
	return POM_OK;
}

static int proto_sip_conntrack_cleanup(void *ce_priv) {

	struct proto_sip_conntrack_priv *priv = ce_priv;

	int i;

	for (i = 0; i < POM_DIR_TOT; i++) {
		if (priv->parser[i])
			packet_stream_parser_cleanup(priv->parser[i]);

		if (priv->pload[i])
			pload_end(priv->pload[i]);

		if (priv->event[i]) {
			if (event_is_started(priv->event[i])) {
				event_process_end(priv->event[i]);
			} else {
				event_cleanup(priv->event[i]);
			}
		}
	}

	free(priv);

	return POM_OK;
}


