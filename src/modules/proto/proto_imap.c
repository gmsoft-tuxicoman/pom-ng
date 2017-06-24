/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2015 Guy Martin <gmsoft@tuxicoman.be>
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

#include "proto_imap.h"
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint64.h>

#include <string.h>
#include <stdio.h>


struct mod_reg_info* proto_imap_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_imap_mod_register;
	reg_info.unregister_func = proto_imap_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_uint64";

	return &reg_info;
}

static int proto_imap_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_imap = { 0 };
	proto_imap.name = "imap";
	proto_imap.api_ver = PROTO_API_VER;
	proto_imap.mod = mod;

	static struct conntrack_info ct_info = { 0 };

	ct_info.default_table_size = 1; // No hashing done here
	ct_info.cleanup_handler = proto_imap_conntrack_cleanup;
	proto_imap.ct_info = &ct_info;

	proto_imap.init = proto_imap_init;
	proto_imap.process = proto_imap_process;
	proto_imap.cleanup = proto_imap_cleanup;

	if (proto_register(&proto_imap) == POM_OK)
		return POM_OK;

	return POM_ERR;

}

static int proto_imap_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("tcp", 143, proto) != POM_OK)
		return POM_ERR;

	struct proto_imap_priv *priv = malloc(sizeof(struct proto_imap_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_imap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_imap_priv));

	proto_set_priv(proto, priv);

	// Register the imap_cmd event
	static struct data_item_reg evt_cmd_data_items[PROTO_IMAP_EVT_CMD_DATA_COUNT] = { { 0 } };
	evt_cmd_data_items[proto_imap_cmd_tag].name = "tag";
	evt_cmd_data_items[proto_imap_cmd_tag].value_type = ptype_get_type("string");
	evt_cmd_data_items[proto_imap_cmd_name].name = "name";
	evt_cmd_data_items[proto_imap_cmd_name].value_type = ptype_get_type("string");
	evt_cmd_data_items[proto_imap_cmd_arg].name = "arg";
	evt_cmd_data_items[proto_imap_cmd_arg].value_type = ptype_get_type("string");

	static struct data_reg evt_cmd_data = {
		.items = evt_cmd_data_items,
		.data_count = PROTO_IMAP_EVT_CMD_DATA_COUNT
	};

	static struct event_reg_info proto_imap_evt_cmd = { 0 };
	proto_imap_evt_cmd.source_name = "proto_imap";
	proto_imap_evt_cmd.source_obj = proto;
	proto_imap_evt_cmd.name = "imap_cmd";
	proto_imap_evt_cmd.description = "IMAP command from the client";
	proto_imap_evt_cmd.data_reg = &evt_cmd_data;

	priv->evt_cmd = event_register(&proto_imap_evt_cmd);
	if (!priv->evt_cmd)
		goto err;

	// Register the imap_rsp event
	static struct data_item_reg evt_rsp_data_items[PROTO_IMAP_EVT_CMD_DATA_COUNT] = { { 0 } };
	evt_rsp_data_items[proto_imap_response_tag].name = "tag";
	evt_rsp_data_items[proto_imap_response_tag].value_type = ptype_get_type("string");
	evt_rsp_data_items[proto_imap_response_status].name = "status";
	evt_rsp_data_items[proto_imap_response_status].value_type = ptype_get_type("string");
	evt_rsp_data_items[proto_imap_response_text].name = "text";
	evt_rsp_data_items[proto_imap_response_text].value_type = ptype_get_type("string");

	static struct data_reg evt_rsp_data = {
		.items = evt_rsp_data_items,
		.data_count = PROTO_IMAP_EVT_RESPONSE_DATA_COUNT
	};

	static struct event_reg_info proto_imap_evt_rsp = { 0 };
	proto_imap_evt_rsp.source_name = "proto_imap";
	proto_imap_evt_rsp.source_obj = proto;
	proto_imap_evt_rsp.name = "imap_rsp";
	proto_imap_evt_rsp.description = "IMAP response from the server";
	proto_imap_evt_rsp.data_reg = &evt_rsp_data;

	priv->evt_rsp = event_register(&proto_imap_evt_rsp);
	if (!priv->evt_rsp)
		goto err;

	// Register the imap_pload event
	static struct data_item_reg evt_pload_data_items[PROTO_IMAP_EVT_PLOAD_DATA_COUNT] = { { 0 } };
	evt_pload_data_items[proto_imap_pload_cmd].name = "cmd";
	evt_pload_data_items[proto_imap_pload_cmd].value_type = ptype_get_type("string");
	evt_pload_data_items[proto_imap_pload_size].name = "size";
	evt_pload_data_items[proto_imap_pload_size].value_type = ptype_get_type("uint64");

	static struct data_reg evt_pload_data = {
		.items = evt_pload_data_items,
		.data_count = PROTO_IMAP_EVT_PLOAD_DATA_COUNT
	};

	static struct event_reg_info proto_imap_evt_pload = { 0 };
	proto_imap_evt_pload.source_name = "proto_imap";
	proto_imap_evt_pload.source_obj = proto;
	proto_imap_evt_pload.name = "imap_pload";
	proto_imap_evt_pload.description = "IMAP payload";
	proto_imap_evt_pload.data_reg = &evt_pload_data;

	priv->evt_pload = event_register(&proto_imap_evt_pload);
	if (!priv->evt_pload)
		goto err;

	return POM_OK;

err:
	proto_imap_cleanup(priv);
	return POM_ERR;
}


static int proto_imap_cleanup(void *proto_priv) {
	
	if (!proto_priv)
		return POM_OK;

	struct proto_imap_priv *priv = proto_priv;
	if (priv->evt_cmd)
		event_unregister(priv->evt_cmd);
	if (priv->evt_rsp)
		event_unregister(priv->evt_rsp);

	free(priv);

	return POM_OK;
}

static int proto_imap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK) {
		pomlog(POMLOG_ERR "Could not get conntrack entry");
		return PROTO_ERR;
	}

	// There should no need to keep the lock here since we are in the packet_stream lock from proto_tcp
	conntrack_unlock(s->ce);

	struct proto_imap_priv *ppriv = proto_priv;

	struct proto_imap_conntrack_priv *priv = s->ce->priv;
	if (!priv) {
		priv = malloc(sizeof(struct proto_imap_conntrack_priv));
		if (!priv) {
			pom_oom(sizeof(struct proto_imap_conntrack_priv));
			return PROTO_ERR;
		}
		memset(priv, 0, sizeof(struct proto_imap_conntrack_priv));

		priv->parser[POM_DIR_FWD] = packet_stream_parser_alloc(IMAP_MAX_LINE, 0);
		if (!priv->parser[POM_DIR_FWD]) {
			free(priv);
			return PROTO_ERR;
		}

		priv->parser[POM_DIR_REV] = packet_stream_parser_alloc(IMAP_MAX_LINE, 0);
		if (!priv->parser[POM_DIR_REV]) {
			packet_stream_parser_cleanup(priv->parser[POM_DIR_FWD]);
			free(priv);
			return PROTO_ERR;
		}

		priv->server_direction = POM_DIR_UNK;

		s->ce->priv = priv;
	}

	if (priv->flags & PROTO_IMAP_FLAG_INVALID)
		return PROTO_OK;

	struct packet_stream_parser *parser = priv->parser[s->direction];
	if (packet_stream_parser_add_payload(parser, s->pload, s->plen) != POM_OK)
		return PROTO_ERR;

	char *line = NULL;
	size_t len = 0;
	while (1) {

		// Check if there is any remaining payload
		uint64_t data_bytes = priv->data_bytes[s->direction];
		if (data_bytes) {

			void *pload;
			if (packet_stream_parser_get_remaining(parser, &pload, &len) != POM_OK)
				return PROTO_ERR;
			s_next->pload = pload;
			if (len <= data_bytes) {
				// There are no more commands in this packet
				s_next->plen = len;
				priv->data_bytes[s->direction] -= len;
				packet_stream_parser_empty(parser);
				return PROTO_OK;
			} else {
				s_next->plen = data_bytes;
				int res = core_process_multi_packet(stack, stack_index + 1, p);
				if (res == PROTO_ERR)
					return PROTO_ERR;
				if (packet_stream_parser_skip_bytes(parser, data_bytes) != POM_OK) {
					pomlog(POMLOG_ERR "Could not skip %"PRIu64" bytes of data", data_bytes);
					return PROTO_ERR;
				}
				priv->data_bytes[s->direction] = 0;

				if (!priv->pload_evt[s->direction]) {
					pomlog(POMLOG_ERR "Could not find the pload event");
					return PROTO_ERR;
				}

				if (event_process_end(priv->pload_evt[s->direction]) != POM_OK)
					return PROTO_ERR;
				priv->pload_evt[s->direction] = NULL;

				if (priv->server_direction != s->direction && priv->cmd_evt) {
					event_process_end(priv->cmd_evt);
					priv->cmd_evt = NULL;
				}
			}
		}


		// Process commands
		if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
			return PROTO_ERR;

		if (!line)
			return PROTO_OK;

		if (!len) // Probably a missed packet
			return PROTO_OK;

		if (priv->rsp_evt && (priv->server_direction == s->direction)) {
			// There was some leftover from the previous server line to parse
			struct data *rsp_data = event_get_data(priv->rsp_evt);
			char *old_line = PTYPE_STRING_GETVAL(rsp_data[proto_imap_response_text].value);
			size_t old_len = strlen(old_line);
			size_t new_len = old_len + len;
			char *new_line = malloc(new_len + 1);
			if (!new_line) {
				pom_oom(new_len + 1);
				return PROTO_ERR;
			}
			memcpy(new_line, old_line, old_len);
			memcpy(new_line + old_len, line, len);
			new_line[new_len] = 0;

			PTYPE_STRING_SETVAL_P(rsp_data[proto_imap_response_text].value, new_line);

			if (new_line[new_len - 1] == '}') {
				// We've got some more payload after this line
				int i;
				for (i = new_len - 2; i > 0; i--) {
					if (new_line[i] < '0' || new_line[i] > '9')
						break;
				}

				if (sscanf(new_line + i + 1, "%"SCNu64, &priv->data_bytes[s->direction]) != 1) {
					pomlog(POMLOG_DEBUG "Invalid size for payload");
					priv->flags |= PROTO_IMAP_FLAG_INVALID;
					return PROTO_OK;
				}

				// Send a new pload event for this pload
				struct event *pload_evt = event_alloc(ppriv->evt_pload);
				if (!pload_evt)
					return PROTO_ERR;
				char *status = PTYPE_STRING_GETVAL(rsp_data[proto_imap_response_status].value);
				size_t status_len = strlen(status);
				size_t complete_len = status_len + 1 + new_len;
				char *complete_line = malloc(complete_len + 1);
				if (!complete_line) {
					pom_oom(complete_len + 1);
					event_cleanup(pload_evt);
					return PROTO_ERR;
				}
				memcpy(complete_line, status, status_len);
				complete_line[status_len] = ' ';
				memcpy(complete_line + status_len + 1, new_line, new_len);
				complete_line[complete_len] = 0;


				struct data *pload_data = event_get_data(pload_evt);
				PTYPE_STRING_SETVAL_P(pload_data[proto_imap_pload_cmd].value, complete_line);
				data_set(pload_data[proto_imap_pload_cmd]);
				PTYPE_UINT64_SETVAL(pload_data[proto_imap_pload_size].value, priv->data_bytes[s->direction]);
				data_set(pload_data[proto_imap_pload_size]);

				if (event_process_begin(pload_evt, stack, stack_index, p->ts) != POM_OK) {
					event_cleanup(pload_evt);
					return PROTO_ERR;
				}
				priv->pload_evt[s->direction] = pload_evt;


			} else {
				if (event_process_end(priv->rsp_evt) != POM_OK)
					return PROTO_ERR;

				priv->rsp_evt = NULL;
			}

			continue;
		}

		// Parse the tag and the command/status
		char *sp = memchr(line, ' ', len);
		if (!sp) {
			pomlog(POMLOG_DEBUG "Space after the tag not found");
			priv->flags |= PROTO_IMAP_FLAG_INVALID;
			return PROTO_OK;
		}

		size_t tok_len = sp - line;
		char *tag = strndup(line, tok_len);
		if (!tag) {
			pom_oom(tok_len);
			return PROTO_ERR;
		}

		line += tok_len + 1;
		len -= tok_len + 1;

		char *cmd_or_status = NULL;
		sp = memchr(line, ' ', len);
		if (sp) {
			tok_len = sp - line;
			cmd_or_status = strndup(line, tok_len);
		} else {
			tok_len = len;
			cmd_or_status = strndup(line, len);
		}

		if (!cmd_or_status) {
			free(tag);
			pom_oom(tok_len);
			return PROTO_ERR;
		}

		// Try to find the server direction
		if (priv->server_direction == POM_DIR_UNK) {
			if (!strcmp(tag, "*")) {
				// Only the server sends untagged replies
				priv->server_direction = s->direction;
			} else {
				if (!strcasecmp(cmd_or_status, "OK") || !strcasecmp(cmd_or_status, "NO") || !strcasecmp(cmd_or_status, "BAD") || !strcasecmp(cmd_or_status, "BYE")) {
					// If it's a tagger reply, then it must be followed by the status
					priv->server_direction = s->direction;
				} else {
					// If it's not a status, then it must be the client
					priv->server_direction = POM_DIR_REVERSE(s->direction);
				}
			}
		}

		if (s->direction == priv->server_direction) {

			if (!event_has_listener(ppriv->evt_rsp)) {
				free(tag);
				free(cmd_or_status);
				return PROTO_OK;
			}

			struct event *rsp_evt = event_alloc(ppriv->evt_rsp);
			if (!rsp_evt) {
				free(tag);
				free(cmd_or_status);
				return PROTO_ERR;
			}
			struct data *evt_data = event_get_data(rsp_evt);
			
			PTYPE_STRING_SETVAL_P(evt_data[proto_imap_response_tag].value, tag);
			data_set(evt_data[proto_imap_response_tag]);
			PTYPE_STRING_SETVAL_P(evt_data[proto_imap_response_status].value, cmd_or_status);
			data_set(evt_data[proto_imap_response_status]);

			if (sp) {
				PTYPE_STRING_SETVAL_N(evt_data[proto_imap_response_text].value, sp + 1, len - tok_len - 1);
				data_set(evt_data[proto_imap_response_text]);
			}

			if (len > 3 && line[len - 1] == '}') {
				// We've got some payload after this line
				int i;
				for (i = len - 2; i > 0;i --) {
					if (line[i] < '0' || line[i] > '9')
						break;
				}

				if (sscanf(line + i + 1, "%"SCNu64, &priv->data_bytes[s->direction]) != 1) {
					pomlog(POMLOG_DEBUG "Invalid size for payload");
					event_cleanup(rsp_evt);
					return PROTO_OK;
				}

				struct event *pload_evt = event_alloc(ppriv->evt_pload);
				if (!pload_evt) {
					event_cleanup(rsp_evt);
					return PROTO_ERR;
				}

				if (event_process_begin(rsp_evt, stack, stack_index, p->ts) != POM_OK) {
					event_cleanup(rsp_evt);
					event_cleanup(pload_evt);
					return PROTO_ERR;
				}
				priv->rsp_evt = rsp_evt;

				struct data *pload_data = event_get_data(pload_evt);
				PTYPE_STRING_SETVAL_N(pload_data[proto_imap_pload_cmd].value, line, len);
				data_set(pload_data[proto_imap_pload_cmd]);
				PTYPE_UINT64_SETVAL(pload_data[proto_imap_pload_size].value, priv->data_bytes[s->direction]);
				data_set(pload_data[proto_imap_pload_size]);

				if (event_process_begin(pload_evt, stack, stack_index, p->ts) != POM_OK) {
					event_cleanup(pload_evt);
					return PROTO_ERR;
				}
				priv->pload_evt[s->direction] = pload_evt;

			} else {
				if (event_process(rsp_evt, stack, stack_index, p->ts) != POM_OK)
					return PROTO_ERR;
			}

		} else {
			if (!event_has_listener(ppriv->evt_cmd)) {
				free(tag);
				free(cmd_or_status);
				return PROTO_OK;
			}

			// Skip the command up to the text
			line += tok_len;
			len -= tok_len;

			while (*line == ' ') {
				line++;
				len--;
			}

			struct event *cmd_evt = event_alloc(ppriv->evt_cmd);
			if (!cmd_evt) {
				free(tag);
				free(cmd_or_status);
				return PROTO_ERR;
			}

			struct data *evt_data = event_get_data(cmd_evt);
			PTYPE_STRING_SETVAL_P(evt_data[proto_imap_cmd_tag].value, tag);
			data_set(evt_data[proto_imap_cmd_tag]);
			PTYPE_STRING_SETVAL_P(evt_data[proto_imap_cmd_name].value, cmd_or_status);
			data_set(evt_data[proto_imap_cmd_name]);

			if (sp) {
				PTYPE_STRING_SETVAL_N(evt_data[proto_imap_cmd_arg].value, line, len);
				data_set(evt_data[proto_imap_cmd_arg]);
			}

			if (len > 3 && line[len - 1] == '}') {
				// We've got some payload after this line
				int i;
				for (i = len - 2; i > 0;i --) {
					if (line[i] < '0' || line[i] > '9')
						break;
				}

				if (sscanf(line + i + 1, "%"SCNu64, &priv->data_bytes[s->direction]) != 1) {
					pomlog(POMLOG_DEBUG "Invalid size for payload");
					event_cleanup(cmd_evt);
					return PROTO_OK;
				}

				if (event_process_begin(cmd_evt, stack, stack_index, p->ts) != POM_OK) {
					event_cleanup(cmd_evt);
					return PROTO_ERR;
				}
				priv->cmd_evt = cmd_evt;

			} else {
				if (event_process(cmd_evt, stack, stack_index, p->ts) != POM_OK)
					return PROTO_ERR;
			}
		}
	}

	return PROTO_OK;
}

static int proto_imap_conntrack_cleanup(void *ce_priv) {

	struct proto_imap_conntrack_priv *priv = ce_priv;
	if (!priv)
		return POM_OK;

	if (priv->data_evt) {
		if (event_is_started(priv->data_evt))
			event_process_end(priv->data_evt);
		else
			event_cleanup(priv->data_evt);
	}

	if (priv->cmd_evt) {
		if (event_is_started(priv->rsp_evt))
			event_process_end(priv->rsp_evt);
		else
			event_cleanup(priv->rsp_evt);
	}

	if (priv->rsp_evt) {
		if (event_is_started(priv->rsp_evt))
			event_process_end(priv->rsp_evt);
		else
			event_cleanup(priv->rsp_evt);

	int i;
	for (i = 0; i < POM_DIR_TOT; i++) {
		if (priv->parser[i])
			packet_stream_parser_cleanup(priv->parser[i]);
		if (priv->pload_evt[i]) {
			if (event_is_started(priv->pload_evt[i]))
				event_process_end(priv->pload_evt[i]);
			else
				event_cleanup(priv->pload_evt[i]);
		}
	}

	free(priv);

	return POM_OK;
}

static int proto_imap_mod_unregister() {

	return proto_unregister("imap");

}
