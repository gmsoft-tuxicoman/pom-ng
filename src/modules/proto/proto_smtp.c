/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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

#include "proto_smtp.h"
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>

#include <string.h>
#include <stdio.h>


struct mod_reg_info* proto_smtp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_smtp_mod_register;
	reg_info.unregister_func = proto_smtp_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_uint16";

	return &reg_info;
}

static int proto_smtp_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_smtp = { 0 };
	proto_smtp.name = "smtp";
	proto_smtp.api_ver = PROTO_API_VER;
	proto_smtp.mod = mod;

	static struct conntrack_info ct_info = { 0 };

	ct_info.default_table_size = 1; // No hashing done here
	ct_info.cleanup_handler = proto_smtp_conntrack_cleanup;
	proto_smtp.ct_info = &ct_info;

	proto_smtp.init = proto_smtp_init;
	proto_smtp.process = proto_smtp_process;
	proto_smtp.post_process = proto_smtp_post_process;
	proto_smtp.cleanup = proto_smtp_cleanup;

	if (proto_register(&proto_smtp) == POM_OK)
		return POM_OK;

	return POM_ERR;

}

static int proto_smtp_init(struct proto *proto, struct registry_instance *i) {

	struct proto_smtp_priv *priv = malloc(sizeof(struct proto_smtp_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_smtp_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_smtp_priv));

	proto_set_priv(proto, priv);

	// Register the smtp_cmd event
	static struct data_item_reg evt_cmd_data_items[PROTO_SMTP_EVT_CMD_DATA_COUNT] = { { 0 } };
	evt_cmd_data_items[proto_smtp_cmd_name].name = "name";
	evt_cmd_data_items[proto_smtp_cmd_name].value_type = ptype_get_type("string");
	evt_cmd_data_items[proto_smtp_cmd_arg].name = "arg";
	evt_cmd_data_items[proto_smtp_cmd_arg].value_type = ptype_get_type("string");

	static struct data_reg evt_cmd_data = {
		.items = evt_cmd_data_items,
		.data_count = PROTO_SMTP_EVT_CMD_DATA_COUNT
	};

	static struct event_reg_info proto_smtp_evt_cmd = { 0 };
	proto_smtp_evt_cmd.source_name = "proto_smtp";
	proto_smtp_evt_cmd.source_obj = proto;
	proto_smtp_evt_cmd.name = "smtp_cmd";
	proto_smtp_evt_cmd.description = "SMTP command from the client";
	proto_smtp_evt_cmd.data_reg = &evt_cmd_data;

	priv->evt_cmd = event_register(&proto_smtp_evt_cmd);
	if (!priv->evt_cmd)
		goto err;

	// Register the smtp_reply event
	static struct data_item_reg evt_reply_data_items[PROTO_SMTP_EVT_CMD_DATA_COUNT] = { { 0 } };
	evt_reply_data_items[proto_smtp_reply_code].name = "code";
	evt_reply_data_items[proto_smtp_reply_code].value_type = ptype_get_type("uint16");
	evt_reply_data_items[proto_smtp_reply_text].name = "text";
	evt_reply_data_items[proto_smtp_reply_text].flags = DATA_REG_FLAG_LIST;

	static struct data_reg evt_reply_data = {
		.items = evt_reply_data_items,
		.data_count = PROTO_SMTP_EVT_REPLY_DATA_COUNT
	};

	static struct event_reg_info proto_smtp_evt_reply = { 0 };
	proto_smtp_evt_reply.source_name = "proto_smtp";
	proto_smtp_evt_reply.source_obj = proto;
	proto_smtp_evt_reply.name = "smtp_reply";
	proto_smtp_evt_reply.description = "SMTP command from the client";
	proto_smtp_evt_reply.data_reg = &evt_reply_data;

	priv->evt_reply = event_register(&proto_smtp_evt_reply);
	if (!priv->evt_reply)
		goto err;

	return POM_OK;

err:
	proto_smtp_cleanup(priv);
	return POM_ERR;
}


static int proto_smtp_cleanup(void *proto_priv) {
	
	if (!proto_priv)
		return POM_OK;

	struct proto_smtp_priv *priv = proto_priv;
	if (priv->evt_cmd)
		event_unregister(priv->evt_cmd);
	if (priv->evt_reply)
		event_unregister(priv->evt_reply);

	free(priv);

	return POM_OK;
}

static int proto_smtp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK) {
		pomlog(POMLOG_ERR "Coult not get conntrack entry");
		return PROTO_ERR;
	}

	// There should no need to keep the lock here since we are in the packet_stream lock from proto_tcp
	conntrack_unlock(s->ce);

	struct proto_smtp_priv *ppriv = proto_priv;

	struct proto_smtp_conntrack_priv *priv = s->ce->priv;
	if (!priv) {
		priv = malloc(sizeof(struct proto_smtp_conntrack_priv));
		if (!priv) {
			pom_oom(sizeof(struct proto_smtp_conntrack_priv));
			return PROTO_ERR;
		}
		memset(priv, 0, sizeof(struct proto_smtp_conntrack_priv));

		priv->parser[POM_DIR_FWD] = packet_stream_parser_alloc(SMTP_MAX_LINE, PACKET_STREAM_PARSER_FLAG_TRIM);
		if (!priv->parser[POM_DIR_FWD]) {
			free(priv);
			return PROTO_ERR;
		}

		priv->parser[POM_DIR_REV] = packet_stream_parser_alloc(SMTP_MAX_LINE, PACKET_STREAM_PARSER_FLAG_TRIM);
		if (!priv->parser[POM_DIR_REV]) {
			packet_stream_parser_cleanup(priv->parser[POM_DIR_FWD]);
			free(priv);
			return PROTO_ERR;
		}

		priv->server_direction = POM_DIR_UNK;

		s->ce->priv = priv;
	}

	if (priv->flags & PROTO_SMTP_FLAG_INVALID)
		return PROTO_OK;

	struct packet_stream_parser *parser = priv->parser[s->direction];
	if (packet_stream_parser_add_payload(parser, s->pload, s->plen) != POM_OK)
		return PROTO_ERR;

	char *line = NULL;
	unsigned int len = 0;
	while (1) {

		// Some check to do prior to parse the payload
		
		if (s->direction == POM_DIR_REVERSE(priv->server_direction)) {
			if (priv->flags & PROTO_SMTP_FLAG_STARTTLS) {
				// Last command was a STARTTLS command, this is the TLS negociation
				// Since we can't parse this, mark it as invalid
				priv->flags |= PROTO_SMTP_FLAG_INVALID;
				return PROTO_OK;

			} else if (priv->flags & PROTO_SMTP_FLAG_CLIENT_DATA) {

				// We are receiving payload data, check where the end is
				void *pload;
				uint32_t plen;
				packet_stream_parser_get_remaining(parser, &pload, &plen);

				if (!plen)
					return PROTO_OK;

				// Look for the "<CR><LF>.<CR><LF>" sequence
				if (priv->data_end_pos > 0) {
					
					// The previous packet ended with something that might be the final sequence
					// Check if we have the rest
					int i, found = 1;
					for (i = 0; i < PROTO_SMTP_DATA_END_LEN - priv->data_end_pos && i <= plen; i++) {
						if (*(char*)(pload + i) != PROTO_SMTP_DATA_END[priv->data_end_pos + i]) {
							found = 0;
							break;
						}
					}
					if (found) {
						// If we have already processed the dot after <CR><LF> there is no way to remove it
						// Thus we mark this connection as invalid. Most MTA will send at worst the last
						// 3 bytes of the end sequence in a sequence packet
						if (i != plen || (priv->data_end_pos >= 2 && plen < 3)) {
							pomlog(POMLOG_DEBUG "The final line was not at the of a packet as expected !");
							priv->flags |= PROTO_SMTP_FLAG_INVALID;
							event_process_end(priv->data_evt);
							priv->data_evt = NULL;
							return PROTO_OK;
						}
						s_next->pload = pload;
						s_next->plen = plen - PROTO_SMTP_DATA_END_LEN + 2; // The last line return is part of the payload
						priv->flags |= PROTO_SMTP_FLAG_CLIENT_DATA_END;

						priv->flags &= ~PROTO_SMTP_FLAG_CLIENT_DATA;
						priv->data_end_pos = 0;

						return PROTO_OK;
					}
					priv->data_end_pos = 0;
				}


				char *dotline = strstr(pload, PROTO_SMTP_DATA_END);
				if (dotline) {
					if (pload + plen - PROTO_SMTP_DATA_END_LEN != dotline) {
						pomlog(POMLOG_DEBUG "The final line was not at the of a packet as expected !");
						priv->flags |= PROTO_SMTP_FLAG_INVALID;
						event_process_end(priv->data_evt);
						priv->data_evt = NULL;
						return PROTO_OK;
					}
					s_next->pload = pload;
					s_next->plen = plen - PROTO_SMTP_DATA_END_LEN + 2; // The last line return is part of the payload
					priv->flags |= PROTO_SMTP_FLAG_CLIENT_DATA_END;

					priv->flags &= ~PROTO_SMTP_FLAG_CLIENT_DATA;

				} else {
					// Check if the end of the payload contains part of the "<CR><LF>.<CR><LF>" sequence
					int i, found = 0;
					for (i = 1 ; (i < PROTO_SMTP_DATA_END_LEN) && (i <= plen); i++) {
						if (!memcmp(pload + plen - i, PROTO_SMTP_DATA_END, i)) {
							found = 1;
							break;
						}
					}

					if (found)
						priv->data_end_pos = i;

					s_next->pload = pload;
					s_next->plen = plen;
				}

				return PROTO_OK;
			}
		}

		// Process commands
		if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
			return PROTO_ERR;

		if (!line)
			return PROTO_OK;

		if (!len) // Probably a missed packet
			return PROTO_OK;

		// Try to find the server direction
		if (priv->server_direction == POM_DIR_UNK) {
			unsigned int code = atoi(line);
			if (code > 0) {
				priv->server_direction = s->direction;
			} else {
				priv->server_direction = POM_DIR_REVERSE(s->direction);
			}
		}

		if (s->direction == priv->server_direction) {

			// Parse the response code and generate the event
			if ((len < 5) || // Server response is 3 digit error code, a space or hyphen and then at least one letter of text
				(line[3] != ' ' && line[3] != '-')) {
				pomlog(POMLOG_DEBUG "Too short or invalid response from server");
				priv->flags |= PROTO_SMTP_FLAG_INVALID;
				return POM_OK;
			}

			int code = atoi(line);
			if (code == 0) {
				pomlog(POMLOG_DEBUG "Invalid response from server");
				priv->flags |= PROTO_SMTP_FLAG_INVALID;
				return POM_OK;
			}

			if (event_has_listener(ppriv->evt_reply)) {

				struct data *evt_data = NULL;
				if (priv->reply_evt) {
					evt_data = event_get_data(priv->reply_evt);
					uint16_t cur_code = *PTYPE_UINT16_GETVAL(evt_data[proto_smtp_reply_code].value);
					if (cur_code != code) {
						pomlog(POMLOG_WARN "Multiline code not the same as previous line : %hu -> %hu", cur_code, code);
						event_process_end(priv->reply_evt);
						priv->reply_evt = NULL;
					}
				}


				if (!priv->reply_evt) {
					priv->reply_evt = event_alloc(ppriv->evt_reply);
					if (!priv->reply_evt)
						return PROTO_ERR;

					evt_data = event_get_data(priv->reply_evt);
					PTYPE_UINT16_SETVAL(evt_data[proto_smtp_reply_code].value, code);
					data_set(evt_data[proto_smtp_reply_code]);

				}

				if (len > 4) {
					struct ptype *txt = ptype_alloc("string");
					if (!txt)
						return PROTO_ERR;
					PTYPE_STRING_SETVAL_N(txt, line + 4, len - 4);
					if (data_item_add_ptype(evt_data, proto_smtp_reply_text, strdup("text"), txt) != POM_OK)
						return PROTO_ERR;
				}
				
				if (!event_is_started(priv->reply_evt))
					event_process_begin(priv->reply_evt, stack, stack_index);
			}


			if (line[3] != '-') {
				// Last line in the response
				if (priv->reply_evt) {
					event_process_end(priv->reply_evt);
					priv->reply_evt = NULL;
				}
			}
			
			if (priv->flags & PROTO_SMTP_FLAG_STARTTLS) {
				// The last command was STARTTLS
				priv->flags &= ~PROTO_SMTP_FLAG_STARTTLS;
				if (code == 220) {
					// TLS has the go, we can't parse  from now so mark as invalid
					priv->flags |= PROTO_SMTP_FLAG_INVALID;
					return POM_OK;
				}
			}

		} else {

			// Client command

			if (len < 4) { // Client commands are at least 4 bytes long
				pomlog(POMLOG_DEBUG "Too short or invalid query from client");
				priv->flags |= PROTO_SMTP_FLAG_INVALID;
				return POM_OK;
			}

			// Make sure it's a command by checking it's at least a four letter word
			int i;
			for (i = 0; i < 4; i++) {
				// In some case it can also be a base64 encoded word
				if (! ((line[i] >= 'A' && line[i] <= 'Z')
					|| (line[i] >= 'a' && line[i] <= 'z')
					|| (line[i] >= '0' && line [i] <= '9')
					|| line[i] == '='))
					break;
			}

			if ((i < 4)) {
				pomlog(POMLOG_DEBUG "Recieved invalid client command");
				priv->flags |= PROTO_SMTP_FLAG_INVALID;
				return POM_OK;
			}

			if (!strncasecmp(line, "DATA", strlen("DATA")) && len == strlen("DATA")) {
				priv->flags |= PROTO_SMTP_FLAG_CLIENT_DATA;
			} else if (!strncasecmp(line, "STARTTLS", strlen("STARTTLS")) && len == strlen("STARTTLS")) {
				priv->flags |= PROTO_SMTP_FLAG_STARTTLS;
			}


			if (event_has_listener(ppriv->evt_cmd)) {
				struct event *evt = event_alloc(ppriv->evt_cmd);
				if (!evt)
					return PROTO_ERR;

				size_t cmdlen = len;
				char *space = memchr(line, ' ', len);
				if (space)
					cmdlen = space - line;

				struct data *evt_data = event_get_data(evt);
				PTYPE_STRING_SETVAL_N(evt_data[proto_smtp_cmd_name].value, line, cmdlen);
				data_set(evt_data[proto_smtp_cmd_name]);
				if (space) {
					PTYPE_STRING_SETVAL_N(evt_data[proto_smtp_cmd_arg].value, space + 1, len - 1 - cmdlen);
					data_set(evt_data[proto_smtp_cmd_arg]);
				}

				if (priv->flags & PROTO_SMTP_FLAG_CLIENT_DATA) {
					// The event ends at the end of the message
					priv->data_evt = evt;
					return event_process_begin(evt, stack, stack_index);
				} else {
					return event_process(evt, stack, stack_index);
				}
			}

		}



	}

	return PROTO_OK;

}

static int proto_smtp_post_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct conntrack_entry *ce = stack[stack_index].ce;
	struct proto_smtp_conntrack_priv *priv = ce->priv;

	if (!priv)
		return PROTO_OK;
	
	if (priv->flags & PROTO_SMTP_FLAG_CLIENT_DATA_END) {
		if (priv->data_evt) {
			if (event_process_end(priv->data_evt) != POM_OK)
				return PROTO_ERR;
			priv->data_evt = NULL;
		}
		priv->flags &= ~PROTO_SMTP_FLAG_CLIENT_DATA_END;
		priv->data_end_pos = 0;
	}


	return POM_OK;
}

static int proto_smtp_conntrack_cleanup(void *ce_priv) {

	struct proto_smtp_conntrack_priv *priv = ce_priv;
	if (!priv)
		return POM_OK;

	if (priv->parser[POM_DIR_FWD])
		packet_stream_parser_cleanup(priv->parser[POM_DIR_FWD]);

	if (priv->parser[POM_DIR_REV])
		packet_stream_parser_cleanup(priv->parser[POM_DIR_REV]);

	if (priv->data_evt) {
		if (event_is_started(priv->data_evt))
			event_process_end(priv->data_evt);
		else
			event_cleanup(priv->data_evt);
	}

	if (priv->reply_evt) {
		if (event_is_started(priv->reply_evt))
			event_process_end(priv->reply_evt);
		else
			event_cleanup(priv->reply_evt);
	}
		

	free(priv);

	return POM_OK;
}

static int proto_smtp_mod_unregister() {

	return proto_unregister("smtp");

}
