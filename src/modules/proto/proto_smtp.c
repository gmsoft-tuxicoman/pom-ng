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

#include <string.h>


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
	evt_reply_data_items[proto_smtp_reply_text].value_type = ptype_get_type("string");

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

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK) {
		pomlog(POMLOG_ERR "Coult not get conntrack entry");
		return PROTO_ERR;
	}

	// There should no need to keep the lock here since we are in the packet_stream lock from proto_tcp
	conntrack_unlock(s->ce);


	struct proto_smtp_conntrack_priv *priv = s->ce->priv;
	if (!priv) {
		priv = malloc(sizeof(struct proto_smtp_conntrack_priv));
		if (!priv) {
			pom_oom(sizeof(struct proto_smtp_conntrack_priv));
			return PROTO_ERR;
		}
		memset(priv, 0, sizeof(struct proto_smtp_conntrack_priv));

		priv->parser = packet_stream_parser_alloc(SMTP_MAX_LINE);
		if (!priv->parser) {
			free(priv);
			return PROTO_ERR;
		}

		priv->direction = POM_DIR_UNK;

		s->ce->priv = priv;
	}

	if (priv->flags & PROTO_SMTP_FLAG_INVALID)
		return PROTO_OK;

	struct packet_stream_parser *parser = priv->parser;
	if (packet_stream_parser_add_payload(parser, s->pload, s->plen) != POM_OK)
		return PROTO_ERR;

	char *line = NULL;
	unsigned int len = 0;
	while (1) {

		if (packet_stream_parser_get_line(parser, &line, &len) != POM_OK)
			return POM_ERR;

		if (!line)
			return PROTO_OK;

		if (!len) // Probably a missed packet
			return PROTO_OK;

		// Try to find the server direction
		if (priv->server_direction == POM_DIR_UNK) {
			unsigned int code = 0;
			if (sscanf(line, "%3u", &code) == 1 && code > 0) {
				priv->server_direction = s->direction;
				priv->state = proto_smtp_state_server;
			} else {
				priv->server_direction = POM_DIR_REVERSE(s->direction);
				priv->state = proto_smtp_client_cmd;
			}
		}

		switch (priv->state) {
			case proto_smtp_state_client_cmd:

				break;

			case proto_smtp_state_server: {
				// Parse the response code and generate the event
				if ((len < 5) || // Server response is 3 digit error code, a space or hyphen and then at least one letter of text
					(line[3] != ' ' && line[3] != '-')) {
					pomlog(POMLOG_DEBUG "Too short or invalid response from server");
					priv->flags |= PROTO_SMTP_FLAG_INVALID;
					return POM_OK;
				}

				int code = 0;
				if (sscanf(line, "%3u", &code) != 1 || code == 0) {
					pomlog(POMLOG_DEBUG "Invalid response from server");
					priv->flags |= PROTO_SMTP_FLAG_INVALID;
					return POM_OK;
				}
				
				if (line[3] == '-') {
					priv->state = proto_smtp_state_server_multiline;
					continue;
				}
				
				priv->state = proto_smtp_state_client_cmd;
				// Buffer should be empty, we should return POM_OK
				continue;

			}

		}


		if (priv->flags & PROTO_SMTP_FLAG_DATA) {
			pomlog(POMLOG_DEBUG "Got data ");

		} else {

			if (priv->server_direction == s->direction) {
				
				if ((len < 5) || // 3 digit number, one space or hyphen, at least one letter of text
					(line[3] != ' ' && line[3] != '-')) { // Response code must be followed by space or hyphen

					pomlog(POMLOG_DEBUG "Too short or invalid response from server");
					priv->flags |= PROTO_SMTP_FLAG_INVALID;
					return PROTO_OK;
				}



				// Handle responses from the server
				unsigned int code = 0;
				if (sscanf(line, "%3u", &code) != 1 || code == 0) {
					pomlog(POMLOG_DEBUG "Invalid response received from server");
					priv->flags |= PROTO_SMTP_FLAG_INVALID;
					return PROTO_OK;
				}

			}
		}


		pomlog(POMLOG_ERR "Got line : %s", line);

	}

	return PROTO_OK;

}

static int proto_smtp_conntrack_cleanup(void *ce_priv) {

	struct proto_smtp_conntrack_priv *priv = ce_priv;
	if (!priv)
		return POM_OK;

	if (priv->parser)
		packet_stream_parser_cleanup(priv->parser);

	return POM_OK;
}

static int proto_smtp_mod_unregister() {

	return proto_unregister("smtp");

}
