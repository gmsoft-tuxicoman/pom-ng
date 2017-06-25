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

#include "analyzer_imap.h"
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint64.h>
#include <pom-ng/proto_imap.h>
#include <pom-ng/decoder.h>
#include <pom-ng/dns.h>
#include <pom-ng/pload.h>

struct mod_reg_info *analyzer_imap_reg_info() {
	
	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_imap_mod_register;
	reg_info.unregister_func = analyzer_imap_mod_unregister;
	reg_info.dependencies = "proto_imap, ptype_bool, ptype_string, ptype_uint16, ptype_uint64";

	return &reg_info;
}

static int analyzer_imap_mod_register(struct mod_reg *mod) {
	
	static struct analyzer_reg analyzer_imap = { 0 };
	analyzer_imap.name = "imap";
	analyzer_imap.mod = mod;
	analyzer_imap.init = analyzer_imap_init;
	analyzer_imap.cleanup = analyzer_imap_cleanup;

	return analyzer_register(&analyzer_imap);
}

static int analyzer_imap_mod_unregister() {
	
	return analyzer_unregister("imap");
}

static int analyzer_imap_init(struct analyzer *analyzer) {

	struct analyzer_imap_priv *priv = malloc(sizeof(struct analyzer_imap_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_imap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_imap_priv));

	analyzer->priv = priv;

	priv->evt_cmd = event_find("imap_cmd");
	priv->evt_rsp = event_find("imap_rsp");
	priv->evt_pload = event_find("imap_pload");
	if (!priv->evt_cmd || !priv->evt_rsp || !priv->evt_pload)
		goto err;

	static struct data_item_reg evt_msg_data_items[ANALYZER_IMAP_EVT_MSG_DATA_COUNT] = { { 0 } };

	evt_msg_data_items[analyzer_imap_common_client_addr].name = "client_addr";
	evt_msg_data_items[analyzer_imap_common_client_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_msg_data_items[analyzer_imap_common_server_addr].name = "server_addr";
	evt_msg_data_items[analyzer_imap_common_server_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_msg_data_items[analyzer_imap_common_server_port].name = "server_port";
	evt_msg_data_items[analyzer_imap_common_server_port].value_type = ptype_get_type("uint16");
	evt_msg_data_items[analyzer_imap_common_server_host].name = "server_host";
	evt_msg_data_items[analyzer_imap_common_server_host].value_type = ptype_get_type("string");


	evt_msg_data_items[analyzer_imap_msg_mailbox].name = "mailbox";
	evt_msg_data_items[analyzer_imap_msg_mailbox].value_type = ptype_get_type("string");
	evt_msg_data_items[analyzer_imap_msg_uid].name = "uid";
	evt_msg_data_items[analyzer_imap_msg_uid].value_type = ptype_get_type("uint64");

	static struct data_reg evt_msg_data = {
		.items = evt_msg_data_items,
		.data_count = ANALYZER_IMAP_EVT_MSG_DATA_COUNT
	};

	static struct event_reg_info analyzer_imap_evt_msg = { 0 };
	analyzer_imap_evt_msg.source_name = "analyzer_imap";
	analyzer_imap_evt_msg.source_obj = analyzer;
	analyzer_imap_evt_msg.name = "imap_msg";
	analyzer_imap_evt_msg.description = "message received over imap";
	analyzer_imap_evt_msg.data_reg = &evt_msg_data;
	analyzer_imap_evt_msg.listeners_notify = analyzer_imap_event_listeners_notify;
	analyzer_imap_evt_msg.priv_cleanup = analyzer_imap_evt_msg_cleanup;
	analyzer_imap_evt_msg.flags = EVENT_REG_FLAG_PAYLOAD;

	priv->evt_msg = event_register(&analyzer_imap_evt_msg);
	if (!priv->evt_msg)
		goto err;


	static struct data_item_reg evt_auth_data_items[ANALYZER_IMAP_EVT_AUTH_DATA_COUNT] = { { 0 } };
	evt_auth_data_items[analyzer_imap_common_client_addr].name = "client_addr";
	evt_auth_data_items[analyzer_imap_common_client_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_auth_data_items[analyzer_imap_common_server_addr].name = "server_addr";
	evt_auth_data_items[analyzer_imap_common_server_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_auth_data_items[analyzer_imap_common_server_port].name = "server_port";
	evt_auth_data_items[analyzer_imap_common_server_port].value_type = ptype_get_type("uint16");
	evt_auth_data_items[analyzer_imap_common_server_host].name = "server_host";
	evt_auth_data_items[analyzer_imap_common_server_host].value_type = ptype_get_type("string");

	evt_auth_data_items[analyzer_imap_auth_type].name = "type";
	evt_auth_data_items[analyzer_imap_auth_type].value_type = ptype_get_type("string");
	evt_auth_data_items[analyzer_imap_auth_params].name = "params";
	evt_auth_data_items[analyzer_imap_auth_params].flags = DATA_REG_FLAG_LIST;
	evt_auth_data_items[analyzer_imap_auth_success].name = "success";
	evt_auth_data_items[analyzer_imap_auth_success].value_type = ptype_get_type("bool");

	static struct data_reg evt_auth_data = {
		.items = evt_auth_data_items,
		.data_count = ANALYZER_IMAP_EVT_AUTH_DATA_COUNT
	};

	static struct event_reg_info analyzer_imap_evt_auth = { 0 };
	analyzer_imap_evt_auth.source_name = "analyzer_imap";
	analyzer_imap_evt_auth.source_obj = analyzer;
	analyzer_imap_evt_auth.name = "imap_auth";
	analyzer_imap_evt_auth.description = "IMAP authentication attempts";
	analyzer_imap_evt_auth.data_reg = &evt_auth_data;
	analyzer_imap_evt_auth.listeners_notify = analyzer_imap_event_listeners_notify;

	priv->evt_auth = event_register(&analyzer_imap_evt_auth);
	if (!priv->evt_auth)
		goto err;
	

	return POM_OK;

err:
	analyzer_imap_cleanup(analyzer);

	return POM_ERR;
}

static int analyzer_imap_cleanup(struct analyzer *analyzer) {

	struct analyzer_imap_priv *priv = analyzer->priv;

	if (priv->pkt_listener && (proto_packet_listener_unregister(priv->pkt_listener) != POM_OK))
		return POM_ERR;

	if (priv->listening) {
		event_listener_unregister(priv->evt_cmd, analyzer);
		event_listener_unregister(priv->evt_rsp, analyzer);
	}

	if (priv->evt_msg)
		event_unregister(priv->evt_msg);

	if (priv->evt_auth)
		event_unregister(priv->evt_auth);

	free(priv);

	return POM_OK;
}

static int analyzer_imap_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_imap_priv *priv = analyzer->priv;

	if (evt_reg == priv->evt_msg) {
		if (has_listeners) {
			priv->pkt_listener = proto_packet_listener_register(proto_get("imap"), PROTO_PACKET_LISTENER_PLOAD_ONLY, analyzer, analyzer_imap_pkt_process, NULL);
			if (!priv->pkt_listener)
				return POM_ERR;
			if (event_listener_register(priv->evt_pload, analyzer, analyzer_imap_pload_event_process_begin, analyzer_imap_pload_event_process_end, NULL) != POM_OK) {
				proto_packet_listener_unregister(priv->pkt_listener);
				priv->pkt_listener = NULL;
				return POM_ERR;
			}
		} else {
			event_listener_unregister(priv->evt_pload, analyzer);
			proto_packet_listener_unregister(priv->pkt_listener);
			priv->pkt_listener = NULL;
		}
	}

	if (!priv->listening && (event_has_listener(priv->evt_msg) || event_has_listener(priv->evt_auth))) {
		

		if (event_listener_register(priv->evt_cmd, analyzer, analyzer_imap_event_process_begin, analyzer_imap_event_process_end, NULL) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_rsp, analyzer, analyzer_imap_event_process_begin, analyzer_imap_event_process_end, NULL) != POM_OK) {
			event_listener_unregister(priv->evt_cmd, analyzer);
			return POM_ERR;
		}

		priv->listening = 1;

	} else if (priv->listening && !event_has_listener(priv->evt_msg) && !event_has_listener(priv->evt_auth)) {

		event_listener_unregister(priv->evt_cmd, analyzer);
		event_listener_unregister(priv->evt_rsp, analyzer);

		priv->listening = 0;

	}



	return POM_OK;
}

static int analyzer_imap_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct proto_process_stack *s = &stack[stack_index - 1];
	if (!s->ce)
		return POM_ERR;

	struct analyzer_imap_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);

	if (!cpriv)
		return POM_ERR;

	if (!event_is_started(cpriv->evt_msg)) {
		pomlog(POMLOG_ERR "Payload received while data event not found");
		return POM_OK;
	}

	struct pload *pload_buff = event_get_priv(cpriv->evt_msg);

	if (!pload_buff) {
		pload_buff = pload_alloc(cpriv->evt_msg, 0);
		pload_set_type(pload_buff, ANALYZER_IMAP_RFC822_PLOAD_TYPE);
		if (!pload_buff)
			return POM_ERR;

		event_set_priv(cpriv->evt_msg, pload_buff);
	}

	//struct proto_process_stack *pload_stack = &stack[stack_index];

	//char *pload = pload_stack->pload;
	//size_t plen = pload_stack->plen;



	return POM_OK;
}

static int analyzer_imap_event_fill_common_data(struct analyzer_imap_ce_priv *cpriv, struct data *data) {

	if (cpriv->client_addr) {
		data[analyzer_imap_common_client_addr].value = ptype_alloc_from(cpriv->client_addr);
		data[analyzer_imap_common_client_addr].flags &= ~DATA_FLAG_NO_CLEAN;
		if (data[analyzer_imap_common_client_addr].value)
			data_set(data[analyzer_imap_common_client_addr]);
	}

	if (cpriv->server_addr) {
		data[analyzer_imap_common_server_addr].value = ptype_alloc_from(cpriv->server_addr);
		data[analyzer_imap_common_server_addr].flags &= ~DATA_FLAG_NO_CLEAN;
		if (data[analyzer_imap_common_server_addr].value)
			data_set(data[analyzer_imap_common_server_addr]);
	}

	if (cpriv->server_port) {
		PTYPE_UINT16_SETVAL(data[analyzer_imap_common_server_port].value, cpriv->server_port);
		data_set(data[analyzer_imap_common_server_port]);
	}

	if (cpriv->server_host) {
		PTYPE_STRING_SETVAL(data[analyzer_imap_common_server_host].value, cpriv->server_host);
		data_set(data[analyzer_imap_common_server_host]);
	}

	return POM_OK;

}

static int analyzer_imap_queue_cmd(struct analyzer_imap_ce_priv *cpriv, enum analyzer_imap_cmd cmd_type, struct event *cmd_evt, struct event *out_evt) {

	struct data *evt_data = event_get_data(cmd_evt);

	struct analyzer_imap_cmd_entry *cmd = malloc(sizeof(struct analyzer_imap_cmd_entry));
	if (!cmd) {
		pom_oom(sizeof(struct analyzer_imap_cmd_entry));
		return POM_ERR;
	}
	memset(cmd, 0, sizeof(struct analyzer_imap_cmd_entry));

	cmd->tag = PTYPE_STRING_GETVAL(evt_data[proto_imap_cmd_tag].value);
	cmd->cmd = cmd_type;
	cmd->cmd_evt = cmd_evt;
	cmd->out_evt = out_evt;
	event_refcount_inc(cmd_evt);

	cmd->prev = cpriv->cmd_queue_tail;
	if (cmd->prev)
		cmd->prev->next = cmd;
	else
		cpriv->cmd_queue_head = cmd;

	return POM_OK;
}

static int analyzer_imap_parse_auth_plain(struct analyzer_imap_priv *apriv, struct analyzer_imap_ce_priv *cpriv, struct event *evt_auth, char *auth_plain) {

	// Parse SASL AUTH PLAIN as described in RFC 4616

	// The decoded arg must be at least 3 bytes
	if (strlen(auth_plain) < 4 || memchr(auth_plain, '=', 4)) {
		pomlog(POMLOG_DEBUG "AUTH PLAIN argument too short");
		return POM_OK;
	}

	struct data *evt_data = event_get_data(evt_auth);
	analyzer_imap_event_fill_common_data(cpriv, evt_data);

	// Set the authentication type
	PTYPE_STRING_SETVAL(evt_data[analyzer_imap_auth_type].value, "PLAIN");
	data_set(evt_data[analyzer_imap_auth_type]);

	// Parse the authentication stuff
	char *creds_str = NULL;
	size_t out_len = 0;
	if (decoder_decode_simple("base64", auth_plain, strlen(auth_plain), &creds_str, &out_len) != POM_OK) {
		pomlog(POMLOG_DEBUG "Unable to decode AUTH PLAIN message");
		return POM_OK;
	}

	if (out_len < 3) {
		pomlog(POMLOG_DEBUG "Invalid decoded AUTH PLAIN data");
		return POM_OK;
	}


	char *tmp = creds_str;

	// Add the identity
	if (strlen(tmp)) {
		// SASL AUTH PLAIN specifies 
		struct ptype *identity = ptype_alloc("string");
		if (!identity)
			goto err;
		PTYPE_STRING_SETVAL(identity, tmp);
		if (data_item_add_ptype(evt_data, analyzer_imap_auth_params, strdup("identity"), identity) != POM_OK) {
			ptype_cleanup(identity);
			goto err;
		}
	}
	tmp += strlen(tmp) + 1;
	
	// Add the username
	struct ptype *username = ptype_alloc("string");
	if (!username)
		goto err;
	PTYPE_STRING_SETVAL(username, tmp);
	if (data_item_add_ptype(evt_data, analyzer_imap_auth_params, strdup("username"), username) != POM_OK) {
		ptype_cleanup(username);
		goto err;
	}
	tmp += strlen(tmp) + 1;

	// Add the password
	struct ptype *password = ptype_alloc("string");
	if (!password)
		goto err;
	PTYPE_STRING_SETVAL(password, tmp);
	if (data_item_add_ptype(evt_data, analyzer_imap_auth_params, strdup("password"), password) != POM_OK) {
		ptype_cleanup(password);
		goto err;
	}

	free(creds_str);


	return POM_OK;

err:

	free(creds_str);

	return POM_ERR;
}

static int analyzer_imap_event_fetch_common_data(struct analyzer_imap_ce_priv *cpriv, struct proto_process_stack *stack, unsigned int stack_index, int server_direction) {

	struct  proto_process_stack *l4_stack = &stack[stack_index - 1];
	struct  proto_process_stack *l3_stack = &stack[stack_index - 2];

	int i;

	char *port_str = "dport";
	if (server_direction == POM_DIR_REV)
		port_str = "sport";
	
	for (i = 0; !cpriv->server_port; i++) {
		struct proto_reg_info *l4_info = proto_get_info(l4_stack->proto);
		char *name = l4_info->pkt_fields[i].name;
		if (!name)
			break;
		if (!strcmp(name, port_str))
			cpriv->server_port = *PTYPE_UINT16_GETVAL(l4_stack->pkt_info->fields_value[i]);
	}


	struct ptype *src = NULL, *dst = NULL;
	for (i = 0; !src || !dst; i++) {
		struct proto_reg_info *l3_info = proto_get_info(l3_stack->proto);
		char *name = l3_info->pkt_fields[i].name;
		if (!name)
			break;

		if (!src && !strcmp(name, "src"))
			src = l3_stack->pkt_info->fields_value[i];
		else if (!dst && !strcmp(name, "dst"))
			dst = l3_stack->pkt_info->fields_value[i];
	}

	if (server_direction == POM_DIR_FWD) {
		if (src)
			cpriv->client_addr = ptype_alloc_from(src);
		if (dst)
			cpriv->server_addr = ptype_alloc_from(dst);
	} else {
		if (src)
			cpriv->server_addr = ptype_alloc_from(src);
		if (dst)
			cpriv->client_addr = ptype_alloc_from(dst);
	}

	if (cpriv->server_addr) {
		char *host = dns_reverse_lookup_ptype(cpriv->server_addr);
		if (host)
			cpriv->server_host = host;
	}

	cpriv->common_data_fetched = 1;

	return POM_OK;
}

static int analyzer_imap_pload_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {
	return POM_OK;
}

static int analyzer_imap_pload_event_process_end(struct event *evt, void *obj) {
	return POM_OK;
}

static void analyzer_imap_invalidate_mbx(struct analyzer_imap_ce_priv *cpriv) {

	if (cpriv->cur_mbx)
		free(cpriv->cur_mbx);
	cpriv->cur_mbx = NULL;


	// TODO We need to actually queue msg here and make use of them
	while (cpriv->msg_queue_head) {
		struct analyzer_imap_msg *msg = cpriv->msg_queue_head;
		cpriv->msg_queue_head = msg->next;
		free(msg);
	}
	cpriv->msg_queue_tail = NULL;

}

static int analyzer_imap_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct analyzer_imap_priv *apriv = analyzer->priv;
	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce)
		return POM_ERR;

	// Only process stuff if we have the DATA event or if we already have an event
	struct event_reg *evt_reg = event_get_reg(evt);
	struct data *evt_data = event_get_data(evt);

	struct analyzer_imap_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);
	
	// It's expected that an IMAP connection will always contain at least one message
	// So we always create the cpriv and event, no matter what
	if (!cpriv) {
		cpriv = malloc(sizeof(struct analyzer_imap_ce_priv));
		if (!cpriv) {
			pom_oom(sizeof(struct analyzer_imap_ce_priv));
			return POM_ERR;
		}
		memset(cpriv, 0, sizeof(struct analyzer_imap_ce_priv));

		if (conntrack_add_priv(s->ce, analyzer, cpriv, analyzer_imap_ce_priv_cleanup) != POM_OK) {
			free(cpriv);
			return POM_ERR;
		}
	}

	if (!cpriv->common_data_fetched)
		analyzer_imap_event_fetch_common_data(cpriv, stack, stack_index, s->direction);

	if (evt_reg == apriv->evt_cmd) {

		char *cmd = PTYPE_STRING_GETVAL(evt_data[proto_imap_cmd_name].value);
		char *arg = NULL;

		if (data_is_set(evt_data[proto_imap_cmd_arg]))
			arg = PTYPE_STRING_GETVAL(evt_data[proto_imap_cmd_arg].value);

		if (!strcasecmp(cmd, "LOGIN")) {

			if (!arg)
				return POM_OK;

			char *pwd = strchr(arg, ' ');
			if (!pwd) {
				// No password found
				pomlog(POMLOG_DEBUG "No password found in LOGIN auth string");
				return POM_OK;
			}
			// We got some auth !
			struct ptype *username = ptype_alloc("string");
			if (!username)
				return POM_ERR;

			size_t username_len = pwd - arg;
			pwd++;

			PTYPE_STRING_SETVAL_N(username, arg, username_len);

			struct ptype *password = ptype_alloc("string");
			if (!password) {
				ptype_cleanup(username);
				return POM_ERR;
			}

			PTYPE_STRING_SETVAL(password, pwd);

			struct event *evt_auth = event_alloc(apriv->evt_auth);
			if (!evt_auth) {
				ptype_cleanup(username);
				ptype_cleanup(password);
				return POM_ERR;
			}

			struct data *auth_data = event_get_data(evt_auth);
			analyzer_imap_event_fill_common_data(cpriv, auth_data);

			PTYPE_STRING_SETVAL(auth_data[analyzer_imap_auth_type].value, "LOGIN");
			data_set(auth_data[analyzer_imap_auth_type]);

			if (data_item_add_ptype(auth_data, analyzer_imap_auth_params, strdup("username"), username) != POM_OK) {
				ptype_cleanup(username);
				ptype_cleanup(password);
				event_cleanup(evt_auth);
				return POM_ERR;
			}

			if (data_item_add_ptype(auth_data, analyzer_imap_auth_params, strdup("password"), password) != POM_OK) {
				ptype_cleanup(password);
				event_cleanup(evt_auth);
				return POM_ERR;
			}
			if (analyzer_imap_queue_cmd(cpriv, analyzer_imap_cmd_auth, evt, evt_auth) != POM_OK) {
				event_cleanup(evt_auth);
				return POM_ERR;
			}

			if (event_process_begin(evt_auth, stack, stack_index, event_get_timestamp(evt)) != POM_OK)
				return POM_ERR;
		} else if (!strcasecmp(cmd, "AUTHENTICATE")) {
			if (!arg) // Invalid command, AUTHENTICATE needs an argument
				return POM_OK;

			if (!strncasecmp(arg, "PLAIN ", strlen("PLAIN "))) {
				arg += strlen("PLAIN ");

				struct event* evt_auth = event_alloc(apriv->evt_auth);
				if (!evt_auth)
					return POM_ERR;
				if (analyzer_imap_parse_auth_plain(apriv, cpriv, evt_auth, arg) == POM_ERR) {
					event_cleanup(evt_auth);
					return POM_ERR;
				}
				if (analyzer_imap_queue_cmd(cpriv, analyzer_imap_cmd_auth, evt, evt_auth) != POM_OK) {
					event_cleanup(evt_auth);
					return POM_ERR;
				}

				if (event_process_begin(evt_auth, stack, stack_index, event_get_timestamp(evt)) != POM_OK)
					return POM_ERR;
			}


		} else if (!strcasecmp(cmd, "SELECT") || !strcasecmp(cmd, "EXAMINE")) {
			if (!arg)
				return POM_OK;

			analyzer_imap_invalidate_mbx(cpriv);

			cpriv->cur_mbx = strdup(arg);
			if (!cpriv->cur_mbx) {
				pom_oom(strlen(arg) + 1);
				return POM_ERR;
			}
		}

	} else if (evt_reg == apriv->evt_rsp) {

		char *tag = PTYPE_STRING_GETVAL(evt_data[proto_imap_response_tag].value);

		// Check if it this is the completion of a command only if it's a tagged result
		struct analyzer_imap_cmd_entry *cmd = NULL;
		if (strcmp(tag, "*") && strcmp(tag, "+")) {
			// Check only for the command if the tag is a number
			for (cmd = cpriv->cmd_queue_head; cmd && strcmp(cmd->tag, tag); cmd = cmd->next);
		}


		// Handle the command
		if (cmd) {
			enum analyzer_imap_rsp_status status = analyzer_imap_rsp_status_unk;
			char *status_str = PTYPE_STRING_GETVAL(evt_data[proto_imap_response_status].value);
			if (!strcasecmp(status_str, "OK")) {
				status = analyzer_imap_rsp_status_ok;
			} else if (!strcasecmp(status_str, "NO")) {
				status = analyzer_imap_rsp_status_no;
			} else if (!strcasecmp(status_str, "BAD")) {
				status = analyzer_imap_rsp_status_bad;
			} else if (!strcasecmp(status_str, "BYE")) {
				status = analyzer_imap_rsp_status_bye;
			}


			// We've got a match

			if (cmd->prev)
				cmd->prev->next = cmd->next;
			else
				cpriv->cmd_queue_head = cmd->next;

			if (cmd->next)
				cmd->next->prev = cmd->prev;
			else
				cpriv->cmd_queue_tail = cmd->prev;

			event_refcount_dec(cmd->cmd_evt);

			struct event *out_evt = cmd->out_evt;

			enum analyzer_imap_cmd cmd_type = cmd->cmd;

			free(cmd);

			struct data *out_data = event_get_data(out_evt);

			switch (cmd_type) {
				case analyzer_imap_cmd_unk:
					pomlog(POMLOG_ERR "Unknown CMD found in queue list");
					if (out_evt)
						event_process_end(out_evt);
					return POM_ERR;
				case analyzer_imap_cmd_auth:
					if (status == analyzer_imap_rsp_status_ok) {
						PTYPE_BOOL_SETVAL(out_data[analyzer_imap_auth_success].value, 1);
						data_set(out_data[analyzer_imap_auth_success]);
					} else if (status == analyzer_imap_rsp_status_no) {
						PTYPE_BOOL_SETVAL(out_data[analyzer_imap_auth_success].value, 0);
						data_set(out_data[analyzer_imap_auth_success]);
					}
					break;
			}

			if (event_process_end(out_evt) != POM_OK)
				return POM_ERR;

			// No more processing needed for this reply
			return POM_OK;
		}

		char *status = NULL;
		if (data_is_set(evt_data[proto_imap_response_status]))
			status = PTYPE_STRING_GETVAL(evt_data[proto_imap_response_status].value);

		if (!status)
			return POM_OK;

		if (!strcmp(tag, "*")) {
			if (!strcasecmp(status, "FLAGS")) {
				// FLAGS response appear only for SELECT or EXAMINE
				// Since we switched mailbox we need to flush what we know about messages
				analyzer_imap_invalidate_mbx(cpriv);
			}
		}

	}


	return POM_OK;
}

static int analyzer_imap_event_process_end(struct event *evt, void *obj) {

	return POM_OK;
}

static int analyzer_imap_ce_priv_cleanup(void *obj, void *priv) {

	struct analyzer_imap_ce_priv *cpriv = priv;

	if (cpriv->evt_msg) {
		if (event_is_started(cpriv->evt_msg))
			event_process_end(cpriv->evt_msg);
		else
			event_cleanup(cpriv->evt_msg);
	}

	if (cpriv->server_host)
		free(cpriv->server_host);
	if (cpriv->client_addr)
		ptype_cleanup(cpriv->client_addr);
	if (cpriv->server_addr)
		ptype_cleanup(cpriv->server_addr);


	while (cpriv->cmd_queue_head) {
		struct analyzer_imap_cmd_entry *cmd = cpriv->cmd_queue_head;
		cpriv->cmd_queue_head = cmd->next;
		event_refcount_dec(cmd->cmd_evt);
		event_process_end(cmd->out_evt);
		free(cmd);
	}


	analyzer_imap_invalidate_mbx(cpriv);

	free(cpriv);

	return POM_OK;
}

static int analyzer_imap_evt_msg_cleanup(void *priv) {

	pload_end(priv);
	return POM_OK;
}
