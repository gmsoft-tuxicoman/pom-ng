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

#include "analyzer_smtp.h"
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/proto_smtp.h>
#include <pom-ng/decoder.h>
#include <pom-ng/dns.h>

struct mod_reg_info *analyzer_smtp_reg_info() {
	
	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_smtp_mod_register;
	reg_info.unregister_func = analyzer_smtp_mod_unregister;
	reg_info.dependencies = "proto_smtp, ptype_bool, ptype_string, ptype_uint16";

	return &reg_info;
}

static int analyzer_smtp_mod_register(struct mod_reg *mod) {
	
	static struct analyzer_reg analyzer_smtp = { 0 };
	analyzer_smtp.name = "smtp";
	analyzer_smtp.api_ver = ANALYZER_API_VER;
	analyzer_smtp.mod = mod;
	analyzer_smtp.init = analyzer_smtp_init;
	analyzer_smtp.cleanup = analyzer_smtp_cleanup;

	return analyzer_register(&analyzer_smtp);
}

static int analyzer_smtp_mod_unregister() {
	
	return analyzer_unregister("smtp");
}

static int analyzer_smtp_init(struct analyzer *analyzer) {

	struct analyzer_smtp_priv *priv = malloc(sizeof(struct analyzer_smtp_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_smtp_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_smtp_priv));

	analyzer->priv = priv;

	priv->rfc822_msg_pload_type = analyzer_pload_type_get_by_name("rfc822");
	if (!priv->rfc822_msg_pload_type)
		goto err;

	priv->evt_cmd = event_find("smtp_cmd");
	priv->evt_reply = event_find("smtp_reply");
	if (!priv->evt_cmd || !priv->evt_reply)
		goto err;

	static struct data_item_reg evt_msg_data_items[ANALYZER_SMTP_EVT_MSG_DATA_COUNT] = { { 0 } };

	evt_msg_data_items[analyzer_smtp_common_client_addr].name = "client_addr";
	evt_msg_data_items[analyzer_smtp_common_client_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_msg_data_items[analyzer_smtp_common_server_addr].name = "server_addr";
	evt_msg_data_items[analyzer_smtp_common_server_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_msg_data_items[analyzer_smtp_common_server_port].name = "server_port";
	evt_msg_data_items[analyzer_smtp_common_server_port].value_type = ptype_get_type("uint16");
	evt_msg_data_items[analyzer_smtp_common_server_host].name = "server_host";
	evt_msg_data_items[analyzer_smtp_common_server_host].value_type = ptype_get_type("string");
	evt_msg_data_items[analyzer_smtp_common_server_hello].name = "server_hello";
	evt_msg_data_items[analyzer_smtp_common_server_hello].value_type = ptype_get_type("string");
	evt_msg_data_items[analyzer_smtp_common_client_hello].name = "client_hello";
	evt_msg_data_items[analyzer_smtp_common_client_hello].value_type = ptype_get_type("string");


	evt_msg_data_items[analyzer_smtp_msg_from].name = "from";
	evt_msg_data_items[analyzer_smtp_msg_from].value_type = ptype_get_type("string");
	evt_msg_data_items[analyzer_smtp_msg_to].name = "to";
	evt_msg_data_items[analyzer_smtp_msg_to].flags = DATA_REG_FLAG_LIST;
	evt_msg_data_items[analyzer_smtp_msg_result].name = "result";
	evt_msg_data_items[analyzer_smtp_msg_result].value_type = ptype_get_type("uint16");

	static struct data_reg evt_msg_data = {
		.items = evt_msg_data_items,
		.data_count = ANALYZER_SMTP_EVT_MSG_DATA_COUNT
	};

	static struct event_reg_info analyzer_smtp_evt_msg = { 0 };
	analyzer_smtp_evt_msg.source_name = "analyzer_smtp";
	analyzer_smtp_evt_msg.source_obj = analyzer;
	analyzer_smtp_evt_msg.name = "smtp_msg";
	analyzer_smtp_evt_msg.description = "message received over smtp";
	analyzer_smtp_evt_msg.data_reg = &evt_msg_data;
	analyzer_smtp_evt_msg.listeners_notify = analyzer_smtp_event_listeners_notify;
	analyzer_smtp_evt_msg.cleanup = analyzer_smtp_evt_msg_cleanup;

	priv->evt_msg = event_register(&analyzer_smtp_evt_msg);
	if (!priv->evt_msg)
		goto err;


	static struct data_item_reg evt_auth_data_items[ANALYZER_SMTP_EVT_AUTH_DATA_COUNT] = { { 0 } };
	evt_auth_data_items[analyzer_smtp_common_client_addr].name = "client_addr";
	evt_auth_data_items[analyzer_smtp_common_client_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_auth_data_items[analyzer_smtp_common_server_addr].name = "server_addr";
	evt_auth_data_items[analyzer_smtp_common_server_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_auth_data_items[analyzer_smtp_common_server_port].name = "server_port";
	evt_auth_data_items[analyzer_smtp_common_server_port].value_type = ptype_get_type("uint16");
	evt_auth_data_items[analyzer_smtp_common_server_host].name = "server_host";
	evt_auth_data_items[analyzer_smtp_common_server_host].value_type = ptype_get_type("string");
	evt_auth_data_items[analyzer_smtp_common_server_hello].name = "server_hello";
	evt_auth_data_items[analyzer_smtp_common_server_hello].value_type = ptype_get_type("string");
	evt_auth_data_items[analyzer_smtp_common_client_hello].name = "client_hello";
	evt_auth_data_items[analyzer_smtp_common_client_hello].value_type = ptype_get_type("string");

	evt_auth_data_items[analyzer_smtp_auth_type].name = "type";
	evt_auth_data_items[analyzer_smtp_auth_type].value_type = ptype_get_type("string");
	evt_auth_data_items[analyzer_smtp_auth_params].name = "params";
	evt_auth_data_items[analyzer_smtp_auth_params].flags = DATA_REG_FLAG_LIST;
	evt_auth_data_items[analyzer_smtp_auth_success].name = "success";
	evt_auth_data_items[analyzer_smtp_auth_success].value_type = ptype_get_type("bool");

	static struct data_reg evt_auth_data = {
		.items = evt_auth_data_items,
		.data_count = ANALYZER_SMTP_EVT_AUTH_DATA_COUNT
	};

	static struct event_reg_info analyzer_smtp_evt_auth = { 0 };
	analyzer_smtp_evt_auth.source_name = "analyzer_smtp";
	analyzer_smtp_evt_auth.source_obj = analyzer;
	analyzer_smtp_evt_auth.name = "smtp_auth";
	analyzer_smtp_evt_auth.description = "SMTP authentication attempts";
	analyzer_smtp_evt_auth.data_reg = &evt_auth_data;
	analyzer_smtp_evt_auth.listeners_notify = analyzer_smtp_event_listeners_notify;

	priv->evt_auth = event_register(&analyzer_smtp_evt_auth);
	if (!priv->evt_auth)
		goto err;
	

	return POM_OK;

err:
	analyzer_smtp_cleanup(analyzer);

	return POM_ERR;
}

static int analyzer_smtp_cleanup(struct analyzer *analyzer) {

	struct analyzer_smtp_priv *priv = analyzer->priv;

	if (priv->pkt_listener) {
		proto_packet_listener_unregister(priv->pkt_listener);
	}

	if (priv->listening) {
		event_listener_unregister(priv->evt_cmd, analyzer);
		event_listener_unregister(priv->evt_reply, analyzer);
	}

	if (priv->evt_msg)
		event_unregister(priv->evt_msg);

	free(priv);

	return POM_OK;
}

static int analyzer_smtp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_smtp_priv *priv = analyzer->priv;

	if (evt_reg == priv->evt_msg) {
		if (has_listeners) {
			priv->pkt_listener = proto_packet_listener_register(proto_get("smtp"), PROTO_PACKET_LISTENER_PLOAD_ONLY, obj, analyzer_smtp_pkt_process);
			if (!priv->pkt_listener)
				return POM_ERR;
		} else {
			if (proto_packet_listener_unregister(priv->pkt_listener) != POM_OK)
				return POM_ERR;
			priv->pkt_listener = NULL;
		}
	}

	if (!priv->listening && (event_has_listener(priv->evt_msg) || event_has_listener(priv->evt_auth))) {
		

		if (event_listener_register(priv->evt_cmd, analyzer, analyzer_smtp_event_process_begin, analyzer_smtp_event_process_end) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_reply, analyzer, analyzer_smtp_event_process_begin, analyzer_smtp_event_process_end) != POM_OK) {
			event_listener_unregister(priv->evt_cmd, analyzer);
			return POM_ERR;
		}

		priv->listening = 1;

	} else if (priv->listening && !event_has_listener(priv->evt_msg) && !event_has_listener(priv->evt_auth)) {

		event_listener_unregister(priv->evt_cmd, analyzer);
		event_listener_unregister(priv->evt_reply, analyzer);

		priv->listening = 0;

	}



	return POM_OK;
}

static int analyzer_smtp_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct proto_process_stack *s = &stack[stack_index - 1];
	if (!s->ce)
		return POM_ERR;

	struct analyzer_smtp_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);

	if (!event_is_started(cpriv->evt_msg)) {
		pomlog(POMLOG_ERR "Payload received while data event not found");
		return POM_OK;
	}

	struct analyzer_pload_buffer *pload_buff = event_get_priv(cpriv->evt_msg);
	struct analyzer_smtp_priv *apriv = analyzer->priv;

	if (!pload_buff) {
		pload_buff = analyzer_pload_buffer_alloc(0, 0);
		analyzer_pload_buffer_set_type(pload_buff, apriv->rfc822_msg_pload_type);
		if (!pload_buff)
			return POM_ERR;

		event_set_priv(cpriv->evt_msg, pload_buff);
	}

	struct proto_process_stack *pload_stack = &stack[stack_index];

	char *pload = pload_stack->pload;
	size_t plen = pload_stack->plen;


	// Look for the end of the "<CR><LF>.." sequence if any
	if (cpriv->dotdot_pos > 0){
		int i, found = 1;
		for (i = 0; i < ANALYZER_SMTP_DOTDOT_LEN - cpriv->dotdot_pos && i <= plen; i++) {
			if (*(char*)(pload + i) != ANALYZER_SMTP_DOTDOT[cpriv->dotdot_pos + i]) {
				found = 0;
				break;
			}
		}
		if (i >= ANALYZER_SMTP_DOTDOT_LEN - cpriv->dotdot_pos) {
			if (found && (i >= ANALYZER_SMTP_DOTDOT_LEN - cpriv->dotdot_pos)) {
				// Process up to the last dot
				size_t len = ANALYZER_SMTP_DOTDOT_LEN - cpriv->dotdot_pos;
				if (analyzer_pload_buffer_append(pload_buff, pload, len - 1) != POM_OK)
					return POM_ERR;
				pload += len;
				plen -= len;

			}
			cpriv->dotdot_pos = 0;
		} else {
			cpriv->dotdot_pos += i;	
		}
	}

	while (plen) {
		char * dotdot = strstr(pload, ANALYZER_SMTP_DOTDOT);

		if (!dotdot)
			break;

		size_t dotdot_len = dotdot - pload + ANALYZER_SMTP_DOTDOT_LEN;
		if (analyzer_pload_buffer_append(pload_buff, pload, dotdot_len - 1) != POM_OK)
			return POM_ERR;
		pload = dotdot + ANALYZER_SMTP_DOTDOT_LEN;
		plen -= dotdot_len;

	}

	// Check for a possible partial dotdot at the end of the pload
	int i, found = 0;
	for (i = 1; (i < ANALYZER_SMTP_DOTDOT_LEN) && (i <= plen); i++) {
		if (!memcmp(pload + plen - i, ANALYZER_SMTP_DOTDOT, i)) {
			found = 1;
		}	break;
	}

	if (found)
		cpriv->dotdot_pos = i;

	// Add whatever remains
	if (plen && analyzer_pload_buffer_append(pload_buff, pload, plen) != POM_OK)
		return POM_ERR;

	return POM_OK;
}

static int analyzer_smtp_event_fill_common_data(struct analyzer_smtp_ce_priv *cpriv, struct data *data) {

	if (cpriv->client_hello) {
		PTYPE_STRING_SETVAL(data[analyzer_smtp_common_client_hello].value, cpriv->client_hello);
		data_set(data[analyzer_smtp_common_client_hello]);
	}

	if (cpriv->server_hello) {
		PTYPE_STRING_SETVAL(data[analyzer_smtp_common_server_hello].value, cpriv->server_hello);
		data_set(data[analyzer_smtp_common_server_hello]);
	}

	if (cpriv->client_addr) {
		data[analyzer_smtp_common_client_addr].value = ptype_alloc_from(cpriv->client_addr);
		data[analyzer_smtp_common_client_addr].flags &= ~DATA_FLAG_NO_CLEAN;
		if (data[analyzer_smtp_common_client_addr].value)
			data_set(data[analyzer_smtp_common_client_addr]);
	}

	if (cpriv->server_addr) {
		data[analyzer_smtp_common_server_addr].value = ptype_alloc_from(cpriv->server_addr);
		data[analyzer_smtp_common_server_addr].flags &= ~DATA_FLAG_NO_CLEAN;
		if (data[analyzer_smtp_common_server_addr].value)
			data_set(data[analyzer_smtp_common_server_addr]);
	}

	if (cpriv->server_port) {
		PTYPE_UINT16_SETVAL(data[analyzer_smtp_common_server_port].value, cpriv->server_port);
		data_set(data[analyzer_smtp_common_server_port]);
	}

	if (cpriv->server_host) {
		PTYPE_STRING_SETVAL(data[analyzer_smtp_common_server_host].value, cpriv->server_host);
		data_set(data[analyzer_smtp_common_server_host]);
	}

	return POM_OK;

}

static int analyzer_smtp_parse_auth_plain(struct analyzer_smtp_priv *apriv, struct analyzer_smtp_ce_priv *cpriv, char *auth_plain) {

	// Parse SASL AUTH PLAIN as described in RFC 4616

	// The decoded arg must be at least 3 bytes
	if (strlen(auth_plain) < 4 || memchr(auth_plain, '=', 4)) {
		pomlog(POMLOG_DEBUG "AUTH PLAIN argument too short");
		return POM_OK;
	}

	// Allocate the event
	cpriv->evt_auth = event_alloc(apriv->evt_auth);
	if (!cpriv->evt_auth)
		return POM_ERR;

	struct data *evt_data = event_get_data(cpriv->evt_auth);

	analyzer_smtp_event_fill_common_data(cpriv, evt_data);

	// Set the authentication type
	PTYPE_STRING_SETVAL(evt_data[analyzer_smtp_auth_type].value, "PLAIN");
	data_set(evt_data[analyzer_smtp_auth_type]);

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
		if (data_item_add_ptype(evt_data, analyzer_smtp_auth_params, strdup("identity"), identity) != POM_OK) {
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
	if (data_item_add_ptype(evt_data, analyzer_smtp_auth_params, strdup("username"), username) != POM_OK) {
		ptype_cleanup(username);
		goto err;
	}
	tmp += strlen(tmp) + 1;

	// Add the password
	struct ptype *password = ptype_alloc("string");
	if (!password)
		goto err;
	PTYPE_STRING_SETVAL(password, tmp);
	if (data_item_add_ptype(evt_data, analyzer_smtp_auth_params, strdup("password"), password) != POM_OK) {
		ptype_cleanup(password);
		goto err;
	}

	free(creds_str);
	return POM_OK;

err:

	event_cleanup(cpriv->evt_auth);
	cpriv->evt_auth = NULL;

	free(creds_str);

	return POM_ERR;
}

static int analyzer_smtp_event_fetch_common_data(struct analyzer_smtp_ce_priv *cpriv, struct proto_process_stack *stack, unsigned int stack_index, int server_direction) {

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
			cpriv->server_host = strdup(host);
	}

	cpriv->common_data_fetched = 1;

	return POM_OK;
}

static int analyzer_smtp_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct analyzer_smtp_priv *apriv = analyzer->priv;
	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce)
		return POM_ERR;

	// Only process stuff if we have the DATA event or if we already have an event
	struct event_reg *evt_reg = event_get_reg(evt);
	struct data *evt_data = event_get_data(evt);

	struct analyzer_smtp_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);
	
	// It's expected that an SMTP connection will always contain at least one message
	// So we always create the cpriv and event, no matter what
	if (!cpriv) {
		cpriv = malloc(sizeof(struct analyzer_smtp_ce_priv));
		if (!cpriv) {
			pom_oom(sizeof(struct analyzer_smtp_ce_priv));
			return POM_ERR;
		}
		memset(cpriv, 0, sizeof(struct analyzer_smtp_ce_priv));

		if (conntrack_add_priv(s->ce, analyzer, cpriv, analyzer_smtp_ce_priv_cleanup) != POM_OK) {
			free(cpriv);
			return POM_ERR;
		}
	}

	if (!cpriv->evt_msg) {
		cpriv->evt_msg = event_alloc(apriv->evt_msg);
		if (!cpriv->evt_msg)
			return POM_ERR;

	}


	struct data *msg_data = event_get_data(cpriv->evt_msg);
	
	if (evt_reg == apriv->evt_cmd) {

		if (!cpriv->common_data_fetched)
			analyzer_smtp_event_fetch_common_data(cpriv, stack, stack_index, POM_DIR_REVERSE(s->direction));


		// Process commands


		// A message was being transmitted and we recevied a new command
		if (event_is_started(cpriv->evt_msg)) {
			event_process_end(cpriv->evt_msg);
			cpriv->evt_msg = NULL;
		}

		char *cmd = PTYPE_STRING_GETVAL(evt_data[proto_smtp_cmd_name].value);
		if (!cmd)
			return POM_OK;

		char *arg = PTYPE_STRING_GETVAL(evt_data[proto_smtp_cmd_arg].value);
		if (arg) {
			while (*arg == ' ')
				arg++;
		}

		if (!strcasecmp(cmd, "MAIL")) {
			if (strncasecmp(arg, "FROM:", strlen("FROM:"))) {
				pomlog(POMLOG_DEBUG "Unparseable MAIL command");
				return POM_OK;
			}
			arg += strlen("FROM:");
			while (*arg == ' ')
				arg++;

			if (*arg == '<')
				arg++;

			size_t len;
			char *end = strchr(arg, '>');
			if (end)
				len = end - arg;
			else
				len = strlen(arg);

			PTYPE_STRING_SETVAL_N(msg_data[analyzer_smtp_msg_from].value, arg, len);
			data_set(msg_data[analyzer_smtp_msg_from]);
			cpriv->last_cmd = analyzer_smtp_last_cmd_mail_from;
			
		} else if (!strcasecmp(cmd, "RCPT")) {
			if (strncasecmp(arg, "TO:", strlen("TO:"))) {
				pomlog(POMLOG_DEBUG "Unparseable RCPT command");
				return POM_OK;
			}
			arg += strlen("TO:");
			while (*arg == ' ')
				arg++;

			if (*arg == '<')
				arg++;

			size_t len;
			char *end = strchr(arg, '>');
			if (end)
				len = end - arg;
			else
				len = strlen(arg);

			struct ptype *to = ptype_alloc("string");
			if (!to)
				return POM_ERR;

			PTYPE_STRING_SETVAL_N(to, arg, len);
			if (data_item_add_ptype(msg_data, analyzer_smtp_msg_to, strdup("to"), to) != POM_OK) {
				ptype_cleanup(to);
				return POM_ERR;
			}
			cpriv->last_cmd = analyzer_smtp_last_cmd_rcpt_to;

		} else if (!strcasecmp(cmd, "DATA")) {
			cpriv->last_cmd = analyzer_smtp_last_cmd_data;

			if (!event_is_started(cpriv->evt_msg)) {
				analyzer_smtp_event_fill_common_data(cpriv, msg_data);
				event_process_begin(cpriv->evt_msg, stack, stack_index, event_get_timestamp(evt));
			} else {
				pomlog(POMLOG_DEBUG "Message event already started !");
			}

		} else if (!strcasecmp(cmd, "RSET")) {
			// Cleanup the event
			event_cleanup(cpriv->evt_msg);
			cpriv->evt_msg = NULL;
			cpriv->last_cmd = analyzer_smtp_last_cmd_other;
		} else if (!strcasecmp(cmd, "HELO") || !strcasecmp(cmd, "EHLO")) {
			if (cpriv->client_hello) {
				pomlog(POMLOG_DEBUG "We already have a client hello !");
				free(cpriv->client_hello);
			}

			cpriv->client_hello = strdup(arg);
			if (!cpriv->client_hello) {
				pom_oom(strlen(arg) + 1);
				return POM_ERR;
			}
			cpriv->last_cmd = analyzer_smtp_last_cmd_other;

		} else if (!strcasecmp(cmd, "AUTH")) {
			if (!strncasecmp(arg, "PLAIN", strlen("PLAIN"))) {
				arg += strlen("PLAIN");
				while (*arg == ' ')
					arg++;


				if (cpriv->evt_auth) {
					event_process_end(cpriv->evt_auth);
					cpriv->evt_auth = NULL;
				}

				if (strlen(arg)) {
					if (analyzer_smtp_parse_auth_plain(apriv, cpriv, arg) == POM_OK) {
						event_process_begin(cpriv->evt_auth, stack, stack_index, event_get_timestamp(evt));
						cpriv->last_cmd = analyzer_smtp_last_cmd_auth_plain_creds;
					}
				} else {
					cpriv->last_cmd = analyzer_smtp_last_cmd_auth_plain;
					
				}

			} else if (!strncasecmp(arg, "LOGIN", strlen("LOGIN"))) {
				arg += strlen("LOGIN");
				while (*arg == ' ')
					arg++;

				if (cpriv->evt_auth) {
					event_process_end(cpriv->evt_auth);
					cpriv->evt_auth = NULL;
				}

				cpriv->evt_auth = event_alloc(apriv->evt_auth);
				if (!cpriv->evt_auth)
					return POM_ERR;

				struct data *auth_data = event_get_data(cpriv->evt_auth);

				analyzer_smtp_event_fill_common_data(cpriv, auth_data);

				// Set the authentication type
				PTYPE_STRING_SETVAL(auth_data[analyzer_smtp_auth_type].value, "LOGIN");
				data_set(auth_data[analyzer_smtp_auth_type]);

				if (strlen(arg)) {
					char *username = NULL;
					size_t out_len = 0;
					struct ptype *username_pt = NULL;
					if (decoder_decode_simple("base64", arg, strlen(arg), &username, &out_len) == POM_OK) {
						username_pt = ptype_alloc("string");
						if (username_pt) {
							PTYPE_STRING_SETVAL_P(username_pt, username);
							if (data_item_add_ptype(auth_data, analyzer_smtp_auth_params, strdup("username"), username_pt) != POM_OK) {
								ptype_cleanup(username_pt);
								event_cleanup(cpriv->evt_auth);
								cpriv->evt_auth = NULL;
								username_pt = NULL;
							}
						} else {
							free(username);
						}
					}

					if (!username_pt) {
						cpriv->last_cmd = analyzer_smtp_last_cmd_other;
						event_process_begin(cpriv->evt_auth, stack, stack_index, event_get_timestamp(evt));
					}
				} else {
					cpriv->last_cmd = analyzer_smtp_last_cmd_auth_login;
				}
			}

		} else if (cpriv->last_cmd == analyzer_smtp_last_cmd_auth_plain) {
			// We are expecting the credentials right now
			if (analyzer_smtp_parse_auth_plain(apriv, cpriv, cmd) == POM_OK) {
				event_process_begin(cpriv->evt_auth, stack, stack_index, event_get_timestamp(evt));
				cpriv->last_cmd = analyzer_smtp_last_cmd_auth_plain_creds;
			} else {
				cpriv->last_cmd = analyzer_smtp_last_cmd_other;
			}
		} else if (cpriv->last_cmd == analyzer_smtp_last_cmd_auth_login) {
			char *username = NULL;
			size_t out_len = 0;
			struct ptype *username_pt = NULL;
			if (decoder_decode_simple("base64", cmd, strlen(cmd), &username, &out_len) == POM_OK) {
				username_pt = ptype_alloc("string");
				if (username_pt) {
					PTYPE_STRING_SETVAL_P(username_pt, username);
					struct data *auth_data = event_get_data(cpriv->evt_auth);
					if (data_item_add_ptype(auth_data, analyzer_smtp_auth_params, strdup("username"), username_pt) != POM_OK) {
						ptype_cleanup(username_pt);
						event_process_end(cpriv->evt_auth);
						cpriv->evt_auth = NULL;
						username_pt = NULL;
					}
				} else {
					free(username);
				}
			}

			if (!username_pt) {
				cpriv->last_cmd = analyzer_smtp_last_cmd_other;
			} else {
				event_process_begin(cpriv->evt_auth, stack, stack_index, event_get_timestamp(evt));
				cpriv->last_cmd = analyzer_smtp_last_cmd_auth_login_user;
			}

		} else if (cpriv->last_cmd == analyzer_smtp_last_cmd_auth_login_user) {
			char *password = NULL;
			size_t out_len = 0;
			struct ptype *password_pt = NULL;
			if (decoder_decode_simple("base64", cmd, strlen(cmd), &password, &out_len) == POM_OK) {
				password_pt = ptype_alloc("string");
				if (password_pt) {
					PTYPE_STRING_SETVAL_P(password_pt, password);
					struct data *auth_data = event_get_data(cpriv->evt_auth);
					if (data_item_add_ptype(auth_data, analyzer_smtp_auth_params, strdup("password"), password_pt) != POM_OK) {
						ptype_cleanup(password_pt);
						event_process_end(cpriv->evt_auth);
						cpriv->evt_auth = NULL;
						password_pt = NULL;
					}
				} else {
					free(password);
				}
			}

			if (!password_pt) {
				cpriv->last_cmd = analyzer_smtp_last_cmd_other;
			} else {
				cpriv->last_cmd = analyzer_smtp_last_cmd_auth_login_pass;
			}
		} else {
			cpriv->last_cmd = analyzer_smtp_last_cmd_other;
		}

	} else if (evt_reg == apriv->evt_reply) {

		if (!cpriv->common_data_fetched)
			analyzer_smtp_event_fetch_common_data(cpriv, stack, stack_index, s->direction);

		// Process replies
		uint16_t code = *PTYPE_UINT16_GETVAL(evt_data[proto_smtp_reply_code].value);

		switch (cpriv->last_cmd) {

			default:
			case analyzer_smtp_last_cmd_other:
				if (code == 220 && evt_data[proto_smtp_reply_text].items && evt_data[proto_smtp_reply_text].items->value) {
					// STARTTLS returns 220 as well so ignore extra code 220
					if (!cpriv->server_hello) {
						char *helo = PTYPE_STRING_GETVAL(evt_data[proto_smtp_reply_text].items->value);
						cpriv->server_hello = strdup(helo);
						if (!cpriv->server_hello) {
							pom_oom(strlen(helo) + 1);
							return POM_ERR;
						}
					}
				}
				break;

			case analyzer_smtp_last_cmd_mail_from:
				if (code != 250) {
					// FROM is invalid
					data_unset(msg_data[analyzer_smtp_msg_from]);
				}
				break;
			case analyzer_smtp_last_cmd_rcpt_to:
				// For now just don't do anything
				// It's best to keep a destination in there even if it's invalid or denied
				break;
			
			case analyzer_smtp_last_cmd_data:
				if (code == 354) {
					// The message is starting, keep last_cmd intact
					return POM_OK;
				}

				// Message is over (if ever transmited)
				if (event_is_started(cpriv->evt_msg)) {
					event_process_end(cpriv->evt_msg);
					cpriv->evt_msg = NULL;
				}
				break;

			case analyzer_smtp_last_cmd_auth_plain:
			case analyzer_smtp_last_cmd_auth_login:
			case analyzer_smtp_last_cmd_auth_login_user:
				// Check if authentication phase can continue
				if (code == 334) {
					// Don't reset cpriv->last_cmd
					return POM_OK;
				} else {
					struct data *evt_data = event_get_data(cpriv->evt_auth);
					PTYPE_BOOL_SETVAL(evt_data[analyzer_smtp_auth_success].value, 0);
					data_set(evt_data[analyzer_smtp_auth_success]);
					event_process_end(cpriv->evt_auth);
					cpriv->evt_auth = NULL;
				}
				break;

			case analyzer_smtp_last_cmd_auth_plain_creds:
			case analyzer_smtp_last_cmd_auth_login_pass: {
				// We just processed the credentials
				struct data *auth_data = event_get_data(cpriv->evt_auth);
				char success = 0;
				if (code == 235)
					success = 1;
				PTYPE_BOOL_SETVAL(auth_data[analyzer_smtp_auth_success].value, success);
				data_set(auth_data[analyzer_smtp_auth_success]);
				event_process_end(cpriv->evt_auth);
				cpriv->evt_auth = NULL;
				break;
			}

		}

		cpriv->last_cmd = analyzer_smtp_last_cmd_other;

	}


	return POM_OK;
}

static int analyzer_smtp_event_process_end(struct event *evt, void *obj) {

	struct analyzer *analyzer = obj;
	struct event_reg *evt_reg = event_get_reg(evt);
	struct analyzer_smtp_priv *apriv = analyzer->priv;

	if (evt_reg != apriv->evt_cmd)
		return POM_OK;

	// Check if the DATA event ended
	struct data *evt_data = event_get_data(evt);
	char *cmd = PTYPE_STRING_GETVAL(evt_data[proto_smtp_cmd_name].value);
	if (!cmd)
		return POM_OK;
	
	if (strcasecmp(cmd, "DATA"))
		return POM_OK;
	
	struct analyzer_smtp_ce_priv *cpriv = conntrack_get_priv(event_get_conntrack(evt), analyzer);

	if (event_is_started(cpriv->evt_msg)) {
		event_process_end(cpriv->evt_msg);
		cpriv->evt_msg = NULL;
	}

	return POM_OK;
}

static int analyzer_smtp_ce_priv_cleanup(void *obj, void *priv) {

	struct analyzer_smtp_ce_priv *cpriv = priv;

	if (cpriv->evt_msg) {
		if (event_is_started(cpriv->evt_msg))
			event_process_end(cpriv->evt_msg);
		else
			event_cleanup(cpriv->evt_msg);
	}

	if (cpriv->evt_auth)
		event_process_end(cpriv->evt_auth);

	if (cpriv->client_hello)
		free(cpriv->client_hello);
	if (cpriv->server_hello)
		free(cpriv->server_hello);
	if (cpriv->server_host)
		free(cpriv->server_host);
	if (cpriv->client_addr)
		ptype_cleanup(cpriv->client_addr);
	if (cpriv->server_addr)
		ptype_cleanup(cpriv->server_addr);

	free(cpriv);

	return POM_OK;
}

static int analyzer_smtp_evt_msg_cleanup(struct event *evt) {

	struct analyzer_pload_buffer *pload = event_get_priv(evt);
	if (!pload)
		return POM_OK;

	analyzer_pload_buffer_cleanup(pload);
	return POM_OK;
}
