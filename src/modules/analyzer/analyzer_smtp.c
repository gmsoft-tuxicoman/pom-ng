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
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/proto_smtp.h>

struct mod_reg_info *analyzer_smtp_reg_info() {
	
	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_smtp_mod_register;
	reg_info.unregister_func = analyzer_smtp_mod_unregister;
	reg_info.dependencies = "proto_smtp, ptype_string, ptype_uint16";

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
	analyzer_smtp_evt_msg.description = "Message received over SMTP";
	analyzer_smtp_evt_msg.data_reg = &evt_msg_data;
	analyzer_smtp_evt_msg.listeners_notify = analyzer_smtp_event_listeners_notify;
	analyzer_smtp_evt_msg.cleanup = analyzer_smtp_evt_msg_cleanup;

	priv->evt_msg = event_register(&analyzer_smtp_evt_msg);
	if (!priv->evt_msg)
		goto err;

	return POM_OK;

err:
	analyzer_smtp_cleanup(analyzer);

	return POM_ERR;
}

static int analyzer_smtp_cleanup(struct analyzer *analyzer) {

	struct analyzer_smtp_priv *priv = analyzer->priv;

	if (priv->pkt_listener) {
		event_listener_unregister(priv->evt_cmd, analyzer);
		event_listener_unregister(priv->evt_reply, analyzer);
		proto_packet_listener_unregister(priv->pkt_listener);
	}

	if (priv->evt_msg)
		event_unregister(priv->evt_msg);

	free(priv);

	return POM_OK;
}

static int analyzer_smtp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_smtp_priv *priv = analyzer->priv;

	if (has_listeners) {
		
		if (priv->pkt_listener)
			return POM_OK;

		if (event_listener_register(priv->evt_cmd, analyzer, analyzer_smtp_event_process_begin, analyzer_smtp_event_process_end) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_reply, analyzer, analyzer_smtp_event_process_begin, analyzer_smtp_event_process_end) != POM_OK) {
			event_listener_unregister(priv->evt_cmd, analyzer);
			return POM_ERR;
		}

		priv->pkt_listener = proto_packet_listener_register(proto_get("smtp"), PROTO_PACKET_LISTENER_PLOAD_ONLY, obj, analyzer_smtp_pkt_process);
		if (!priv->pkt_listener) {
			event_listener_unregister(priv->evt_cmd, analyzer);
			event_listener_unregister(priv->evt_reply, analyzer);
			return POM_ERR;
		}

	} else {
		
		if (proto_packet_listener_unregister(priv->pkt_listener) != POM_OK)
			return POM_ERR;

		event_listener_unregister(priv->evt_cmd, analyzer);
		event_listener_unregister(priv->evt_reply, analyzer);

		priv->pkt_listener = NULL;
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


		// Process commands


		// A message was being transmitted and we recevied a new command
		if (event_is_started(cpriv->evt_msg)) {
			event_process_end(cpriv->evt_msg);
			cpriv->evt_msg = NULL;
		}

		cpriv->last_cmd = analyzer_smtp_last_cmd_other;
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
				event_process_begin(cpriv->evt_msg, stack, stack_index);
			} else {
				pomlog(POMLOG_DEBUG "Message event already started !");
			}

		} else if (!strcasecmp(cmd, "RSET")) {
			// Cleanup the event
			event_cleanup(cpriv->evt_msg);
			cpriv->evt_msg = NULL;
		}

	} else if (evt_reg == apriv->evt_reply) {
		// Process replies


		uint16_t code = *PTYPE_UINT16_GETVAL(evt_data[proto_smtp_reply_code].value);

		switch (cpriv->last_cmd) {

			default:
			case analyzer_smtp_last_cmd_other:
				// We don't care about replies for other commands than the one we process
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

	if (cpriv->evt_msg)
		event_cleanup(cpriv->evt_msg);

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
