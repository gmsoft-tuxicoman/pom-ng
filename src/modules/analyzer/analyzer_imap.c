/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2015-2017 Guy Martin <gmsoft@tuxicoman.be>
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


static struct data_item_reg analyzer_imap_msg_data_items[ANALYZER_IMAP_MSG_DATA_COUNT] = { { 0 } };
static struct data_reg analyzer_imap_msg_data = {
	.items = analyzer_imap_msg_data_items,
	.data_count = ANALYZER_IMAP_MSG_DATA_COUNT
};

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


	analyzer_imap_msg_data_items[analyzer_imap_msg_data_headers].name = "headers";
	analyzer_imap_msg_data_items[analyzer_imap_msg_data_headers].value_type = ptype_get_type("string");
	analyzer_imap_msg_data_items[analyzer_imap_msg_data_headers].flags = DATA_REG_FLAG_LIST;

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
	evt_msg_data_items[analyzer_imap_msg_part].name = "part";
	evt_msg_data_items[analyzer_imap_msg_part].value_type = ptype_get_type("string");
	evt_msg_data_items[analyzer_imap_msg_headers].name = "headers";
	evt_msg_data_items[analyzer_imap_msg_headers].flags = DATA_REG_FLAG_LIST;

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
	
	static struct data_item_reg evt_id_data_items[ANALYZER_IMAP_EVT_ID_DATA_COUNT] = { { 0 } };
	evt_id_data_items[analyzer_imap_common_client_addr].name = "client_addr";
	evt_id_data_items[analyzer_imap_common_client_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_id_data_items[analyzer_imap_common_server_addr].name = "server_addr";
	evt_id_data_items[analyzer_imap_common_server_addr].flags = DATA_REG_FLAG_NO_ALLOC;
	evt_id_data_items[analyzer_imap_common_server_port].name = "server_port";
	evt_id_data_items[analyzer_imap_common_server_port].value_type = ptype_get_type("uint16");
	evt_id_data_items[analyzer_imap_common_server_host].name = "server_host";
	evt_id_data_items[analyzer_imap_common_server_host].value_type = ptype_get_type("string");

	evt_id_data_items[analyzer_imap_id_client_params].name = "client_params";
	evt_id_data_items[analyzer_imap_id_client_params].flags = DATA_REG_FLAG_LIST;
	evt_id_data_items[analyzer_imap_id_server_params].name = "server_params";
	evt_id_data_items[analyzer_imap_id_server_params].flags = DATA_REG_FLAG_LIST;

	static struct data_reg evt_id_data = {
		.items = evt_id_data_items,
		.data_count = ANALYZER_IMAP_EVT_ID_DATA_COUNT
	};

	static struct event_reg_info analyzer_imap_evt_id = { 0 };
	analyzer_imap_evt_id.source_name = "analyzer_imap";
	analyzer_imap_evt_id.source_obj = analyzer;
	analyzer_imap_evt_id.name = "imap_id";
	analyzer_imap_evt_id.description = "IMAP ID commands output for client and server";
	analyzer_imap_evt_id.data_reg = &evt_id_data;
	analyzer_imap_evt_id.listeners_notify = analyzer_imap_event_listeners_notify;

	priv->evt_id = event_register(&analyzer_imap_evt_id);
	if (!priv->evt_id)
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

	if (priv->evt_id)
		event_unregister(priv->evt_id);

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

	if (!priv->listening && (event_has_listener(priv->evt_msg) || event_has_listener(priv->evt_auth) || event_has_listener(priv->evt_id))) {
		

		if (event_listener_register(priv->evt_cmd, analyzer, analyzer_imap_event_process_begin, analyzer_imap_event_process_end, NULL) != POM_OK) {
			return POM_ERR;
		} else if (event_listener_register(priv->evt_rsp, analyzer, analyzer_imap_event_process_begin, analyzer_imap_event_process_end, NULL) != POM_OK) {
			event_listener_unregister(priv->evt_cmd, analyzer);
			return POM_ERR;
		}

		priv->listening = 1;

	} else if (priv->listening && !event_has_listener(priv->evt_msg) && !event_has_listener(priv->evt_auth) && !event_has_listener(priv->evt_id)) {

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

	if (!cpriv->pload)
		return POM_OK;


	struct analyzer_imap_ce_priv_pload *cpload = cpriv->pload;

	struct proto_process_stack *pload_stack = &stack[stack_index];
	char *pload = pload_stack->pload;
	size_t plen = pload_stack->plen;
	if (!plen)
		return POM_OK;

	size_t remaining = cpload->len - cpload->pos;
	if (plen > remaining)
		plen = remaining;
	cpload->pos += plen;


	int ret = POM_OK;
	struct pload *pload_buff = NULL;

	if (cpload->header_only) {

		while (plen) {

			char *crlf = memchr(pload, '\n', plen);

			if (!crlf) {
				if (cpload->hdr_buff)
					free(cpload->hdr_buff);
				cpload->hdr_buff = strndup(pload, plen);
				break;
			}

			size_t line_len = crlf - pload;
			char *line = pload;
			pload = crlf + 1;
			plen -= line_len + 1;

			if (!line_len)
				continue;

			if (line[line_len -1] == '\r')
				line_len--;

			if (!line_len)
				continue;


			if (cpload->hdr_buff) {
				size_t buff_len = line_len + strlen(cpload->hdr_buff);
				char *new_line = malloc(buff_len + 1);
				if (!new_line) {
					pom_oom(buff_len + 1);
					ret = POM_ERR;
					break;
				}
				strcpy(new_line, cpload->hdr_buff);
				strncat(new_line, line, line_len);
				new_line[buff_len] = 0;
				line_len = buff_len;
				line = new_line;

			}

			ret = mime_header_parse(&cpload->msg->data[analyzer_imap_msg_data_headers], line, line_len);

			if (cpload->hdr_buff) {
				free(cpload->hdr_buff);
				cpload->hdr_buff = NULL;
				free(line);
			}

			if (ret != POM_OK)
				break;

		}

		if (plen) {
			cpload->hdr_buff = strndup(pload, plen);
			if (!cpload->hdr_buff) {
				pom_oom(plen);
				ret = POM_ERR;
			}
		}


	} else {

		pload_buff = event_get_priv(cpload->evt_msg);

		if (pload_buff)
			ret = pload_append(pload_buff, pload, plen);
	}


	if (cpload->pos >= cpload->len || ret != POM_OK) {

		if (pload_buff)
			pload_end(pload_buff);
		if (cpload->hdr_buff) {
			free(cpload->hdr_buff);
			cpload->hdr_buff = NULL;
		}

		event_set_priv(cpload->evt_msg, NULL);
		cpload->pos = 0;
		cpload->len = 0;
	}

	return ret;
}

static int analyzer_imap_event_fill_common_data(struct analyzer_imap_ce_priv *cpriv, struct data *data) {

	struct analyzer_imap_ce_priv_common_data *cdata = cpriv->common_data;

	if (!cdata)
		return POM_ERR;

	if (cdata->client_addr) {
		data[analyzer_imap_common_client_addr].value = ptype_alloc_from(cdata->client_addr);
		data[analyzer_imap_common_client_addr].flags &= ~DATA_FLAG_NO_CLEAN;
		if (data[analyzer_imap_common_client_addr].value)
			data_set(data[analyzer_imap_common_client_addr]);
	}

	if (cdata->server_addr) {
		data[analyzer_imap_common_server_addr].value = ptype_alloc_from(cdata->server_addr);
		data[analyzer_imap_common_server_addr].flags &= ~DATA_FLAG_NO_CLEAN;
		if (data[analyzer_imap_common_server_addr].value)
			data_set(data[analyzer_imap_common_server_addr]);
	}

	if (cdata->server_port) {
		PTYPE_UINT16_SETVAL(data[analyzer_imap_common_server_port].value, cdata->server_port);
		data_set(data[analyzer_imap_common_server_port]);
	}

	if (cdata->server_host) {
		PTYPE_STRING_SETVAL(data[analyzer_imap_common_server_host].value, cdata->server_host);
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

static size_t analyzer_imap_strlen(char *imap_str, size_t len) {


	if (*imap_str == '(' || *imap_str == '[') {
		char end_sep = ')';
		if (*imap_str == '[')
			end_sep = ']';

		char *pos = imap_str + 1;
		char *end = imap_str + len;

		while (pos < end && *pos) {
			for (;pos < end && *pos == ' '; pos++);

			if (pos >= end)
				break;

			size_t sublen = analyzer_imap_strlen(pos, end - pos);
			pos += sublen;
			if (pos >= end)
				break;

			if (*pos == end_sep) {
				pos++;
				break;
			}

		}
		return pos - imap_str;


	} else if (*imap_str != '"') {
		char *end = imap_str;
		while (*end >= '!' && *end <= 'z' && *end != '(' && *end != ')' && *end != '[' && *end != ']' && *end != '<' && *end != '>' )
			end++;
		return end - imap_str;

	}

	// Check for double quoted string

	char *dquote = NULL;
	char *tmp = imap_str + 1;
	while ((dquote = memchr(tmp, '"', len))) {
		unsigned int bslash_count = 0;
		char *bslash = tmp - 1;
		while (bslash >= imap_str && *bslash == '\\') {
			bslash_count++;
			bslash--;
		}

		if ((bslash_count % 2) == 0) {
			// The double quote is not escaped
			break;
		}

		tmp = dquote + 1;
		len -= dquote - tmp;

	}

	return dquote - imap_str + 1;

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

static int analyzer_imap_parse_id(struct event *evt_id, char *arg, int is_client) {

	struct data *id_data = event_get_data(evt_id);

	size_t len = strlen(arg);
	if (len == 0 || *arg != '(' || arg[len - 1] != ')')
		return POM_OK;

	arg++;
	len -= 2;

	while (len > 0) {
		size_t key_len = analyzer_imap_strlen(arg, len);
		if (!key_len)
			break;
		char *key = arg;
		arg += key_len;
		len -= key_len;
		while (*arg == ' ') {
			arg++;
			len--;
		}

		size_t value_len = analyzer_imap_strlen(arg, len);
		if (!value_len)
			break;
		char *value = arg;
		arg += value_len;
		len -= value_len;
		while (*arg == ' ') {
			arg++;
			len--;
		}

		key = pom_undquote(key, key_len);
		value = pom_undquote(value, value_len);

		struct ptype *value_pt = ptype_alloc("string");
		PTYPE_STRING_SETVAL_P(value_pt, value);

		int client_server = (is_client ? analyzer_imap_id_client_params : analyzer_imap_id_server_params);
		if (data_item_add_ptype(id_data, client_server, key, value_pt) != POM_OK) {
			event_cleanup(evt_id);
			return POM_ERR;
		}
	}
	return POM_OK;
}

static int analyzer_imap_event_fetch_common_data(struct analyzer_imap_ce_priv *cpriv, struct proto_process_stack *stack, unsigned int stack_index, int server_direction) {


	struct analyzer_imap_ce_priv_common_data *cdata = malloc(sizeof(struct analyzer_imap_ce_priv_common_data));
	if (!cdata) {
		pom_oom(sizeof(struct analyzer_imap_ce_priv_common_data));
		return POM_ERR;
	}
	memset(cdata, 0, sizeof(struct analyzer_imap_ce_priv_common_data));

	struct  proto_process_stack *l4_stack = &stack[stack_index - 1];
	struct  proto_process_stack *l3_stack = &stack[stack_index - 2];

	int i;

	char *port_str = "dport";
	if (server_direction == POM_DIR_REV)
		port_str = "sport";
	
	for (i = 0; !cdata->server_port; i++) {
		struct proto_reg_info *l4_info = proto_get_info(l4_stack->proto);
		char *name = l4_info->pkt_fields[i].name;
		if (!name)
			break;
		if (!strcmp(name, port_str))
			cdata->server_port = *PTYPE_UINT16_GETVAL(l4_stack->pkt_info->fields_value[i]);
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
			cdata->client_addr = ptype_alloc_from(src);
		if (dst)
			cdata->server_addr = ptype_alloc_from(dst);
	} else {
		if (src)
			cdata->server_addr = ptype_alloc_from(src);
		if (dst)
			cdata->client_addr = ptype_alloc_from(dst);
	}

	if (cdata->server_addr) {
		char *host = dns_reverse_lookup_ptype(cdata->server_addr);
		if (host)
			cdata->server_host = host;
	}

	cpriv->common_data = cdata;

	return POM_OK;
}

static struct analyzer_imap_fetch_body_part* analyzer_imap_parse_fetch_field_body(char *line, size_t len) {

	struct analyzer_imap_fetch_body_part *res = malloc(sizeof(struct analyzer_imap_fetch_body_part));
	if (!res) {
		pom_oom(sizeof(struct analyzer_imap_fetch_body_part));
		return NULL;
	}
	memset(res, 0, sizeof(struct analyzer_imap_fetch_body_part));

	size_t field_len = 0;
	if (len >= strlen("HEADER.FIELDS.NOT") && !strncasecmp(line, "HEADER.FIELDS.NOT", strlen("HEADER.FIELDS.NOT"))) {
		res->part = analyzer_imap_fetch_body_field_header_fields_not;
		field_len = strlen("HEADER.FIELDS.NOT");
	} else if (len >= strlen("HEADER.FIELDS") && !strncasecmp(line, "HEADER.FIELDS", strlen("HEADER.FIELDS"))) {
		res->part = analyzer_imap_fetch_body_field_header_fields;
		field_len = strlen("HEADER.FIELDS");
	} else if (len >= strlen("HEADER") && !strncasecmp(line, "HEADER", strlen("HEADER"))) {
		res->part = analyzer_imap_fetch_body_field_header;
		field_len = strlen("HEADER");
	} else if (len >= strlen("MIME") && !strncasecmp(line, "MIME", strlen("MIME"))) {
		res->part = analyzer_imap_fetch_body_field_mime;
		field_len = strlen("MIME");
	} else if (len >= strlen("TEXT") && !strncasecmp(line, "TEXT", strlen("TEXT"))) {
		res->part = analyzer_imap_fetch_body_field_text;
		field_len = strlen("TEXT");
	} else {
		// It's most likely a number
		char *dot = memchr(line, '.', len);
		if (dot) {
			field_len = dot - line + 1;
		} else {
			field_len = len;
		}
		if (sscanf(line, "%u", &res->part) != 1) {
			// Parse error, set the part as unknown
			return res;
		}
		// Negate the value to mean it's an actual part number
		res->part = -res->part;
	}

	line += field_len;
	len -= field_len;

	if (!len)
		return res;

	res->next = analyzer_imap_parse_fetch_field_body(line, len);
	if (!res->next) {
		free(res);
		return NULL;
	}

	return res;
}

void analyzer_imap_fetch_bodystructure_cleanup(struct analyzer_imap_fetch_bodystructure *bodystruct) {

	if (bodystruct->mime_type)
		mime_type_cleanup(bodystruct->mime_type);

	if (bodystruct->encoding)
		free(bodystruct->encoding);

	if (bodystruct->subparts) {
		int i;
		for (i = 0; i < bodystruct->subparts_count; i++)
			analyzer_imap_fetch_bodystructure_cleanup(bodystruct->subparts[i]);

		free(bodystruct->subparts);
	}

	free(bodystruct);
}

struct analyzer_imap_fetch_bodystructure* analyzer_imap_parse_fetch_field_bodystructure(char *line, size_t len) {


	struct analyzer_imap_fetch_bodystructure *res = malloc(sizeof(struct analyzer_imap_fetch_bodystructure));
	if (!res) {
		pom_oom(sizeof(struct analyzer_imap_fetch_bodystructure));
		return NULL;
	}
	memset(res, 0, sizeof(struct analyzer_imap_fetch_bodystructure));

	if (*line == '(') {
		// This is a nested bodystructure

		while (len > 2 && *line == '(') {
			struct analyzer_imap_fetch_bodystructure **tmp = realloc(res->subparts, sizeof(struct analyzer_imap_fetch_bodystructure*) * (res->subparts_count + 1));
			if (!tmp) {
				pom_oom(sizeof(struct analyzer_imap_fetch_bodystructure*) * (res->subparts_count + 1));
				analyzer_imap_fetch_bodystructure_cleanup(res);
				return NULL;
			}

			res->subparts = tmp;

			tmp[res->subparts_count] = NULL;

			char *subpart = line;
			size_t sublen = analyzer_imap_strlen(line, len);

			if (sublen < 2) {// Shouldn't happen
				analyzer_imap_fetch_bodystructure_cleanup(res);
				pomlog(POMLOG_DEBUG "Cannot parse BODYSTRUCTURE : substring too short");
				return NULL;
			}

			line += sublen;
			len -= sublen;


			// Remove the parenthesis
			subpart++;
			sublen--;
			if (subpart[sublen - 1] == ')')
				sublen--;

			tmp[res->subparts_count] = analyzer_imap_parse_fetch_field_bodystructure(subpart, sublen);
			if (!tmp[res->subparts_count]) {
				analyzer_imap_fetch_bodystructure_cleanup(res);
				return NULL;
			}

			res->subparts_count++;

			while (len > 0 && *line == ' ') {
				line++;
				len--;
			}
		}

		// Now parse what kind of multipart we have

		if (len < 0) // Check if it's correctly provided or not
			return res;

		size_t multipart_len = analyzer_imap_strlen(line, len);
		char *multipart_type = pom_undquote(line, multipart_len);
		if (!multipart_type) {
			analyzer_imap_fetch_bodystructure_cleanup(res);
			return NULL;
		}

		char *multipart = malloc(strlen("multipart/") + strlen(multipart_type) + 1);
		if (!multipart) {
			pom_oom(strlen("multipart/") + strlen(multipart_type) + 1);
			analyzer_imap_fetch_bodystructure_cleanup(res);
			return NULL;
		}

		strcpy(multipart, "multipart/");
		strcat(multipart, multipart_type);
		free(multipart_type);

		res->mime_type = mime_type_alloc(multipart);
		if (!res->mime_type) {
			analyzer_imap_fetch_bodystructure_cleanup(res);
			return NULL;
		}

		printf("Multipart of type %s\n", multipart);

		return res;
	}


	// Process a non nested bodystructure

	while (len > 0 && *line == ' ') {
		line++;
		len--;
	}

	if (len == 0) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	// First field is the (top mime) type

	size_t tmp_len = analyzer_imap_strlen(line, len);
	char *mime_toptype = pom_undquote(line, tmp_len);
	if (!mime_toptype) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	line += tmp_len;
	len -= tmp_len;

	while (len > 0 && *line == ' ') {
		line++;
		len--;
	}
	if (len == 0) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	// Second field is the sub (mime) type

	tmp_len = analyzer_imap_strlen(line, len);
	char *mime_subtype = pom_undquote(line, tmp_len);
	if (!mime_subtype) {
		free(mime_toptype);
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	size_t mime_type_len = strlen(mime_toptype) + 1 + strlen(mime_subtype) + 1;
	char *mime_type = malloc(mime_type_len);
	if (!mime_type) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		free(mime_toptype);
		free(mime_subtype);
		pom_oom(mime_type_len);
		return NULL;
	}
	strcpy(mime_type, mime_toptype);
	free(mime_toptype);
	strcat(mime_type, "/");
	strcat(mime_type, mime_subtype);
	free(mime_subtype);

	res->mime_type = mime_type_alloc(mime_type);

	if (!res->mime_type) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	printf("Got bodystructure part of type %s\n", res->mime_type->name);

	line += tmp_len;
	len -= tmp_len;

	while (len > 0 && *line == ' ') {
		line++;
		len--;
	}
	if (len == 0) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	// Third field are mime parameters

	tmp_len = analyzer_imap_strlen(line, len);

	// TODO parse mime parameters

	line += tmp_len;
	len -= tmp_len;

	while (len > 0 && *line == ' ') {
		line++;
		len--;
	}
	if (len == 0) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	// Fourth field is the mime ID, we don't care about it

	tmp_len = analyzer_imap_strlen(line, len);
	line += tmp_len;
	len -= tmp_len;

	while (len > 0 && *line == ' ') {
		line++;
		len--;
	}
	if (len == 0) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	// Fifth field is the mime description, we don't care either

	tmp_len = analyzer_imap_strlen(line, len);
	line += tmp_len;
	len -= tmp_len;

	while (len > 0 && *line == ' ') {
		line++;
		len--;
	}
	if (len == 0) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	// Sixth field is the encoding
	tmp_len = analyzer_imap_strlen(line, len);
	if (strncasecmp(line, "NIL", strlen("NIL"))) {

		res->encoding = pom_undquote(line, tmp_len);
		if (!res->encoding) {
			pom_oom(tmp_len);
			analyzer_imap_fetch_bodystructure_cleanup(res);
			return NULL;
		}

		int i, elen = strlen(res->encoding);
		for (i = 0; i < elen; i++) {
			if (res->encoding[i] >= 'A' && res->encoding[i] <= 'Z')
				res->encoding[i] += 'a' - 'A';
		}
	}

	line += tmp_len;
	len -= tmp_len;

	while (len > 0 && *line == ' ') {
		line++;
		len--;
	}
	if (len == 0) {
		analyzer_imap_fetch_bodystructure_cleanup(res);
		return NULL;
	}

	// Seventh field is the part size
	tmp_len = analyzer_imap_strlen(line, len);

	if (strncasecmp(line, "NIL", strlen("NIL"))) {

		if (tmp_len > 21) {
			pomlog(POMLOG_DEBUG "Field size too big");
			analyzer_imap_fetch_bodystructure_cleanup(res);
			return NULL;
		}
		char uint[22] = { 0 };
		strncpy(uint, line, tmp_len);

		if (sscanf(uint, "%"SCNu64, &res->size) != 1) {
			pomlog(POMLOG_DEBUG "Unable to parse field size");
			analyzer_imap_fetch_bodystructure_cleanup(res);
			return NULL;
		}
	}

	return res;

}


static void analyzer_imap_msg_cleanup(struct analyzer_imap_msg *msg) {

	if (msg->bodystructure) {
		analyzer_imap_fetch_bodystructure_cleanup(msg->bodystructure);
	}

	if (msg->data) {
		data_cleanup_table(msg->data, &analyzer_imap_msg_data);
	}

	free(msg);
}

struct analyzer_imap_msg *analyzer_imap_msg_merge(struct analyzer_imap_ce_priv *cpriv, struct analyzer_imap_msg *msg) {

	// This function returns a merged message. The original message might be destroyed and shouldn't be used after calling this function

	if (!msg->uid) {
		pomlog(POMLOG_DEBUG "Cannot process message without a UID");
		return NULL;
	}

	// Merge new messaage data with known ones if any
	// If not, add it to the list

	struct analyzer_imap_msg *old_msg = NULL;
	HASH_FIND(hh, cpriv->msgs, &msg->uid, sizeof(msg->uid), old_msg);

	if (!old_msg) {
		// Allocate data for this message
		msg->data = data_alloc_table(&analyzer_imap_msg_data);
		if (!msg->data) {
			analyzer_imap_msg_cleanup(msg);
			return NULL;
		}

		HASH_ADD(hh, cpriv->msgs, uid, sizeof(msg->uid), msg);


		return msg;
	}

	// The message was found, let's merge things !

	if (msg->seq)
		old_msg->seq = msg->seq;

	if (msg->rfc822_size)
		old_msg->rfc822_size = msg->rfc822_size;

	if (msg->bodystructure && !old_msg->bodystructure) {
		old_msg->bodystructure = msg->bodystructure;
		msg->bodystructure = NULL;
	}

	analyzer_imap_msg_cleanup(msg);

	return old_msg;
}

static int analyzer_imap_parse_fetch(struct analyzer_imap_ce_priv *cpriv, char *line, size_t len, struct analyzer_imap_fetch_cmd_data *data) {

	// Ok now parse all the stuff here
	while (len) {
		while (*line == ' ') {
			line++;
			len--;
		}

		if (*line == '{') {
			char *end;
			for (end = line + 1; end < line + len; end++) {
				if (*end < '0' || *end > '9')
					break;
			}
			if (*end != '}') {
				pomlog(POMLOG_DEBUG "Unable to parse payload size, '}' not found");
				break;
			}

			if (end != line + len - 1) {
				end++;
				len -= end - line;
				line = end;

				continue;
			}

			// This this the payload length
			char len_str[21] = { 0 };
			line ++;
			len -= 2;
			if (len > 20)
				len = 20;

			memcpy(len_str, line, len);

			if (sscanf(len_str, "%"SCNu64, &data->data_size) != 1) {
				pomlog(POMLOG_DEBUG "Unable to parse payload size");
			}

			break;
		}


		size_t name_len = analyzer_imap_strlen(line, len);
		if (!name_len)
			break;

		enum analyzer_imap_fetch_field field = 0;


		if (name_len == strlen("UID") && !strncasecmp(line, "UID", strlen("UID"))) {
			field = analyzer_imap_fetch_field_uid;
		} else if (name_len == strlen("INTERNALDATE") && !strncasecmp(line, "INTERNALDATE", strlen("INTERNALDATE"))) {
			field = analyzer_imap_fetch_field_internaldate;
		} else if (name_len == strlen("FLAGS") && !strncasecmp(line, "FLAGS", strlen("FLAGS"))) {
			field = analyzer_imap_fetch_field_flags;
		} else if (name_len == strlen("RFC822") && !strncasecmp(line, "RFC822", strlen("RFC822"))) {
			field = analyzer_imap_fetch_field_rfc822;
		} else if (name_len == strlen("RFC822.HEADER") && !strncasecmp(line, "RFC822.HEADER", strlen("RFC822.HEADER"))) {
			field = analyzer_imap_fetch_field_rfc822_header;
		} else if (name_len == strlen("RFC822.SIZE") && !strncasecmp(line, "RFC822.SIZE", strlen("RFC822.SIZE"))) {
			field = analyzer_imap_fetch_field_rfc822_size;
		} else if (name_len == strlen("RFC822.TEXT") && !strncasecmp(line, "RFC822.TEXT", strlen("RFC822.TEXT"))) {
			field = analyzer_imap_fetch_field_rfc822_text;
		} else if (name_len == strlen("BODYSTRUCTURE") && !strncasecmp(line, "BODYSTRUCTURE", strlen("BODYSTRUCTURE"))) {
			field = analyzer_imap_fetch_field_bodystructure;
		} else if (name_len == strlen("BODY") && !strncasecmp(line, "BODY", strlen("BODY"))) {
			field = analyzer_imap_fetch_field_body;
		} else if (name_len == strlen("BODY.PEEK") && !strncasecmp(line, "BODY.PEEK", strlen("BODY.PEEK"))) {
			field = analyzer_imap_fetch_field_body;
		} else if (name_len == strlen("ENVELOPE") && !strncasecmp(line, "ENVELOPE", strlen("ENVELOPE"))) {
			field = analyzer_imap_fetch_field_envelope;
		} else {
			char *name = strndup(line, name_len);
			pomlog(POMLOG_DEBUG "Unknown fetch field %s", name);
			free(name);
		}

		line += name_len;
		len -= name_len;
		while (*line == ' ') {
			line++;
			len--;
		}

		size_t value_len = analyzer_imap_strlen(line, len);
		if (!value_len)
			break;

		if (field == analyzer_imap_fetch_field_body) {
			// Check for an offset
			if (value_len < len && line[value_len] == '<') {
				while (value_len < len && line[value_len] != '>')
					value_len++;
				value_len++;
			}

		}

		char *value = strndup(line, value_len);

		line += value_len;
		len -= value_len;


		if (!value) {
			pom_oom(value_len);
			return POM_ERR;
		}


		switch (field) {
			case analyzer_imap_fetch_field_uid: {
				if (sscanf(value, "%"SCNu64, &data->msg->uid) != 1) {
					pomlog(POMLOG_DEBUG "Error while parsing FETCH UID");
					free(value);
					continue;
				}
				break;
			}
			case analyzer_imap_fetch_field_rfc822_size: {
				if (sscanf(value, "%"SCNu64, &data->msg->rfc822_size) != 1) {
					pomlog(POMLOG_DEBUG "Error while parsing FETCH RFC822.SIZE");
					free(value);
					continue;
				}
				break;
			}
			case analyzer_imap_fetch_field_body: {
				char *tmp = value;
				size_t tmp_len = value_len;
				size_t offset = 0;

				if (tmp_len > 3 && tmp[tmp_len - 1] == '>') {
					// Parse the offset
					char *offset_str = tmp + tmp_len;
					while (offset_str > value && *(offset_str - 1) != '<')
						offset_str--;

					if (sscanf(offset_str, "%"SCNu64, &offset) != 1) {
						pomlog(POMLOG_DEBUG "Error while parsing BODY[]<offset>");
						free(value);
						continue;
					}
					tmp_len = offset_str - value - 1;
				}


				if (tmp_len > 1 && tmp[tmp_len - 1] == ']')
					tmp_len--;
				if (tmp_len > 1 && tmp[0] == '[') {
					tmp++;
					tmp_len--;
				}

				// Strip space if any, we don't need header definitions
				char *sp = memchr(tmp, ' ', tmp_len);
				if (sp) {
					*sp = 0;
					tmp_len = sp - value - 1;
				}

				while (data->parts) {
					struct analyzer_imap_fetch_body_part *tmp = data->parts;
					data->parts = tmp->next;
					free(tmp);

				}

				data->parts = analyzer_imap_parse_fetch_field_body(tmp, tmp_len);
				if (!data->parts) {
					free(value);
					continue;
				}

				if (data->part_str) {
					free(data->part_str);
					data->part_str = NULL;
				}

				if (tmp_len)
					data->part_str = strndup(tmp, tmp_len);

				break;
			}
			case analyzer_imap_fetch_field_bodystructure: {
				char *tmp = value;
				size_t tmp_len = value_len;

				if (tmp_len > 1 && tmp[tmp_len - 1] == ')')
					tmp_len--;

				if (tmp_len > 1 && tmp[0] == '(') {
					tmp++;
					tmp_len--;
				}

				if (data->msg->bodystructure) {
					pomlog(POMLOG_DEBUG "BODYSTRUCTURE provided more than once");
					analyzer_imap_fetch_bodystructure_cleanup(data->msg->bodystructure);
				}
				data->msg->bodystructure = analyzer_imap_parse_fetch_field_bodystructure(tmp, tmp_len);


				break;
			}


			default:
				break;
		}

		free(value);
	}

	data->msg = analyzer_imap_msg_merge(cpriv, data->msg);

	return POM_OK;

}


static int analyzer_imap_pload_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct analyzer_imap_priv *apriv = analyzer->priv;
	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce)
		return POM_ERR;
	struct analyzer_imap_ce_priv *cpriv = conntrack_get_priv(s->ce, analyzer);

	struct data *evt_data = event_get_data(evt);

	if (!data_is_set(evt_data[proto_imap_pload_cmd]) || !data_is_set(evt_data[proto_imap_pload_size]))
		return POM_OK;

	char *line = PTYPE_STRING_GETVAL(evt_data[proto_imap_pload_cmd].value);

	char *sp = strchr(line, ' ');
	if (!sp)
		return POM_OK;

	while (*sp == ' ')
		sp++;

	if (!event_has_listener(apriv->evt_msg))
		return POM_OK;

	// For now we only parse FETCH commands
	if (strncasecmp(sp, "FETCH (", strlen("FETCH ("))) {
		pomlog(POMLOG_DEBUG "Cannot parse payload command \"%s\"", line);
		return POM_OK;
	}
	line = sp + strlen("FETCH (");
	printf("%s\n", line);


	struct analyzer_imap_fetch_cmd_data data = { 0 };

	struct analyzer_imap_msg *msg = malloc(sizeof(struct analyzer_imap_msg));
	if (!msg) {
		pom_oom(sizeof(struct analyzer_imap_msg));
		return POM_ERR;
	}
	memset(msg, 0, sizeof(struct analyzer_imap_msg));

	data.msg = msg;
	int res = analyzer_imap_parse_fetch(cpriv, line, strlen(line), &data);


	if (res != POM_OK)
		goto end;

	if (!data.data_size || !data.parts || data.parts->part == analyzer_imap_fetch_body_field_unknown) {
		res = POM_OK;
		goto end;
	}

	struct analyzer_imap_ce_priv_pload *cpload = malloc(sizeof(struct analyzer_imap_ce_priv_pload));
	if (!cpload) {
		pom_oom(sizeof(struct analyzer_imap_ce_priv_pload));
		res = POM_ERR;
		goto end;
	}
	memset(cpload, 0, sizeof(struct analyzer_imap_ce_priv_pload));

	cpload->msg = data.msg;
	cpload->len = data.data_size;

	// New message coming in, create the corresponding event
	cpload->evt_msg = event_alloc(apriv->evt_msg);
	if (!cpload->evt_msg) {
		free(cpload);
		res = POM_ERR;
		goto end;
	}

	struct data *msg_data = event_get_data(cpload->evt_msg);
	analyzer_imap_event_fill_common_data(cpriv, msg_data);

	PTYPE_UINT64_SETVAL(msg_data[analyzer_imap_msg_uid].value, data.msg->uid);
	data_set(msg_data[analyzer_imap_msg_uid]);

	if (cpriv->cur_mbx) {
		PTYPE_STRING_SETVAL(msg_data[analyzer_imap_msg_mailbox].value, cpriv->cur_mbx);
		data_set(msg_data[analyzer_imap_msg_mailbox]);
	}

	if (data.parts->part >= 0 && data.parts->part <= analyzer_imap_fetch_body_field_header_fields_not) {
		cpload->header_only = 1;
	} else {

		if (data.part_str) {
			PTYPE_STRING_SETVAL(msg_data[analyzer_imap_msg_part].value, data.part_str);
			data_set(msg_data[analyzer_imap_msg_part]);
		}

		struct pload *pload_buff = pload_alloc(cpload->evt_msg, 0);
		if (!pload_buff) {
			event_cleanup(cpload->evt_msg);
			free(cpload);
			res = POM_ERR;
			goto end;
		}

		event_set_priv(cpload->evt_msg, pload_buff);

		pload_set_expected_size(pload_buff, data.data_size);
	}

	cpriv->pload = cpload;

	res = event_process_begin(cpload->evt_msg, stack, stack_index, event_get_timestamp(evt));
end:

	if (data.part_str) {
		free(data.part_str);
		data.part_str = NULL;
	}

	while (data.parts) {
		struct analyzer_imap_fetch_body_part *tmp = data.parts;
		data.parts = tmp->next;
		free(tmp);

	}

	return res;
}

static int analyzer_imap_pload_event_process_end(struct event *evt, void *obj) {

	struct analyzer *analyzer = obj;
	struct conntrack_entry *ce = event_get_conntrack(evt);
	if (!ce)
		return POM_ERR;

	struct analyzer_imap_ce_priv *cpriv = conntrack_get_priv(ce, analyzer);
	if (!cpriv)
		return POM_ERR;

	if (!cpriv->pload)
		return POM_OK;

	struct analyzer_imap_ce_priv_pload *cpload = cpriv->pload;
	cpriv->pload = NULL;

	if (cpload->evt_msg)
		event_process_end(cpload->evt_msg);

	free(cpload);


	return POM_OK;
}

static void analyzer_imap_invalidate_mbx(struct analyzer_imap_ce_priv *cpriv) {

	if (cpriv->cur_mbx)
		free(cpriv->cur_mbx);
	cpriv->cur_mbx = NULL;

	struct analyzer_imap_msg *cur_msg, *tmp;

	HASH_ITER(hh, cpriv->msgs, cur_msg, tmp) {
		HASH_DEL(cpriv->msgs, cur_msg);
		analyzer_imap_msg_cleanup(cur_msg);
	}

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

	if (!cpriv->common_data)
		analyzer_imap_event_fetch_common_data(cpriv, stack, stack_index, s->direction);

	if (evt_reg == apriv->evt_cmd) {

		char *cmd = PTYPE_STRING_GETVAL(evt_data[proto_imap_cmd_name].value);
		char *arg = NULL;

		if (data_is_set(evt_data[proto_imap_cmd_arg]))
			arg = PTYPE_STRING_GETVAL(evt_data[proto_imap_cmd_arg].value);

		if (!strcasecmp(cmd, "LOGIN")) {

			if (!arg)
				return POM_OK;

			if (!event_has_listener(apriv->evt_auth))
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

			pwd = pom_undquote(pwd, strlen(pwd));
			if (pwd) {
				PTYPE_STRING_SETVAL_P(password, pwd);
			}

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

			if (event_process_begin(evt_auth, stack, stack_index, event_get_timestamp(evt)) != POM_OK)
				return POM_ERR;

			if (analyzer_imap_queue_cmd(cpriv, analyzer_imap_cmd_auth, evt, evt_auth) != POM_OK) {
				event_process_end(evt_auth);
				return POM_ERR;
			}

		} else if (!strcasecmp(cmd, "AUTHENTICATE")) {
			if (!arg) // Invalid command, AUTHENTICATE needs an argument
				return POM_OK;

			if (!event_has_listener(apriv->evt_auth))
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

				if (event_process_begin(evt_auth, stack, stack_index, event_get_timestamp(evt)) != POM_OK) {
					event_cleanup(evt_auth);
					return POM_ERR;
				}

				if (analyzer_imap_queue_cmd(cpriv, analyzer_imap_cmd_auth, evt, evt_auth) != POM_OK) {
					event_process_end(evt_auth);
					return POM_ERR;
				}

			}


		} else if (!strcasecmp(cmd, "SELECT") || !strcasecmp(cmd, "EXAMINE")) {
			if (!arg)
				return POM_OK;

			analyzer_imap_invalidate_mbx(cpriv);

			cpriv->cur_mbx = pom_undquote(arg, strlen(arg));
			if (!cpriv->cur_mbx) {
				pom_oom(strlen(arg) + 1);
				return POM_ERR;
			}
		} else if (!strcasecmp(cmd, "ID")) {
			if (!arg)
				return POM_OK;

			if (!event_has_listener(apriv->evt_id))
				return POM_OK;

			struct event *evt_id = event_alloc(apriv->evt_id);
			if (!evt_id)
				return POM_ERR;

			if (cpriv->evt_id)
				event_process_end(cpriv->evt_id);
			cpriv->evt_id = NULL;

			if (analyzer_imap_parse_id(evt_id, arg, 1) != POM_OK) {
				event_cleanup(evt_id);
				return POM_ERR;
			}

			struct data *id_data = event_get_data(evt_id);
			analyzer_imap_event_fill_common_data(cpriv, id_data);

			if (event_process_begin(evt_id, stack, stack_index, event_get_timestamp(evt)) != POM_OK) {
				event_cleanup(evt_id);
				return POM_ERR;
			}

			if (analyzer_imap_queue_cmd(cpriv, analyzer_imap_cmd_id, evt, evt_id) != POM_OK) {
				event_process_end(evt_id);
				return POM_ERR;
			}

			cpriv->evt_id = evt_id;

		}

	} else if (evt_reg == apriv->evt_rsp) {

		char *tag = PTYPE_STRING_GETVAL(evt_data[proto_imap_response_tag].value);

		// Check if it this is the completion of a command only if it's a tagged result
		struct analyzer_imap_cmd_entry *cmd = NULL;
		if (strcmp(tag, "*") && strcmp(tag, "+")) {
			// Check only for the command if the tag is a number
			for (cmd = cpriv->cmd_queue_head; cmd && strcmp(cmd->tag, tag); cmd = cmd->next);
		}

		char *status_str = NULL;
		if (data_is_set(evt_data[proto_imap_response_status]))
			status_str = PTYPE_STRING_GETVAL(evt_data[proto_imap_response_status].value);

		if (cmd) {
			// We found a matching command in our queue
			enum analyzer_imap_rsp_status status = analyzer_imap_rsp_status_unk;
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
				case analyzer_imap_cmd_id:
					cpriv->evt_id = NULL;
					break;
			}

			if (event_process_end(out_evt) != POM_OK)
				return POM_ERR;

			// No more processing needed for this reply
			return POM_OK;
		}


		if (!status_str)
			return POM_OK;

		if (!strcmp(tag, "*")) {
			/*if (!strcasecmp(status_str, "FLAGS")) {
				// FLAGS response appear only for SELECT or EXAMINE
				// Since we switched mailbox we need to flush what we know about messages
				analyzer_imap_invalidate_mbx(cpriv);
			} else*/ 
			if (!strcasecmp(status_str, "ID")) {

				char *text = PTYPE_STRING_GETVAL(evt_data[proto_imap_response_text].value);
				if (!text)
					return POM_OK;

				struct event *evt_id = cpriv->evt_id;
				if (!cpriv->evt_id) {
					evt_id = event_alloc(apriv->evt_id);
					if (!evt_id)
						return POM_ERR;
					struct data *id_data = event_get_data(evt_id);
					analyzer_imap_event_fill_common_data(cpriv, id_data);
				}

				if (analyzer_imap_parse_id(evt_id, text, 0) != POM_OK) {
					if (!cpriv->evt_id)
						event_cleanup(evt_id);
					return POM_ERR;
				}

				if (!cpriv->evt_id)
					return event_process(evt_id, stack, stack_index, event_get_timestamp(evt));

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

	if (cpriv->pload) {

		struct analyzer_imap_ce_priv_pload *cpload = cpriv->pload;

		if (cpload->evt_msg) {
			if (event_is_started(cpload->evt_msg))
				event_process_end(cpload->evt_msg);
			else
				event_cleanup(cpload->evt_msg);
		}

	}

	if (cpriv->common_data) {

		struct analyzer_imap_ce_priv_common_data *cdata = cpriv->common_data;

		if (cdata->server_host)
			free(cdata->server_host);
		if (cdata->client_addr)
			ptype_cleanup(cdata->client_addr);
		if (cdata->server_addr)
			ptype_cleanup(cdata->server_addr);

		free(cpriv->common_data);
	}


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
