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

#ifndef __ANALYZER_SMTP_H__
#define __ANALYZER_SMTP_H__

#include <pom-ng/analyzer.h>


#define ANALYZER_SMTP_EVT_COMMON_DATA_COUNT	7
#define ANALYZER_SMTP_EVT_MSG_DATA_COUNT	ANALYZER_SMTP_EVT_COMMON_DATA_COUNT + 3
#define ANALYZER_SMTP_EVT_AUTH_DATA_COUNT	ANALYZER_SMTP_EVT_COMMON_DATA_COUNT + 3

#define ANALYZER_SMTP_DOTDOT		"\r\n.."
#define ANALYZER_SMTP_DOTDOT_LEN	4


#define ANALYZER_SMTP_FLAGS_LISTENING	0x1
#define ANALYZER_SMTP_FLAGS_COMMON_DATA	0x2

enum {
	analyzer_smtp_common_client_addr = 0,
	analyzer_smtp_common_server_addr,
	analyzer_smtp_common_server_port,
	analyzer_smtp_common_server_host,
	analyzer_smtp_common_client_hello,
	analyzer_smtp_common_server_hello,
	analyzer_smtp_common_data,
	analyzer_smtp_common_end
};

enum {
	analyzer_smtp_msg_from = analyzer_smtp_common_end,
	analyzer_smtp_msg_to,
	analyzer_smtp_msg_result,
};

enum {
	analyzer_smtp_auth_type = analyzer_smtp_common_end,
	analyzer_smtp_auth_params,
	analyzer_smtp_auth_success,
};

enum analyzer_smtp_last_cmd {
	analyzer_smtp_last_cmd_other,
	analyzer_smtp_last_cmd_mail_from,
	analyzer_smtp_last_cmd_rcpt_to,
	analyzer_smtp_last_cmd_data,
	analyzer_smtp_last_cmd_auth_plain,
	analyzer_smtp_last_cmd_auth_plain_creds,
	analyzer_smtp_last_cmd_auth_login,
	analyzer_smtp_last_cmd_auth_login_user,
	analyzer_smtp_last_cmd_auth_login_pass
};


struct analyzer_smtp_priv {
	struct event_reg *evt_cmd, *evt_reply;
	struct event_reg *evt_msg, *evt_auth;
	struct proto_packet_listener *pkt_listener;
	struct analyzer_pload_type *rfc822_msg_pload_type;
	int listening;
};

struct analyzer_smtp_ce_priv {
	struct event *evt_msg, *evt_auth;
	enum analyzer_smtp_last_cmd last_cmd;
	unsigned int dotdot_pos;
	char *client_hello, *server_hello, *server_host;
	struct ptype *client_addr, *server_addr;
	int common_data_fetched;
	uint16_t server_port;
};


static int analyzer_smtp_mod_register(struct mod_reg *mod);
static int analyzer_smtp_mod_unregister();
static int analyzer_smtp_init(struct analyzer *analyzer);
static int analyzer_smtp_cleanup(struct analyzer *analyzer);

static int analyzer_smtp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
static int analyzer_smtp_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_smtp_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_smtp_event_process_end(struct event *evt, void *obj);
static int analyzer_smtp_ce_priv_cleanup(void *obj, void *priv);
static int analyzer_smtp_evt_msg_cleanup(struct event *evt);

#endif

