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

#define ANALYZER_SMTP_EVT_MSG_DATA_COUNT 3

enum {
	analyzer_smtp_msg_from,
	analyzer_smtp_msg_to,
	analyzer_smtp_msg_result
};

enum analyzer_smtp_last_cmd {
	analyzer_smtp_last_cmd_other,
	analyzer_smtp_last_cmd_mail_from,
	analyzer_smtp_last_cmd_rcpt_to,
	analyzer_smtp_last_cmd_data
};


struct analyzer_smtp_priv {
	struct event_reg *evt_cmd, *evt_reply;
	struct event_reg *evt_msg;
	struct proto_packet_listener *pkt_listener;
	struct analyzer_pload_type *rfc822_msg_pload_type;
};

struct analyzer_smtp_ce_priv {
	struct event *evt_msg;
	enum analyzer_smtp_last_cmd last_cmd;
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

