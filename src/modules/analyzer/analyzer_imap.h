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

#ifndef __ANALYZER_IMAP_H__
#define __ANALYZER_IMAP_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/proto.h>
#include <pom-ng/mime.h>

#define ANALYZER_IMAP_EVT_COMMON_DATA_COUNT	4
#define ANALYZER_IMAP_EVT_MSG_DATA_COUNT	ANALYZER_IMAP_EVT_COMMON_DATA_COUNT + 2
#define ANALYZER_IMAP_EVT_AUTH_DATA_COUNT	ANALYZER_IMAP_EVT_COMMON_DATA_COUNT + 3
#define ANALYZER_IMAP_EVT_ID_DATA_COUNT		ANALYZER_IMAP_EVT_COMMON_DATA_COUNT + 2

#define ANALYZER_IMAP_FLAGS_LISTENING	0x1
#define ANALYZER_IMAP_FLAGS_COMMON_DATA	0x2

#define ANALYZER_IMAP_RFC822_PLOAD_TYPE	"rfc822"

enum {
	analyzer_imap_common_client_addr = 0,
	analyzer_imap_common_server_addr,
	analyzer_imap_common_server_port,
	analyzer_imap_common_server_host,
	analyzer_imap_common_end
};

enum {
	analyzer_imap_msg_mailbox = analyzer_imap_common_end,
	analyzer_imap_msg_uid,
};

enum {
	analyzer_imap_auth_type = analyzer_imap_common_end,
	analyzer_imap_auth_params,
	analyzer_imap_auth_success,
};

enum {
	analyzer_imap_id_client_params = analyzer_imap_common_end,
	analyzer_imap_id_server_params,
};

struct analyzer_imap_priv {
	struct event_reg *evt_cmd, *evt_rsp, *evt_pload;
	struct event_reg *evt_msg, *evt_auth, *evt_id;
	struct proto_packet_listener *pkt_listener;
	int listening;
};

struct analyzer_imap_msg {
	uint64_t header_size, body_size;
	uint64_t uid, seq;
	struct analyzer_imap_msg *prev, *next;
};

struct analyzer_imap_ce_priv {
	struct event *evt_msg, *evt_id;
	char *server_host;
	struct ptype *client_addr, *server_addr;
	int common_data_fetched;
	uint16_t server_port;


	char *cur_mbx;
	struct analyzer_imap_msg *msg_queue_head, *msg_queue_tail;

	struct analyzer_imap_cmd_entry *cmd_queue_head, *cmd_queue_tail;
};


enum analyzer_imap_fetch_field {

	analyzer_imap_fetch_field_unknown = 0,
	analyzer_imap_fetch_field_uid,
	analyzer_imap_fetch_field_internaldate,
	analyzer_imap_fetch_field_flags,
	analyzer_imap_fetch_field_rfc822,
	analyzer_imap_fetch_field_rfc822_header,
	analyzer_imap_fetch_field_rfc822_size,
	analyzer_imap_fetch_field_rfc822_text,
	analyzer_imap_fetch_field_bodystructure,
	analyzer_imap_fetch_field_body,
	analyzer_imap_fetch_field_envelope,
};


enum analyzer_imap_fetch_body_field {
	analyzer_imap_fetch_body_field_unknown = 0,
	analyzer_imap_fetch_body_field_header,
	analyzer_imap_fetch_body_field_header_fields,
	analyzer_imap_fetch_body_field_header_fields_not,
	analyzer_imap_fetch_body_field_mime,
	analyzer_imap_fetch_body_field_text,
	analyzer_imap_fetch_body_field_part
};

struct analyzer_imap_fetch_body_part {
	int part;
	struct analyzer_imap_fetch_body_part *next;
};

struct analyzer_imap_fetch_bodystructure {
	struct mime_type *mime_type;
	char *encoding;
	
};

enum analyzer_imap_cmd {
	analyzer_imap_cmd_unk = 0,
	analyzer_imap_cmd_auth,
	analyzer_imap_cmd_id,
};

enum analyzer_imap_rsp_status {
	analyzer_imap_rsp_status_unk = 0,
	analyzer_imap_rsp_status_ok,
	analyzer_imap_rsp_status_no,
	analyzer_imap_rsp_status_bad,
	analyzer_imap_rsp_status_bye,
};

struct analyzer_imap_cmd_entry {

	char *tag;
	enum analyzer_imap_cmd cmd;
	struct event *cmd_evt, *out_evt;
	struct analyzer_imap_cmd_entry *prev, *next;

};


static int analyzer_imap_mod_register(struct mod_reg *mod);
static int analyzer_imap_mod_unregister();
static int analyzer_imap_init(struct analyzer *analyzer);
static int analyzer_imap_cleanup(struct analyzer *analyzer);

static int analyzer_imap_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
static int analyzer_imap_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_imap_pload_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_imap_pload_event_process_end(struct event *evt, void *obj);
static int analyzer_imap_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_imap_event_process_end(struct event *evt, void *obj);
static int analyzer_imap_ce_priv_cleanup(void *obj, void *priv);
static int analyzer_imap_evt_msg_cleanup(void *priv);

#endif

