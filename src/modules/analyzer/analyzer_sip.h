/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __ANALYZER_SIP_H__
#define __ANALYZER_SIP_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/pload.h>
#include <pom-ng/telephony.h>
#include <uthash.h>

#define ANALYZER_SIP_CALL_COMMON_DATA_COUNT	5
#define ANALYZER_SIP_CALL_DATA_COUNT		8
#define ANALYZER_SIP_CALL_DTMF_DATA_COUNT	7
#define ANALYZER_SIP_SDP_PLOAD_TYPE		"sdp"
#define ANALYZER_SIP_DTMF_PLOAD_TYPE		"dtmf"

enum {
	analyzer_sip_call_common_from_display = 0,
	analyzer_sip_call_common_from_uri,
	analyzer_sip_call_common_to_display,
	analyzer_sip_call_common_to_uri,
	analyzer_sip_call_common_id
};

enum {
	analyzer_sip_call_trying_duration = 5,
	analyzer_sip_call_ringing_duration,
	analyzer_sip_call_connected_duration
};

enum {
	analyzer_sip_dtmf_signal = 5,
	analyzer_sip_dtmf_duration
};


struct analyzer_sip_priv {

	struct event_reg *evt_sip_req, *evt_sip_rsp;

	struct event_reg *evt_sip_call, *evt_sip_call_dial, *evt_sip_call_ringing, *evt_sip_call_connect, *evt_sip_call_hangup, *evt_sip_dtmf;

	struct proto *proto_sip;
	struct proto_packet_listener *sip_packet_listener;

	struct ptype *p_dialog_timeout;
	struct ptype *p_call_max_duration;

	int listening;
	int sdp_listening, dtmf_listening;

};

enum analyzer_sip_method {
	analyzer_sip_method_unknown = 0,
	analyzer_sip_method_invite,
	analyzer_sip_method_ack,
	analyzer_sip_method_cancel,
	analyzer_sip_method_bye,
};

struct analyzer_sip_call_dialog {

	char *from_tag, *to_tag;
	struct conntrack_entry *ce;
	struct analyzer_sip_conntrack_priv *ce_priv;
	char *branch;
	struct analyzer_sip_call *call;
	uint32_t cseq;
	enum analyzer_sip_method cseq_method;
	struct analyzer_sip_call_dialog *prev, *next;
	struct conntrack_timer *t;
	int terminated;

	struct analyzer_sip_call_dialog *ce_prev, *ce_next;

};

enum analyzer_sip_call_state {
	analyzer_sip_call_state_unknown = 0,
	analyzer_sip_call_state_trying,
	analyzer_sip_call_state_alerting,
	analyzer_sip_call_state_connected,
	analyzer_sip_call_state_terminated,
};

enum analyzer_sip_call_usage {
	analyzer_sip_call_usage_other = 0,
	analyzer_sip_call_usage_invite,
};

struct analyzer_sip_call {

	char *call_id;
	pthread_mutex_t lock;
	struct timer *t;

	struct telephony_call *tel_call;

	struct analyzer_sip_call_dialog *dialogs;

	enum analyzer_sip_call_state state;
	enum analyzer_sip_call_usage usage;

	ptime start_ts, ringing_ts, connected_ts;

	struct event *evt;

	UT_hash_handle hh;

	struct analyzer_sip_call *sess_prev, *sess_next;
};

struct analyzer_sip_sdp_priv {

	struct analyzer_sip_sdp_line_lst *line_head, *line_tail;
	struct analyzer_sip_call *call;
	struct telephony_sdp *sdp;
	ptime ts;
};

struct analyzer_sip_conntrack_priv {

	struct analyzer_sip_call_dialog *dialogs;
	struct analyzer_sip_call_dialog *cur_dialog;

};

struct mod_reg_info* analyzer_sip_reg_info();
static int analyzer_sip_mod_register(struct mod_reg *mod);
static int analyzer_sip_mod_unregister();

static int analyzer_sip_init(struct analyzer *analyzer);
static int analyzer_sip_finish(struct analyzer *analyzer);
static int analyzer_sip_cleanup(struct analyzer *analyzer);

static int analyzer_sip_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);

static int analyzer_sip_conntrack_cleanup(void *obj, void *priv);
static int analyzer_sip_call_cleanup(struct analyzer_sip_call *call);

static int analyzer_sip_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);

static int analyzer_sip_call_timeout(void *priv, ptime now);
static int analyzer_sip_dialog_timeout(struct conntrack_entry *ce, void *priv, ptime now);
static int analyzer_sip_dialog_cleanup(struct analyzer_sip_call_dialog *d);

static int analyzer_sip_sdp_open(void *obj, void **priv, struct pload *pload);
static int analyzer_sip_sdp_write(void *obj, void *priv, void *data, size_t len);
static int analyzer_sip_sdp_close(void *obj, void *priv);

static int analyzer_sip_dtmf_open(void *obj, void **priv, struct pload *pload);

#endif
