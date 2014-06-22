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

#define ANALYZER_SIP_CALL_DATA_COUNT	3
#define ANALYZER_SIP_SDP_PLOAD_TYPE	"sdp"

enum {
	analyzer_sip_call_from_display,
	analyzer_sip_call_to_display,
	analyzer_sip_call_id,
};

struct analyzer_sip_priv {

	struct event_reg *evt_sip_req, *evt_sip_rsp;

	struct event_reg *evt_sip_call;

	struct proto *proto_sip;
	struct proto_packet_listener *sip_packet_listener;

	int listening;

};

struct analyzer_sip_call {

	char *call_id;
	struct conntrack_session *sess;
	struct analyzer_sip_rtp_stream *streams;

	UT_hash_handle hh;
};


struct analyzer_sip_sdp_priv {

	struct analyzer_sip_sdp_line_lst *line_head, *line_tail;
	struct analyzer_sip_call *call;
	struct telephony_sdp *sdp;
};

struct mod_reg_info* analyzer_sip_reg_info();
static int analyzer_sip_mod_register(struct mod_reg *mod);
static int analyzer_sip_mod_unregister();

static int analyzer_sip_init(struct analyzer *analyzer);
static int analyzer_sip_cleanup(struct analyzer *analyzer);

static int analyzer_sip_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);

static int analyzer_sip_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_sip_event_process_end(struct event *evt, void *obj);

static int analyzer_sip_sdp_open(void *obj, void **priv, struct pload *pload);
static int analyzer_sip_sdp_write(void *obj, void *priv, void *data, size_t len);
static int analyzer_sip_sdp_close(void *obj, void *priv);

#endif
