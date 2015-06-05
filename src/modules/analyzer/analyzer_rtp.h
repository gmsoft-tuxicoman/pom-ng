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


#ifndef __ANALYZER_RTP_H__
#define __ANALYZER_RTP_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/pload.h>


#define ANALYZER_RTP_STREAM_DATA_COUNT 7


enum {
	analyzer_rtp_stream_src_addr = 0,
	analyzer_rtp_stream_dst_addr,
	analyzer_rtp_stream_src_port,
	analyzer_rtp_stream_dst_port,
	analyzer_rtp_stream_sess_proto,
	analyzer_rtp_stream_call_id,
	analyzer_rtp_stream_ssrc
};

struct analyzer_rtp_priv {

	struct event_reg *evt_rtp_stream;
	struct proto_packet_listener *rtp_listener;
	struct proto *proto_rtp;

};

struct analyzer_rtp_ce_priv {
	struct event *evt[POM_DIR_TOT];
	struct pload *pload[POM_DIR_TOT];
};

struct mod_reg_info* analyzer_rtp_reg_info();
static int analyzer_rtp_mod_register(struct mod_reg *mod);
static int analyzer_rtp_mod_unregister();

static int analyzer_rtp_init(struct analyzer *analyzer);
static int analyzer_rtp_cleanup(struct analyzer *analyzer);
static int analyzer_rtp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
static int analyzer_rtp_pload_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_rtp_ce_cleanup(void *obj, void *priv);
static int analyzer_rtp_stream_event_cleanup(struct event *evt);

#endif
