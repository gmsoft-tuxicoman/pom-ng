/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014-2015 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_TELEPHONY_H__
#define __POM_NG_TELEPHONY_H__

#include <pom-ng/ptype.h>
#include <pom-ng/event.h>


// Codec definitions

enum telephony_codec_type {
	telephony_codec_type_unknown = 0,
	telephony_codec_type_audio,
	telephony_codec_type_video,
	telephony_codec_type_text,
	telephony_codec_type_application,
	telephony_codec_type_message,

};

struct telephony_codec_info {
	struct telephony_codec_reg *codec;
	unsigned int clock_rate;
	uint8_t pload_type, chan_num;
};

struct telephony_call;
struct telephony_sdp;
struct telephony_sdp_dialog;
struct telephony_stream;
struct telephony_rtp_info;

struct telephony_sdp *telephony_sdp_alloc(struct telephony_sdp_dialog *d, ptime ts);
int telephony_sdp_parse(struct telephony_sdp *sdp, void *data, size_t len);
int telephony_sdp_end(struct telephony_sdp *sdp);
int telephony_sdp_add_expectations(struct telephony_sdp *sdp, ptime now);
void telephony_stream_cleanup(struct telephony_stream *stream);
void telephony_sdp_cleanup(struct telephony_sdp *sdp);

struct telephony_call *telephony_call_alloc(struct proto *sess_proto, char *call_id);
void telephony_call_cleanup(struct telephony_call *call);

struct telephony_sdp_dialog *telephony_sdp_dialog_alloc(struct telephony_call *call);
void telephony_sdp_dialog_cleanup(struct telephony_sdp_dialog *sdp_dialog);

struct proto *telephony_stream_info_get_sess_proto(struct conntrack_entry *ce);
char *telephony_stream_info_get_call_id(struct conntrack_entry *ce);
int telephony_stream_info_get_codec(struct telephony_codec_info *info, struct proto_process_stack *stack, int stack_index);

char *telephony_codec_info_get_pload_type(struct telephony_codec_info *info);
#endif
