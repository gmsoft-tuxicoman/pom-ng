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


#ifndef __TELEPHONY_H__
#define __TELEPHONY_H__


#include <pom-ng/telephony.h>

#define TELEPHONY_SDP_MAX_LINE_LEN	512

struct telephony_codec_reg {

	enum telephony_codec_type type;
	char *name;
	int default_rtp_pload_type;

	struct telephony_codec_reg *prev, *next;

};

// SDP definitions

struct telephony_sdp_port {

	struct proto *proto;
	struct ptype *port;
	struct telephony_sdp_port *next;

};

struct telephony_sdp_address {

	struct proto *proto;
	struct ptype *addr;
	struct telephony_sdp_address *next;
};


struct telephony_sdp_stream_payload {

	struct telephony_codec_reg *codec;
	struct telephony_sdp_stream_payload *next;
	unsigned int clock_rate;
	uint8_t pload_type, chan_num;
};

enum telephony_stream_type {
	telephony_stream_type_unknown = 0,
	telephony_stream_type_rtp_avp,
	telephony_stream_type_rtp_savp,
};

enum telephony_sdp_stream_direction {
	telephony_sdp_stream_direction_unknown = 0,
	telephony_sdp_stream_direction_inactive,
	telephony_sdp_stream_direction_sendonly,
	telephony_sdp_stream_direction_recvonly,
	telephony_sdp_stream_direction_sendrecv,
};


struct telephony_sdp_stream {

	enum telephony_stream_type type;
	struct telephony_sdp_address *addrs;
	struct telephony_sdp_stream_payload *ploads;
	enum telephony_sdp_stream_direction dir;
	enum telephony_codec_type pload_type;
	struct proto *port_proto;

	struct telephony_sdp_stream *next;

	uint16_t port, port_num;

};


enum telephony_sdp_sess_attrib_type {
	telephony_sdp_sess_attrib_direction,
	telephony_sdp_sess_attrib_rtpmap,
};

struct telephony_sdp_sess_attrib_rtpmap {
	struct telephony_codec_reg *codec;
	uint8_t pload_type, chan_num;
};

struct telephony_sdp_sess_attrib {

	enum telephony_sdp_sess_attrib_type type;
	union {
		enum telephony_sdp_stream_direction direction;
		struct telephony_sdp_sess_attrib_rtpmap rtpmap;
	};

	struct telephony_sdp_sess_attrib *next;
};

struct telephony_sdp {

	struct packet_stream_parser *parser;
	struct telephony_sdp_address *addr;

	struct telephony_sdp_sess_attrib *sess_attribs;

	struct telephony_sdp_stream *streams;


};

#endif
