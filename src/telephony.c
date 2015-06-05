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

#include <pom-ng/proto.h>
#include <pom-ng/pload.h>
#include <pom-ng/ptype_uint16.h>

#include "telephony.h"

static struct telephony_codec_reg telephony_codecs[] = {
	{ telephony_codec_type_audio, "PCMU", 0 },
	{ telephony_codec_type_audio, "G723", 4 },
	{ telephony_codec_type_audio, "PCMA", 8 },
	{ telephony_codec_type_audio, "G729", 18 },
	{ 0, NULL, 0 },
};

static struct proto *telephony_proto_ipv4 = NULL, *telephony_proto_ipv6 = NULL, *telephony_proto_udp = NULL, *telephony_proto_rtp = NULL;

static struct telephony_codec_reg *telephony_codec_get_by_name(char *name) {

	int i;
	for (i = 0; telephony_codecs[i].name; i++) {
		if (strcasecmp(telephony_codecs[i].name, name))
			return &telephony_codecs[i];
	}

	return NULL;
};

int telephony_init() {

	telephony_proto_ipv4 = proto_get("ipv4");
	telephony_proto_ipv6 = proto_get("ipv6");
	telephony_proto_udp = proto_get("udp");
	telephony_proto_rtp = proto_get("rtp");

	if (!telephony_proto_ipv4 || !telephony_proto_ipv6 || !telephony_proto_udp || !telephony_proto_rtp) {
		pomlog(POMLOG_ERR "Failed to get hold of all the needed protocols");
		return POM_ERR;
	}


	return POM_OK;
}

static int telephony_sdp_parse_line_a_rtpmap(struct telephony_sdp *sdp, char *line, size_t len) {


	// Parse the payload type
	
	uint8_t pt = 0;
	char *space = memchr(line, ' ', len);
	if (!space)
		return POM_OK;

	size_t pt_len = space - line;
	if (pt_len > 3)
		return POM_OK;
	
	char pt_str[4] = { 0 };
	memcpy(pt_str, line, pt_len);
	if (sscanf(pt_str, "%hhu", &pt) != 1)
		return POM_OK;

	line += pt_len + 1;
	len -= pt_len + 1;

	char *slash = memchr(line, '/', len);
	if (!slash) {
		pomlog(POMLOG_DEBUG "No '/' found in rtpmap line");
		return POM_OK;
	}

	size_t codec_name_len = slash - line;
	char *codec_name = strndup(line, codec_name_len);
	if (!codec_name) {
		pom_oom(codec_name_len + 1);
		return POM_ERR;
	}

	struct telephony_codec_reg *codec = telephony_codec_get_by_name(codec_name);

	if (!codec) {
		pomlog(POMLOG_DEBUG "Codec %s not supported", codec_name);
		free(codec_name);
		return POM_OK;
	}
	free(codec_name);

	line += codec_name_len + 1;
	len -= codec_name_len + 1;

	// Parse the clock rate
	size_t clock_rate_len = len;
	slash = memchr(line, '/', len);
	if (slash)
		clock_rate_len = slash - line;

	char clock_rate_str[16] = { 0 };

	if  (clock_rate_len > sizeof(clock_rate_str) - 1) {
		pomlog(POMLOG_DEBUG "Clock rate length too long in SDP a= line");
		return POM_OK;
	}
	
	memcpy(clock_rate_str, line, clock_rate_len);

	unsigned int clock_rate = 0;
	if (sscanf(clock_rate_str, "%u", &clock_rate) != 1) {
		pomlog(POMLOG_DEBUG "Error while parsing the clock rate");
		return POM_OK;
	}


	uint8_t chan_num = 1;
	
	// Parse possible encoding parameter (channel number)
	if (slash) {
		if (len < 2) {
			pomlog(POMLOG_DEBUG "Channel number string too short in SDP a= line");
			return POM_OK;
		}
		chan_num = *(slash + 1);
	}

	if (sdp->streams) {
		// Apply parameters to the stream
		
		// First, find the corresponding pload
		struct telephony_stream_payload *pload;
		for (pload = sdp->streams->ploads; pload && pload->pload_type != pt; pload = pload->next);
		if (!pload) {
			// Not found, create a new one
			pomlog(POMLOG_DEBUG "Payload type %hhu not found while parsing SDP a= line", pt);
			pload = malloc(sizeof(struct telephony_stream_payload));
			if (!pload) {
				pom_oom(sizeof(struct telephony_stream_payload));
				return POM_ERR;
			}
			memset(pload, 0, sizeof(struct telephony_stream_payload));
			pload->next = sdp->streams->ploads;
			sdp->streams->ploads = pload;
		}

		if (pload->codec) {
			pomlog(POMLOG_DEBUG "Codec for pload %hhu is already defined", pt);
		} else {
			pload->codec = codec;
		}
		pload->chan_num = chan_num;

	} else {
		// This is a session attribute
		struct telephony_sdp_attrib *a = malloc(sizeof(struct telephony_sdp_attrib));
		if (!a) {
			pom_oom(sizeof(struct telephony_sdp_attrib));
			return POM_ERR;
		}
		memset(a, 0, sizeof(struct telephony_sdp_attrib));
		a->type = telephony_sdp_attrib_rtpmap;
		a->rtpmap.codec = codec;
		a->rtpmap.pload_type = pt;
		a->rtpmap.chan_num = chan_num;

	}

	return POM_OK;
}

static int telephony_sdp_parse_line_a(struct telephony_sdp *sdp, char *line, size_t len) {

	size_t str_len = 0;

	// Check for rtpmap attribute
	char *rtpmap = "rtpmap:";
	str_len = strlen(rtpmap);
	if (len > str_len && !strncasecmp(line, rtpmap, str_len))
		return telephony_sdp_parse_line_a_rtpmap(sdp, line + str_len, len - str_len);
	
	// Test for the inactive/sendonly/recvonly/sendrecv
	char *sendrecv[] = {
		"inactive",
		"sendonly",
		"recvonly",
		"sendrecv",
		NULL
	};

	enum telephony_stream_direction dir = telephony_stream_direction_unknown;

	int i;
	for (i = 0; sendrecv[i]; i++) {
		str_len = strlen(sendrecv[i]);
		if (len < str_len)
			continue;
		if (!strncasecmp(line, sendrecv[i], str_len)) {
			dir = i + telephony_stream_direction_inactive;

			if (sdp->streams) {
				sdp->streams->dir = dir;
			} else {
				struct telephony_sdp_attrib *a = malloc(sizeof(struct telephony_sdp_attrib));
				if (!a) {
					pom_oom(sizeof(struct telephony_sdp_attrib));
					return POM_ERR;
				}
				memset(a, 0, sizeof(struct telephony_sdp_attrib));
				a->type = telephony_sdp_attrib_direction;
				a->direction = dir;

				a->next = sdp->attribs;
				sdp->attribs = a;
			}
		}
	}
	
	// Not supported then

	return POM_OK;
}

static int telephony_sdp_parse_line_c(struct telephony_sdp *sdp, char *line, size_t len) {

	if (len < 3)
		return POM_OK;
	if (memcmp("IN ", line, 3)) // Only IN addresses are supported now
		return POM_OK;

	line += 3;
	len -= 3;

	if (len < 4)
		return POM_OK;

	struct proto *proto = NULL;
	struct ptype *addr = NULL;
	if (!memcmp("IP4 ", line, 4)) {
		proto = telephony_proto_ipv4;
		addr = ptype_alloc("ipv4");
	} else if (!memcmp("IP6 ", line, 4)) {
		proto = telephony_proto_ipv6;
		addr = ptype_alloc("ipv6");
	} else {
		return POM_OK;
	}

	if (!proto || !addr)
		return POM_ERR;

	line += 4;
	len -= 4;

	char *addr_str = strndup(line, len);
	if (!addr_str) {
		ptype_cleanup(addr);
		return POM_ERR;
	}

	// TODO handle multicast TTL

	if (ptype_parse_val(addr, addr_str) != POM_OK) {
		pomlog(POMLOG_DEBUG "Invalid address in SDP : '%s'", addr_str);
		free(addr_str);
		ptype_cleanup(addr);
		return POM_ERR;
	}

	free(addr_str);

	struct telephony_stream_address *sdp_addr = malloc(sizeof(struct telephony_stream_address));
	if (!sdp_addr) {
		pom_oom(sizeof(struct telephony_stream_address));
		ptype_cleanup(addr);
		return POM_ERR;
	}
	memset(sdp_addr, 0, sizeof(struct telephony_stream_address));

	sdp_addr->proto = proto;
	sdp_addr->addr = addr;

	if (sdp->streams) {
		sdp_addr->next = sdp->streams->addrs;
		sdp->streams->addrs = sdp_addr;
	} else {
		if (sdp->addr) {
			pomlog(POMLOG_DEBUG "Warning, the SDP already has a session level address");
			free(sdp_addr);
			ptype_cleanup(addr);
		} else {
			sdp->addr = sdp_addr;
		}
	}

	return POM_OK;
}

static int telephony_sdp_parse_line_m(struct telephony_sdp *sdp, char *line, size_t len) {

	char *media_str[] = {
		"audio",
		"video",
		"text",
		"application",
		"message",
		NULL
	};

	// Add the stream to the SDP so additional attributes get added to it even if we can't parse it
	
	struct telephony_stream *stream = malloc(sizeof(struct telephony_stream));
	if (!stream) {
		pom_oom(sizeof(struct telephony_stream));
		return POM_ERR;
	}
	memset(stream, 0, sizeof(struct telephony_stream));
	stream->next = sdp->streams;
	if (stream->next)
		stream->next->prev = stream;
	sdp->streams = stream;
	stream->port_num = 1;

	// Get the codec type
	int i;
	for (i = 0; media_str[i]; i++) {
		size_t str_len = strlen(media_str[i]);
		if (len < str_len + 1)
			continue;
		
		if (!strncasecmp(line, media_str[i], str_len)) {
			stream->pload_type = i + telephony_codec_type_audio;
			line += str_len + 1;
			len -= str_len + 1;
			break;
		}
	}

	if (stream->pload_type == telephony_codec_type_unknown)
		return POM_OK;
	
	// Parse the port

	char port_str[6] = { 0 };

	char *space = memchr(line, ' ', len);
	if (!space)
		return POM_OK;

	size_t port_len = space - line;
	if (port_len >= sizeof(port_str))
		return POM_OK;

	char *slash = memchr(line, '/', port_len);

	if (slash) {
		// Parse the port number
		port_len = slash - line;
		slash++;
		size_t port_num_len = space - slash;
		char port_num_str[6] = { 0 };
		if (port_num_len >= sizeof(port_num_str))
			return POM_OK;
		memcpy(port_num_str, slash, port_num_len);

		if (sscanf(port_num_str, "%hu", &stream->port_num) != 1)
			return POM_OK;
	}

	memcpy(port_str, line, port_len);

	if (sscanf(port_str, "%hu", &stream->port) != 1)
		return POM_OK;

	len -= space - line + 1;
	line = space + 1;


	// Parse the protocol
	char *proto_str[] = {
		"RTP/AVP",
		"RTP/SAVP",
		NULL,
	};
	

	for (i = 0; proto_str[i]; i++) {
		size_t str_len = strlen(proto_str[i]);
		if (len < str_len)
			continue;

		if (!strncasecmp(line, proto_str[i], str_len)) {
			stream->type = i + telephony_stream_type_rtp_avp;
			line += str_len;
			len -= str_len;
			break;
		}
	}

	if (stream->type == telephony_stream_type_unknown)
		return POM_OK;

	stream->l4proto = telephony_proto_udp;

	// Parse the format
	
	while (len) {
		while (len && *line == ' ') {
			line++;
			len--;
		}
		
		char *space = memchr(line, ' ', len);
		size_t fmt_len = len;
		if (space)
			fmt_len = space - line;

		char fmt_str[4] = { 0 };
		if (fmt_len > 3) {
			pomlog(POMLOG_DEBUG "Format in SDP m= line is too long");
			return POM_OK;
		}
		memcpy(fmt_str, line, fmt_len);

		struct telephony_stream_payload *p = malloc(sizeof(struct telephony_stream_payload));
		if (!p) {
			pom_oom(sizeof(struct telephony_stream_payload));
			return POM_ERR;
		}
		memset(p, 0, sizeof(struct telephony_stream_payload));

		if (sscanf(fmt_str, "%hhu", &p->pload_type) != 1) {
			pomlog(POMLOG_DEBUG "Failed to parse SDP format payload type");
			return POM_OK;
		}

		// Make sure the payload is not a dupe
		struct telephony_stream_payload *tmp;
		for (tmp = stream->ploads; tmp && tmp->pload_type != p->pload_type; tmp = tmp->next);
		if (tmp) {
			pomlog(POMLOG_DEBUG "Duplicate payload in SDP m= line format");
			free(p);
		} else {
			p->next = stream->ploads;
			stream->ploads = p;
		}

		line += fmt_len;
		len -= fmt_len;
	}

	return POM_OK;
}


struct telephony_sdp *telephony_sdp_alloc(struct telephony_sdp_dialog *d, ptime ts) {

	struct telephony_sdp *sdp = malloc(sizeof(struct telephony_sdp));

	if (!sdp) {
		pom_oom(sizeof(struct telephony_sdp));
		return NULL;
	}
	memset(sdp, 0, sizeof(struct telephony_sdp));

	sdp->parser = packet_stream_parser_alloc(TELEPHONY_SDP_MAX_LINE_LEN, PACKET_STREAM_PARSER_FLAG_TRIM);
	if (!sdp->parser) {
		free(sdp);
		return NULL;
	}

	sdp->dialog = d;
	sdp->ts = ts;

	return sdp;
}

int telephony_sdp_parse(struct telephony_sdp *sdp, void *data, size_t len) {

	if (!sdp)
		return POM_ERR;

	if (packet_stream_parser_add_payload(sdp->parser, data, len) != POM_OK)
		return POM_ERR;

	
	char *line = NULL;
	size_t line_len = 0;

	do {

		if (packet_stream_parser_get_line(sdp->parser, &line, &line_len) != POM_OK)
			return POM_ERR;

		if (!line) // No more full lines in the packet
			return POM_OK;

		if (len < 3) // Empty or invalid line
			continue;

		char line_type = *line;

		line += 2;
		line_len -= 2;

		switch (line_type) {
			case 'a':
				telephony_sdp_parse_line_a(sdp, line, line_len);
				break;
			case 'c':
				telephony_sdp_parse_line_c(sdp, line, line_len);
				break;
			case 'm':
				telephony_sdp_parse_line_m(sdp, line, line_len);
				break;

		}


	} while (1);

	return POM_OK;

}

int telephony_sdp_end(struct telephony_sdp *sdp) {

	// Free up the parser
	
	void *pload;
	size_t len;
	packet_stream_parser_get_remaining(sdp->parser, &pload, &len);
	if (len)
		pomlog(POMLOG_DEBUG "SDP not entirely parsed !");

	packet_stream_parser_cleanup(sdp->parser);
	sdp->parser = NULL;


	// Apply session parameters to each stream

	struct telephony_stream *stream = NULL;

	// Apply the address
	if (sdp->addr) {
	
		for (stream = sdp->streams; stream; stream = stream->next) {
			if (stream->addrs)
				continue;

			struct telephony_stream_address *addr = malloc(sizeof(struct telephony_stream_address));
			if (!addr) {
				pom_oom(sizeof(struct telephony_stream_address));
				return POM_ERR;
			}
			memset(addr, 0, sizeof(struct telephony_stream_address));
			addr->proto = sdp->addr->proto;
			addr->addr = ptype_alloc_from(sdp->addr->addr);
			if (!addr->addr) {
				free(addr);
				return POM_ERR;
			}

			addr->next = stream->addrs;
			stream->addrs = addr;
		}

	}

	// Apply the session attributes

	while (sdp->attribs) {
		struct telephony_sdp_attrib *attr = sdp->attribs;
		sdp->attribs = attr->next;

		struct telephony_stream *stream;
		for (stream = sdp->streams; stream; stream = stream->next) {

			if (attr->type == telephony_sdp_attrib_rtpmap) {
				// First, find the corresponding pload
				struct telephony_stream_payload *pload;
				for (pload = stream->ploads; pload && pload->pload_type != attr->rtpmap.pload_type; pload = pload->next);
				if (!pload) {
					pload = malloc(sizeof(struct telephony_stream_payload));
					if (!pload) {
						pom_oom(sizeof(struct telephony_stream_payload));
						return POM_ERR;
					}
					memset(pload, 0, sizeof(struct telephony_stream_payload));
					pload->next = sdp->streams->ploads;
					stream->ploads = pload;
				}

				if (!pload->codec) {
					// Apply only if this particular rtpmap line wasn't specified for the media
					pload->codec = attr->rtpmap.codec;
					pload->chan_num = attr->rtpmap.chan_num;
				}
			} else if (attr->type == telephony_sdp_attrib_direction) {
				if (stream->dir == telephony_stream_direction_unknown)
					stream->dir = attr->direction;
			}
		}

		free(attr);
	}


	return POM_OK;
}

struct telephony_stream *telephony_stream_find(struct telephony_stream *streams, struct ptype *addr, struct proto *l4proto, uint16_t port) {

	struct telephony_stream *tmp;
	for (tmp = streams; tmp; tmp = tmp->next) {
		if (tmp->l4proto != l4proto)
			continue;

		int match = 0, i;
		for (i = 0; i < tmp->port_num; i++) {
			if (port == (tmp->port * (i * 2))) {
				match = 1;
				break;
			}
		}

		if (!match)
			continue;

		match = 0;
		struct telephony_stream_address *tmp_addr;
		for (tmp_addr = tmp->addrs; tmp_addr; tmp_addr = tmp_addr->next) {
			if (ptype_compare_val(PTYPE_OP_EQ, tmp_addr->addr, addr)) {
				match = 1;
				break;
			}
		}

		if (match)
			break;
	}


	return tmp;
}

void telephony_sdp_expectation_callback_cleanup(void *priv) {

	event_refcount_dec(priv);
}

int telephony_sdp_add_expectations(struct telephony_sdp *sdp, ptime now) {

	if (!sdp)
		return POM_ERR;

	struct telephony_sdp_dialog *d = sdp->dialog;
	struct telephony_stream *stream = sdp->streams;

	// Check each stream present in the SDP and find out if we are already monitoring it
	while (stream) {

		// We only support RTP/AVP stream so far
		if (stream->type != telephony_stream_type_rtp_avp) {
			stream = stream->next;
			continue;
		}

		// Protocol could not be determined
		if (!stream->l4proto) {
			stream = stream->next;
			continue;
		}

		// Unknown stream direction
		if (stream->dir == telephony_stream_direction_unknown) {
			stream = stream->next;
			continue;
		}

		// No address defined
		if (!stream->addrs) {
			stream = stream->next;
			continue;
		}

		// Find if the stream already exist in the dialog
		// It should match the first address and port
		struct telephony_stream *tmp_stream = telephony_stream_find(d->streams, stream->addrs->addr, stream->l4proto, stream->port);
		if (tmp_stream) {
			// The expectation for this stream as already been added !
			// TODO check if port is 0 or if stream is inactive
			stream = stream->next;
			continue;
		}

		// Rejected stream
		if (!stream->port) {
			stream = stream->next;
			continue;
		}

		// Inactive stream
		if (stream->dir == telephony_stream_direction_inactive) {
			stream = stream->next;
			continue;
		}

		// At this point the stream is unknown to us and we need to create an expectation for it

		struct telephony_stream_address *addr;
		for (addr = stream->addrs; addr; addr = addr->next) {

			int i;
			for (i = 0; i < stream->port_num; i++) {
				// Create an expectation for each address/port combination
				// RTP use only pair ports

				struct proto_expectation *e = proto_expectation_alloc(telephony_proto_rtp, NULL);
				if (!e)
					return POM_ERR;

				if (proto_expectation_append(e, addr->proto, addr->addr, NULL) != POM_OK) {
					proto_expectation_cleanup(e);
					return POM_ERR;
				}

				struct ptype *port = ptype_alloc("uint16");
				if (!port) {
					proto_expectation_cleanup(e);
					return POM_ERR;
				}

				PTYPE_UINT16_SETVAL(port, stream->port + (i * 2));

				if (proto_expectation_append(e, stream->l4proto, port, NULL) != POM_OK) {
					proto_expectation_cleanup(e);
					ptype_cleanup(port);
					return POM_ERR;
				}
				ptype_cleanup(port);

				struct event *evt = sdp->dialog->call->evt;
				if (evt)
					event_refcount_inc(evt);

				proto_expectation_set_match_callback(e, telephony_sdp_expectation_callback, evt, telephony_sdp_expectation_callback_cleanup);

				// FIXME will be improved after
				if (proto_expectation_add_and_cleanup(e, 60, now) != POM_OK) {
					proto_expectation_cleanup(e);
					return POM_ERR;
				}
			}
		}

		tmp_stream = stream;
		stream = stream->next;

		// Remove the stream from the sdp list
		if (tmp_stream->next)
			tmp_stream->next->prev = tmp_stream->prev;

		if (tmp_stream->prev)
			tmp_stream->prev->next = tmp_stream->next;
		else
			sdp->streams = tmp_stream->next;

		// Add the stream to the SDP dialog
		tmp_stream->next = d->streams;
		if (tmp_stream->next)
			tmp_stream->next->prev = tmp_stream;
		d->streams = tmp_stream;

		tmp_stream->prev = NULL;
	}

	return POM_OK;
}

void telephony_stream_cleanup(struct telephony_stream *stream) {

	while (stream->addrs) {
		struct telephony_stream_address *addr = stream->addrs;
		stream->addrs = addr->next;

		if (addr->addr)
			ptype_cleanup(addr->addr);
		free(addr);
	}

	while (stream->ploads) {
		struct telephony_stream_payload *pload = stream->ploads;
		stream->ploads = pload->next;
		free(pload);
	}
	free(stream);
}

void telephony_sdp_cleanup(struct telephony_sdp *sdp) {

	if (!sdp)
		return;

	if (sdp->parser)
		packet_stream_parser_cleanup(sdp->parser);

	while (sdp->addr) {
		struct telephony_stream_address *addr = sdp->addr;
		sdp->addr = addr->next;

		if (addr->addr)
			ptype_cleanup(addr->addr);

		free(addr);
	}

	while (sdp->streams) {
		struct telephony_stream *stream = sdp->streams;
		sdp->streams = stream->next;
		telephony_stream_cleanup(stream);
	}

	while (sdp->attribs) {
		struct telephony_sdp_attrib *attr = sdp->attribs;
		sdp->attribs = attr->next;
		free(attr);
	}

	free(sdp);

}


struct telephony_call *telephony_call_alloc(struct event *evt) {

	struct telephony_call *res = malloc(sizeof(struct telephony_call));
	if (!res) {
		pom_oom(sizeof(struct telephony_call));
		return NULL;
	}
	memset(res, 0, sizeof(struct telephony_call));

	res->evt = evt;

	return res;
}

void telephony_call_cleanup(struct telephony_call *call) {

	while (call->dialogs) {
		struct telephony_sdp_dialog *d = call->dialogs;
		call->dialogs = d->next;
		telephony_sdp_dialog_cleanup(d);
	}

	free(call);
}


struct telephony_sdp_dialog *telephony_sdp_dialog_alloc(struct telephony_call *call) {

	struct telephony_sdp_dialog *res = malloc(sizeof(struct telephony_sdp_dialog));
	if (!res) {
		pom_oom(sizeof(struct telephony_sdp_dialog));
		return NULL;
	}
	memset(res, 0, sizeof(struct telephony_sdp_dialog));
	res->call = call;

	return res;
}

void telephony_sdp_dialog_cleanup(struct telephony_sdp_dialog *sdp_dialog) {

	while (sdp_dialog->streams) {
		struct telephony_stream *s = sdp_dialog->streams;
		sdp_dialog->streams = s->next;
		telephony_stream_cleanup(s);
	}

	free(sdp_dialog);
}

void telephony_sdp_expectation_callback(struct proto_expectation *e, void *priv, struct conntrack_entry *ce) {

	struct telephony_rtp_ce_priv *p = malloc(sizeof(struct telephony_rtp_ce_priv));
	if (!p) {
		pom_oom(sizeof(struct telephony_rtp_ce_priv));
		return;
	}
	memset(p, 0, sizeof(struct telephony_rtp_ce_priv));
	p->evt = priv;

	if (conntrack_add_priv(ce, telephony_init, p, telephony_cleanup_rtp_priv) != POM_OK) {
		event_refcount_dec(priv);
		free(p);
		return;
	}
}

int telephony_cleanup_rtp_priv(void *obj, void *priv) {

	struct telephony_rtp_ce_priv *p = priv;
	if (p->evt)
		event_refcount_dec(p->evt);

	free(p);
	return POM_OK;
}

