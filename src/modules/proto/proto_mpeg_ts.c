/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/ptype.h>
#include <pom-ng/core.h>
#include <pom-ng/input_client.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint16.h>

#include "proto_mpeg_ts.h"

#include <string.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <docsis.h>
#include <errno.h>


static struct proto_dependency *proto_docsis = NULL, *proto_mpeg_sect = NULL;

// params
static struct ptype *param_force_no_copy = NULL, *param_mpeg_ts_stream_timeout = NULL;


int proto_mpeg_ts_init(struct registry_instance *i) {

	param_force_no_copy = ptype_alloc("bool");
	param_mpeg_ts_stream_timeout = ptype_alloc_unit("uint16", "seconds");
	if (!param_force_no_copy || !param_mpeg_ts_stream_timeout)
		goto err;

	struct registry_param *p = registry_new_param("force_no_copy", "true", param_force_no_copy, "Should we force packet API to prevent copy packets internally", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("stream_timeout", "60", param_mpeg_ts_stream_timeout, "Timeout for each MPEG PID", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	proto_docsis = proto_add_dependency("docsis");
	proto_mpeg_sect = proto_add_dependency("mpeg_sect");

	if (!proto_docsis || !proto_mpeg_sect) {
		proto_mpeg_ts_cleanup();
		return POM_ERR;
	}


	return POM_OK;

err:
	if (param_force_no_copy)
		ptype_cleanup(param_force_no_copy);
	
	if (param_mpeg_ts_stream_timeout)
		ptype_cleanup(param_mpeg_ts_stream_timeout);

	return POM_ERR;

}

int proto_mpeg_ts_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	unsigned char *buff = s->pload;

	uint16_t pid = ((buff[1] & 0x1F) << 8) | buff[2];
	unsigned char pusi = buff[1] & 0x40;

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_mpeg_ts_field_pid], pid);

	// FIXME Check the adaptation layer

	int hdr_len = 4;

	if (pusi) { // Check PUSI
		if (buff[4] > 183)
			return PROTO_INVALID;
		hdr_len = 5; // Header is 5 bytes long, including the payload unit start pointer
	}

	// Try to find out what type or payload we are dealing with

	enum proto_mpeg_stream_type stream_type;

	if (buff[0] == 0x0 && buff[1] == 0x0 && buff[2] == 0x1) {
		// PES packet, currenly not handled
		s_next->pload = s->pload + hdr_len;
		s_next->plen = s->plen - hdr_len;
		s_next->proto = NULL;
		return PROTO_OK;
	} else if (pid == MPEG_TS_NULL_PID) {
		// Nothing to do for NULL packets
		s_next->proto = NULL;
		return PROTO_OK;
	} else if (pid == MPEG_TS_DOCSIS_PID) {
		stream_type = proto_mpeg_stream_type_docsis;
		s_next->proto = proto_docsis->proto;
	} else {
		// If nothing matched, it's probably a section packet
		stream_type = proto_mpeg_stream_type_sect;
		s_next->proto = proto_mpeg_sect->proto;
	}


	s->ce = conntrack_get(s->proto, s->pkt_info->fields_value[proto_mpeg_ts_field_pid], NULL, NULL, NULL);
	if (!s->ce)
		return PROTO_ERR;
	
	pom_mutex_lock(&s->ce->lock);

	if (!s->ce->priv) {
		s->ce->priv = malloc(sizeof(struct proto_mpeg_ts_conntrack_priv));
		if (!s->ce->priv) {
			pom_mutex_unlock(&s->ce->lock);
			pom_oom(sizeof(struct proto_mpeg_ts_conntrack_priv));
			return PROTO_ERR;
		}
		memset(s->ce->priv, 0, sizeof(struct proto_mpeg_ts_conntrack_priv));

	}

	struct proto_mpeg_ts_conntrack_priv *priv = s->ce->priv;

	unsigned int input_id = p->input->id;
	// Find the MPEG stream from the right input

	if (priv->streams_array_size < (input_id + 1)) {
		struct proto_mpeg_ts_stream *new_streams = realloc(priv->streams, sizeof(struct proto_mpeg_ts_stream) * (input_id + 1));
		if (!new_streams) {
			pom_mutex_unlock(&s->ce->lock);
			pom_oom(sizeof(struct proto_mpeg_ts_stream) * (input_id + 1));
			return PROTO_ERR;
		}
		priv->streams = new_streams;
		memset(&priv->streams[priv->streams_array_size], 0, sizeof(struct proto_mpeg_ts_stream) * ((p->input->id + 1) - priv->streams_array_size));
		priv->streams_array_size = p->input->id + 1;

	}

	struct proto_mpeg_ts_stream *stream = &priv->streams[p->input->id];
	if (!stream->ce) {
		// New stream
		stream->input_id = input_id;
		stream->type = stream_type;

		stream->t = timer_alloc(stream, proto_mpeg_ts_stream_cleanup);
		if (!stream->t) {
			pom_mutex_unlock(&s->ce->lock);
			return PROTO_ERR;
		}
		stream->ce = s->ce;
		stream->last_seq = (buff[3] - 1) & 0xF;

	}

	if (!stream->stream) {
		char *force_no_copy = PTYPE_BOOL_GETVAL(param_force_no_copy);
		stream->stream = packet_stream_alloc(p->id * MPEG_TS_LEN, 0, CT_DIR_FWD, 512 * MPEG_TS_LEN, (*force_no_copy ? PACKET_FLAG_FORCE_NO_COPY : 0), proto_mpeg_ts_process_stream, stream);
		if (!stream->stream) {
			pom_mutex_unlock(&s->ce->lock);
			return PROTO_ERR;
		}
	}

	pom_mutex_unlock(&s->ce->lock);
	
	// Add the packet to the stream
	if (packet_stream_process_packet(stream->stream, p, stack, stack_index, p->id * MPEG_TS_LEN, 0) != POM_OK)
		return PROTO_ERR;

	return PROTO_STOP;
}


int proto_mpeg_ts_process_stream(void *priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_mpeg_ts_stream *stream = priv;

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	unsigned char *buff = s->pload;

	int pusi = buff[1] & 0x40;

	struct proto_dependency *next_proto = NULL;
	if (stream->type == proto_mpeg_stream_type_docsis) {
		next_proto = proto_docsis;
	} else if (stream->type == proto_mpeg_stream_type_sect) {
		next_proto = proto_mpeg_sect;
	} else {
		pomlog(POMLOG_ERR "Internal error : unhandled stream type");
		return PROTO_ERR;
	}


	unsigned int missed = 0;
	stream->last_seq = (stream->last_seq + 1) & 0xF;
	while (stream->last_seq != (buff[3] & 0xF)) {
		stream->last_seq = (stream->last_seq + 1) & 0xF;
		missed++;

		// Add missing payload to length
		// TODO fill the gap in the multipart
		//stream->pkt_cur_len += MPEG_TS_LEN - 4;

	}
	if (missed)
		pomlog(POMLOG_DEBUG "Missed %u MPEG packet(s) on input %u", missed, stream->input_id);

	if (stream->multipart) {

		if (!stream->pkt_tot_len) {
			unsigned char *pload_buff = buff + (pusi ? 5 : 4);
			// Last packet was too short to know the size
			if (stream->type == proto_mpeg_stream_type_docsis) {
				if (stream->multipart->head->len >= sizeof(struct docsis_hdr)) {
					pomlog(POMLOG_DEBUG "MPEG paket with invalid length : %u", stream->multipart->head->len);
					return PROTO_INVALID;
				}

				unsigned char tmp_buff[sizeof(struct docsis_hdr)];
				memcpy(tmp_buff, stream->multipart->head->pkt->buff + stream->multipart->head->pkt_buff_offset, stream->multipart->head->len);
				memcpy(tmp_buff + stream->multipart->head->len, pload_buff, sizeof(struct docsis_hdr) - stream->multipart->head->len);

				struct docsis_hdr *tmp_hdr = (struct docsis_hdr*)tmp_buff;
				stream->pkt_tot_len = ntohs(tmp_hdr->len) + sizeof(struct docsis_hdr);
			} else if (stream->type == proto_mpeg_stream_type_sect) {
				switch (stream->multipart->head->len) {
					case 1:
						stream->pkt_tot_len = ((pload_buff[0] & 0xF) << 8) | pload_buff[1];
						break;
					case 2:
						stream->pkt_tot_len = (((unsigned char*)stream->multipart->head->pkt->buff + stream->multipart->head->pkt_buff_offset)[1] & 0xF) | pload_buff[0];
						break;
				}
				stream->pkt_tot_len += 3; // add the 3 headers bytes
				
			}
		
		}

	}

	unsigned int pos = 4;
	if (pusi) {
		pos++;

		unsigned char ptr = buff[4];

		
		if (stream->multipart) {
			
			if (ptr != stream->pkt_tot_len - stream->pkt_cur_len) {
				pomlog(POMLOG_DEBUG "Invalid tail length for %s packet : expected %u, got %hhu", (stream->type == proto_mpeg_stream_type_docsis ? "DOCSIS" : "SECT" ), stream->pkt_tot_len - stream->pkt_cur_len, ptr);
				packet_multipart_cleanup(stream->multipart);
			} else {

				// Add the end of the previous packet
				if (packet_multipart_add_packet(stream->multipart, p, stream->pkt_cur_len, ptr, (s->pload - (void *)p->buff + 5)) != POM_OK)
					return PROTO_ERR;
				
				// Process the multipart once we're done with the MPEG packet
				if (packet_multipart_process(stream->multipart, stack, stack_index + 1) == PROTO_ERR)
					return PROTO_ERR;

			}

			timer_dequeue(stream->t);

			// Multipart will be released automatically
			stream->multipart = NULL;
			stream->pkt_cur_len = 0;
			stream->pkt_tot_len = 0;

		}
		pos += ptr;

		while (1) {
			// Skip stuff bytes
			while (buff[pos] == 0xFF) {
				pos++;
				if (pos >= MPEG_TS_LEN)
					// Nothing left to process
					return PROTO_STOP;
			}
		
			char *force_no_copy = PTYPE_BOOL_GETVAL(param_force_no_copy);
			if ( (stream->type == proto_mpeg_stream_type_docsis && (pos > (MPEG_TS_LEN - 1) - offsetof(struct docsis_hdr, hcs)))
				|| (stream->type == proto_mpeg_stream_type_sect && (pos > (MPEG_TS_LEN - 1) - 3))) {
				// Cannot fetch the complete packet size, will do later
				stream->multipart = packet_multipart_alloc(next_proto, (*force_no_copy ? PACKET_FLAG_FORCE_NO_COPY : 0));
				if (!stream->multipart)
					return PROTO_ERR;
				stream->pkt_tot_len = 0;
				stream->pkt_cur_len = 0;
				break;
			}

			// Check for self contained packets
			unsigned int pkt_len = 0;
			if (stream->type == proto_mpeg_stream_type_docsis) {
				struct docsis_hdr *docsis_hdr = (void*)buff + pos;
				pkt_len = ntohs(docsis_hdr->len) + sizeof(struct docsis_hdr);
			} else if (stream->type == proto_mpeg_stream_type_sect) {
				pkt_len = (((*(buff + pos + 1) & 0xF) << 8) | *(buff + pos + 2)) + 3;
			} else {
				pomlog(POMLOG_ERR "Internal error : Unhandled stream type");
				return PROTO_ERR;
			}
			if (pkt_len + pos > MPEG_TS_LEN) {
				stream->multipart = packet_multipart_alloc(next_proto, (*force_no_copy ? PACKET_FLAG_FORCE_NO_COPY : 0));
				if (!stream->multipart)
					return PROTO_ERR;
				stream->pkt_tot_len = pkt_len;
				stream->pkt_cur_len = 0;

				break;
			}
				
			// Process the packet
			s_next->pload = buff + pos;
			s_next->plen = pkt_len;
			s_next->proto = next_proto->proto;
			int res = core_process_multi_packet(stack, stack_index + 1, p);
			if (res != PROTO_OK && res != PROTO_INVALID)
				return res;

			pos += pkt_len;

			if (pos >= MPEG_TS_LEN)
				// Nothing left to process
				return PROTO_STOP;

		}

	} else if (!stream->multipart) {
		return PROTO_INVALID;
	}


	// Some leftover, add to multipart
	
	if (packet_multipart_add_packet(stream->multipart, p, stream->pkt_cur_len, MPEG_TS_LEN - pos, pos) != POM_OK) {	
		packet_multipart_cleanup(stream->multipart);
		stream->multipart = NULL;
		stream->pkt_cur_len = 0;
		stream->pkt_tot_len = 0;
		return PROTO_ERR;
	}

	stream->pkt_cur_len += MPEG_TS_LEN - pos;
	if (stream->pkt_tot_len && stream->pkt_cur_len >= stream->pkt_tot_len) {
		timer_dequeue(stream->t);
		// Process the multipart
		if (packet_multipart_process(stream->multipart, stack, stack_index + 1) == PROTO_ERR)
			return PROTO_ERR;

		stream->multipart = NULL;
		stream->pkt_cur_len = 0;
		stream->pkt_tot_len = 0;
	}

	if (stream->multipart) {
		uint16_t *stream_timeout = PTYPE_UINT16_GETVAL(param_mpeg_ts_stream_timeout);
		timer_queue(stream->t, *stream_timeout);
	}

	// No need to process further, we take care of that
	return PROTO_STOP;

}


int proto_mpeg_ts_stream_cleanup(void *priv) {

	struct proto_mpeg_ts_stream *stream = priv;
	if (stream->multipart)
		packet_multipart_cleanup(stream->multipart);
	if (stream->stream)
		packet_stream_cleanup(stream->stream);

	timer_cleanup(stream->t);
	
	memset(stream, 0, sizeof(struct proto_mpeg_ts_stream));

	return POM_OK;
}

int proto_mpeg_ts_conntrack_cleanup(struct conntrack_entry *ce) {

	struct proto_mpeg_ts_conntrack_priv *priv = ce->priv;
	int i;
	for (i = 0; i < priv->streams_array_size; i++){ 
		if (priv->streams[i].multipart) 
			packet_multipart_cleanup(priv->streams[i].multipart);
		if (priv->streams[i].stream)
			packet_stream_cleanup(priv->streams[i].stream);
		timer_cleanup(priv->streams[i].t);
	}
	if (priv->streams)
		free(priv->streams);

	free(priv);

	return POM_OK;
}

int proto_mpeg_ts_cleanup() {


	int res = POM_OK;

	res += ptype_cleanup(param_force_no_copy);
	res += ptype_cleanup(param_mpeg_ts_stream_timeout);

	if (proto_docsis)
		res += proto_remove_dependency(proto_docsis);
	proto_docsis = NULL;
	
	if (proto_mpeg_sect)
		res += proto_remove_dependency(proto_mpeg_sect);
	proto_mpeg_sect = NULL;

	return res;
}