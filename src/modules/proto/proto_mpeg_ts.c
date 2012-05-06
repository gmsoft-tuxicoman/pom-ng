/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2012 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/conntrack.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint16.h>

#include "proto_mpeg_ts.h"

#include <string.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <docsis.h>
#include <errno.h>

int proto_mpeg_ts_init(struct proto *proto, struct registry_instance *i) {

	struct proto_mpeg_ts_priv *priv = malloc(sizeof(struct proto_mpeg_ts_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_mpeg_ts_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_mpeg_ts_priv));

	proto->priv = priv;

	struct registry_param *p = NULL;

	priv->param_mpeg_ts_stream_timeout = ptype_alloc_unit("uint16", "seconds");
	if (!priv->param_mpeg_ts_stream_timeout)
		goto err;

	p = registry_new_param("stream_timeout", "60", priv->param_mpeg_ts_stream_timeout, "Timeout for each MPEG PID", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = NULL;

	priv->proto_docsis = proto_add_dependency("docsis");
	priv->proto_mpeg_sect = proto_add_dependency("mpeg_sect");

	if (!priv->proto_docsis || !priv->proto_mpeg_sect)
		goto err;


	return POM_OK;

err:

	if (p)
		registry_cleanup_param(p);

	proto_mpeg_ts_cleanup(proto);
	
	return POM_ERR;

}

int proto_mpeg_ts_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	// WARNING THIS CODE ASSUMES THAT PACKETS ARRIVE IN ORDER
	// This should be achieved by packet threads affinity on an input level
	// If MPEG packets are not the link layer, then care should be taken to 
	// send them in the right order. For example by reoderding RTP or TCP packets containing them

	struct proto_mpeg_ts_priv *ppriv = proto->priv;
	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	unsigned char *buff = s->pload;

	uint16_t pid = ((buff[1] & 0x1F) << 8) | buff[2];
	unsigned char pusi = buff[1] & 0x40;

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_mpeg_ts_field_pid], pid);

	int hdr_len = 4;

	// Filter out NULL packets
	if (pid == MPEG_TS_NULL_PID) {
		s_next->proto = NULL;
		s_next->pload = s->pload + hdr_len;
		s_next->plen = s->plen - hdr_len;
		return PROTO_OK;
	}

	// FIXME Check the adaptation layer


	// Try to find out what type or payload we are dealing with

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

	// Find the MPEG stream from the right input
	
	int i;
	for (i = 0; i < priv->streams_array_size && priv->streams[i].input != p->input; i++);

	struct proto_mpeg_ts_stream *stream = NULL;
	if (i >= priv->streams_array_size) {
		// New stream
		
		// We need to have a PUSI to analyze and start recomposing the content
		if (!pusi) {
			pom_mutex_unlock(&s->ce->lock);
			return PROTO_OK;
		}

		// Create the new stream
		struct proto_mpeg_ts_stream *new_streams = realloc(priv->streams, sizeof(struct proto_mpeg_ts_stream) * (priv->streams_array_size + 1));
		if (!new_streams) {
			pom_mutex_unlock(&s->ce->lock);
			pom_oom(sizeof(struct proto_mpeg_ts_stream) * (priv->streams_array_size + 1));
			return PROTO_ERR;
		}
		priv->streams = new_streams;
		memset(&priv->streams[priv->streams_array_size], 0, sizeof(struct proto_mpeg_ts_stream));
		stream = &priv->streams[priv->streams_array_size];
		priv->streams_array_size++;

		stream->input = p->input;
		stream->ppriv = ppriv;

		stream->t = timer_alloc(stream, proto_mpeg_ts_stream_cleanup);
		if (!stream->t) {
			pom_mutex_unlock(&s->ce->lock);
			return PROTO_ERR;
		}
		stream->ce = s->ce;
		stream->last_seq = (buff[3] - 1) & 0xF;

		// Remove the conntrack timer if any
		conntrack_delayed_cleanup(s->ce, 0);
		
		// Identify the stream,
		if (pid == MPEG_TS_DOCSIS_PID) {
			stream->type = proto_mpeg_stream_type_docsis;
		} else if (buff[4] == 0x0 && buff[5] == 0x0 && buff[6] == 0x1) {
			// PES packet. They have no pointer if PUSI is 1
			// Currently not handled
			stream->type = proto_mpeg_stream_type_pes;
		} else {
			// The last option is a SECT packet
			stream->type = proto_mpeg_stream_type_sect;
		}


	} else {
		stream = &priv->streams[i];
	}

	pom_mutex_unlock(&s->ce->lock);

	// Filter out PES packets
	if (stream->type == proto_mpeg_stream_type_pes) {
		s_next->pload = s->pload + hdr_len;
		s_next->plen = s->plen - hdr_len;
		s_next->proto = NULL;
		return POM_OK;
	}

	// Check the validity of the pointer
	if (pusi) {
		if (buff[4] > 183)
			return PROTO_INVALID;
	}


	// Check for missing packets
	unsigned int missed = 0;
	stream->last_seq = (stream->last_seq + 1) & 0xF;
	while (stream->last_seq != (buff[3] & 0xF)) {
		stream->last_seq = (stream->last_seq + 1) & 0xF;
		missed++;

		// Add missing payload to length
		// TODO fill the gap 

	}
	if (missed)
		pomlog(POMLOG_DEBUG "Missed %u MPEG packet(s) on input %s", missed, stream->input->name);


	// Add the payload to the multipart if any
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
						stream->pkt_tot_len = ((((unsigned char*)stream->multipart->head->pkt->buff + stream->multipart->head->pkt_buff_offset)[1] & 0xF) << 8) | pload_buff[0];
						break;
				}
				stream->pkt_tot_len += 3; // add the 3 headers bytes
				
			}
		
		}

	}

	// Get the right payload protocol
	struct proto_dependency *next_proto;
	switch (stream->type) {
		case proto_mpeg_stream_type_docsis:
			next_proto = ppriv->proto_docsis;
		case proto_mpeg_stream_type_sect:
			next_proto = ppriv->proto_mpeg_sect;
			break;
		default:
			next_proto = NULL;
	}

	// We have the begining of a new packets, there are some stuff to do ...
	unsigned int pos = 4;
	if (pusi) {
		pos++;

		unsigned char ptr = buff[4];

	
		// If we already have some parts of a packet, process it
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
		
			if ( (stream->type == proto_mpeg_stream_type_docsis && (pos > (MPEG_TS_LEN - offsetof(struct docsis_hdr, hcs))))
				|| (stream->type == proto_mpeg_stream_type_sect && (pos > (MPEG_TS_LEN - 3)))) {
				// Cannot fetch the complete packet size, will do later
				stream->multipart = packet_multipart_alloc(next_proto, 0);
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
				stream->multipart = packet_multipart_alloc(next_proto, 0);
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
			if (res == PROTO_ERR)
				return PROTO_ERR;

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
		uint16_t *stream_timeout = PTYPE_UINT16_GETVAL(stream->ppriv->param_mpeg_ts_stream_timeout);
		timer_queue(stream->t, *stream_timeout);
	}

	// No need to process further, we take care of that
	return PROTO_STOP;

}


int proto_mpeg_ts_stream_cleanup(void *priv) {


	struct proto_mpeg_ts_stream *stream = priv;
	
	pom_mutex_lock(&stream->ce->lock);

	// Cleanup the stream stuff
	if (stream->multipart)
		packet_multipart_cleanup(stream->multipart);
	if (stream->stream)
		packet_stream_cleanup(stream->stream);

	timer_cleanup(stream->t);
	
	// Remove it from the table
	struct proto_mpeg_ts_conntrack_priv *cpriv = stream->ce->priv;

	// Find out where it is in the table
	int i;
	for (i = 0; i < cpriv->streams_array_size && cpriv->streams[i].input != stream->input; i++);

	if (i >= cpriv->streams_array_size) {
		pomlog(POMLOG_ERR "Internal error, stream not found in the conntrack priv while cleaning it up");
		pom_mutex_unlock(&stream->ce->lock);
		return POM_ERR;
	}

	if (cpriv->streams_array_size == 1) {
		// Cleanup the conntrack in 10 seconds if no more packets
		conntrack_delayed_cleanup(stream->ce, 10);
	} else {
		size_t len = (cpriv->streams_array_size - i - 1) * sizeof(struct proto_mpeg_ts_stream);
		if (len)
			memmove(&cpriv->streams[i], &cpriv->streams[i+1], len);
	}

	cpriv->streams_array_size--;
	struct proto_mpeg_ts_stream *new_streams = realloc(cpriv->streams, sizeof(struct proto_mpeg_ts_stream) * cpriv->streams_array_size);

	if (cpriv->streams_array_size && !new_streams) {
		// Not really an issue as we lowered the size anyway
		pom_oom(sizeof(struct proto_mpeg_ts_stream) * cpriv->streams_array_size);
	} else {
		cpriv->streams = new_streams;
	}
	
	pom_mutex_unlock(&stream->ce->lock);

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

int proto_mpeg_ts_cleanup(struct proto *proto) {


	if (proto->priv) {
		struct proto_mpeg_ts_priv *priv = proto->priv;

		if (priv->param_mpeg_ts_stream_timeout)
			ptype_cleanup(priv->param_mpeg_ts_stream_timeout);


		if (priv->proto_docsis)
			proto_remove_dependency(priv->proto_docsis);
		
		if (priv->proto_mpeg_sect)
			proto_remove_dependency(priv->proto_mpeg_sect);

		free(priv);
	}

	return POM_OK;
}
