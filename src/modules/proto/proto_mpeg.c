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

#include "proto_mpeg.h"

#include <string.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <docsis.h>
#include <errno.h>


static struct proto_dependency *proto_docsis = NULL;

// ptype for fields value template
static struct ptype *ptype_uint16 = NULL;

// params
static struct ptype *param_force_no_copy = NULL, *param_mpeg_ts_stream_timeout = NULL;

struct mod_reg_info* proto_mpeg_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_mpeg_mod_register;
	reg_info.unregister_func = proto_mpeg_mod_unregister;

	return &reg_info;
}


static int proto_mpeg_mod_register(struct mod_reg *mod) {

	ptype_uint16 = ptype_alloc("uint16");
	if (!ptype_uint16)
		return POM_ERR;
	
	ptype_uint16->flags |= PTYPE_UINT16_PRINT_HEX;

	static struct proto_pkt_field fields[PROTO_MPEG_TS_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_MPEG_TS_FIELD_NUM + 1));
	fields[0].name = "pid";
	fields[0].value_template = ptype_uint16;
	fields[0].description = "PID";

	static struct proto_reg_info proto_mpeg_ts;
	memset(&proto_mpeg_ts, 0, sizeof(struct proto_reg_info));
	proto_mpeg_ts.name = "mpeg_ts";
	proto_mpeg_ts.api_ver = PROTO_API_VER;
	proto_mpeg_ts.mod = mod;
	proto_mpeg_ts.pkt_fields = fields;

	proto_mpeg_ts.ct_info.default_table_size = 256;
	proto_mpeg_ts.ct_info.fwd_pkt_field_id = proto_mpeg_ts_field_pid;
	proto_mpeg_ts.ct_info.cleanup_handler = proto_mpeg_ts_conntrack_cleanup;

	proto_mpeg_ts.init = proto_mpeg_ts_init;
	proto_mpeg_ts.process = proto_mpeg_ts_process;
	proto_mpeg_ts.cleanup = proto_mpeg_ts_cleanup;

	if (proto_register(&proto_mpeg_ts) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_mpeg_ts_init(struct registry_instance *i) {

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

	if (!proto_docsis) {
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

static int proto_mpeg_ts_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	unsigned char *buff = s->pload;

	uint16_t pid = ((buff[1] & 0x1F) << 8) | buff[2];

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_mpeg_ts_field_pid], pid);

	int hdr_len = 4;

	if (buff[1] & 0x40) { // Check PUSI
		if (buff[4] > 183)
			return PROTO_INVALID;
		hdr_len = 5; // Header is 5 bytes long, including the payload unit start pointer
	}

	// For now only process multipart on DOCSIS PID
	switch (pid) {
		case MPEG_TS_DOCSIS_PID:
			s_next->proto = proto_docsis->proto;
			break;

		default:
			s_next->pload = s->pload + hdr_len;
			s_next->plen = s->plen - hdr_len;
			s_next->proto = NULL;
			return PROTO_OK;
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

		stream->t = timer_alloc(stream, proto_mpeg_ts_stream_cleanup);
		if (!stream->t) {
			pom_mutex_unlock(&s->ce->lock);
			return PROTO_ERR;
		}
		stream->ce = s->ce;
		stream->last_seq = (buff[3] - 1) & 0xF;

	}

	if (!stream->stream) {
		char *force_no_copy; PTYPE_BOOL_GETVAL(param_force_no_copy, force_no_copy);
		stream->stream = packet_stream_alloc(p->id * MPEG_TS_LEN, 512 * MPEG_TS_LEN, (*force_no_copy ? PACKET_FLAG_FORCE_NO_COPY : 0));
		if (!stream->stream) {
			pom_mutex_unlock(&s->ce->lock);
			return PROTO_ERR;
		}
	}

	pom_mutex_unlock(&s->ce->lock);
	
	// Add the packet to the stream
	if (packet_stream_add_packet(stream->stream, p, s, p->id * MPEG_TS_LEN) != POM_OK) {
		return PROTO_ERR;
	}

	struct packet_stream_pkt *stream_pkt = NULL;
	while ((stream_pkt = packet_stream_get_next(stream->stream, s))) {
		struct packet_multipart *multipart = NULL;
		int res = proto_mpeg_ts_process_docsis(stream, stream_pkt->pkt, stack, stack_index, &multipart);
		if (packet_stream_release_packet(stream->stream, stream_pkt) != POM_OK)
			return PROTO_ERR;

		if (res == PROTO_ERR)
			return PROTO_ERR;

		if (multipart) {
			res = packet_multipart_process(multipart, stack, stack_index + 1);
			if (res == PROTO_ERR)
				return PROTO_ERR;
		}
	}

	return PROTO_STOP;
}


static int proto_mpeg_ts_process_docsis(struct proto_mpeg_ts_stream *stream, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index, struct packet_multipart **multipart) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	unsigned char *buff = s->pload;

	*multipart = NULL;

	int pusi = buff[1] & 0x40;

	unsigned int missed = 0;
	stream->last_seq = (stream->last_seq + 1) & 0xF;
	while (stream->last_seq != (buff[3] & 0xF)) {
		stream->last_seq = (stream->last_seq + 1) & 0xF;
		missed++;

		// Add missing payload
	}
	if (missed)
		pomlog(POMLOG_DEBUG "Missed %u MPEG packet(s) on input %u", missed, stream->input_id);

	if (stream->multipart) {
		timer_dequeue(stream->t);

		if (!stream->pkt_tot_len) {
			// Last packet was too short to know the size
			if (stream->multipart->head->len >= sizeof(struct docsis_hdr)) {
				pomlog(POMLOG_DEBUG "MPEG paket with invalid length : %u", stream->multipart->head->len);
				return PROTO_INVALID;
			}

			unsigned char tmp_buff[sizeof(struct docsis_hdr)];
			memcpy(tmp_buff, stream->multipart->head->pkt->buff + stream->multipart->head->pkt_buff_offset, stream->multipart->head->len);
			memcpy(tmp_buff + stream->multipart->head->len, buff + (pusi ? 5 : 4), sizeof(struct docsis_hdr) - stream->multipart->head->len);

			struct docsis_hdr *tmp_hdr = (struct docsis_hdr*)tmp_buff;
			stream->pkt_tot_len = ntohs(tmp_hdr->len) + sizeof(struct docsis_hdr);
		}

	}

	unsigned int pos = 4;
	if (pusi) {
		pos++;

		unsigned char ptr = buff[4];

		
		if (stream->multipart) {
			
			if (ptr != stream->pkt_tot_len - stream->pkt_cur_len) {
				pomlog(POMLOG_DEBUG "Invalid tail length for DOCSIS packet : expected %u, got %hhu", stream->pkt_tot_len - stream->pkt_cur_len, ptr);
				packet_multipart_cleanup(stream->multipart);
			} else {

				// Add the end of the previous packet
				if (packet_multipart_add_packet(stream->multipart, p, stream->pkt_cur_len, ptr, (s->pload - (void *)p->buff + 5)) != POM_OK)
					return PROTO_ERR;
				
				// Process the multipart once we're done with the MPEG packet
				*multipart = stream->multipart;

			}

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
		
			char *force_no_copy; PTYPE_BOOL_GETVAL(param_force_no_copy, force_no_copy);
			if (pos > (MPEG_TS_LEN - 1) - offsetof(struct docsis_hdr, hcs)) {
				// Cannot fetch the complete packet size, will do later
				stream->multipart = packet_multipart_alloc(proto_docsis, (*force_no_copy ? PACKET_FLAG_FORCE_NO_COPY : 0));
				if (!stream->multipart)
					return PROTO_ERR;
				stream->pkt_tot_len = 0;
				stream->pkt_cur_len = 0;
				break;
			}

			// Check for self contained packets
			struct docsis_hdr *docsis_hdr = (void*)buff + pos;
			unsigned int docsis_len = ntohs(docsis_hdr->len) + sizeof(struct docsis_hdr);
			if (docsis_len + pos > MPEG_TS_LEN) {
				stream->multipart = packet_multipart_alloc(proto_docsis, (*force_no_copy ? PACKET_FLAG_FORCE_NO_COPY : 0));
				if (!stream->multipart)
					return PROTO_ERR;
				stream->pkt_tot_len = docsis_len;
				stream->pkt_cur_len = 0;

				break;
			}
				
			// Process the packet
			s_next->pload = buff + pos;
			s_next->plen = docsis_len;
			s_next->proto = proto_docsis->proto;
			int res = core_process_multi_packet(stack, stack_index + 1, p);
			if (res != PROTO_OK && res != PROTO_INVALID)
				return res;

			pos += docsis_len;

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
		if (*multipart) {
			pomlog(POMLOG_ERR "A multipart is already ready for processing ! This shouldn't happen !");
			return PROTO_ERR;
		}

		// Process the multipart
		*multipart = stream->multipart;

		stream->multipart = NULL;
		stream->pkt_cur_len = 0;
		stream->pkt_tot_len = 0;
	}

	if (stream->multipart) {
		uint16_t *stream_timeout; PTYPE_UINT16_GETVAL(param_mpeg_ts_stream_timeout, stream_timeout);
		timer_queue(stream->t, *stream_timeout);
	}

	// No need to process further, we take care of that
	return PROTO_STOP;

}


static int proto_mpeg_ts_stream_cleanup(void *priv) {

	struct proto_mpeg_ts_stream *stream = priv;
	if (stream->multipart)
		packet_multipart_cleanup(stream->multipart);
	if (stream->stream)
		packet_stream_cleanup(stream->stream);

	timer_cleanup(stream->t);
	
	memset(stream, 0, sizeof(struct proto_mpeg_ts_stream));

	return POM_OK;
}

static int proto_mpeg_ts_conntrack_cleanup(struct conntrack_entry *ce) {

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

static int proto_mpeg_ts_cleanup() {


	int res = POM_OK;

	res += ptype_cleanup(param_force_no_copy);
	res += ptype_cleanup(param_mpeg_ts_stream_timeout);

	res += proto_remove_dependency(proto_docsis);

	return res;
}

static int proto_mpeg_mod_unregister() {

	int res = proto_unregister("mpeg");

	ptype_cleanup(ptype_uint16);
	ptype_uint16 = NULL;

	return res;
}
