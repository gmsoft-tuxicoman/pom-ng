/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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



#include "common.h"
#include "proto.h"
#include "packet.h"
#include "main.h"
#include "core.h"
#include "input_client.h"

#include <pom-ng/ptype.h>

static struct packet *packet_head, *packet_unused_head;
static pthread_mutex_t packet_list_mutex = PTHREAD_MUTEX_INITIALIZER;

struct packet *packet_pool_get() {

	pom_mutex_lock(&packet_list_mutex);

	struct packet *tmp = packet_unused_head;

	if (!tmp) {
		// Alloc a new packet
		tmp = malloc(sizeof(struct packet));
		if (!tmp) {
			pom_mutex_unlock(&packet_list_mutex);
			pom_oom(sizeof(struct packet));
			return NULL;
		}
	} else {
		// Fetch it from the unused pool
		packet_unused_head = tmp->next;
		if (packet_unused_head)
			packet_unused_head->prev = NULL;
	}

	memset(tmp, 0, sizeof(struct packet));

	// Add the packet to the used pool
	tmp->next = packet_head;
	if (tmp->next)
		tmp->next->prev = tmp;
	
	packet_head = tmp;

	tmp->refcount = 1;
	
	pom_mutex_unlock(&packet_list_mutex);

	return tmp;
}

struct packet *packet_clone(struct packet *src, unsigned int flags) {

	struct packet *dst = NULL;

	if (!(flags & PACKET_FLAG_FORCE_NO_COPY) && src->input_pkt) {
		// It uses the input buffer, we cannot hold this ressource
		dst = packet_pool_get();
		if (!dst)
			return NULL;

		memcpy(&dst->ts, &src->ts, sizeof(struct timeval));
		dst->len = src->len;
		dst->buff = malloc(src->len);
		if (!dst->buff) {
			pom_oom(dst->len);
			packet_pool_release(dst);
			return NULL;
		}

		memcpy(dst->buff, src->buff, src->len);

		dst->datalink = src->datalink;
		dst->input = src->input;
		dst->id = src->id;

		// Multipart and stream are not copied
		
		return dst;
	}
	pom_mutex_lock(&packet_list_mutex); // Use this lock to prevent refcount race
	src->refcount++;
	pom_mutex_unlock(&packet_list_mutex);
	return src;
}

int packet_pool_release(struct packet *p) {

	pom_mutex_lock(&packet_list_mutex);
	p->refcount--;
	if (p->refcount) {
		pom_mutex_unlock(&packet_list_mutex);
		return POM_OK;
	}

	// Remove the packet from the used list
	if (p->next)
		p->next->prev = p->prev;

	if (p->prev)
		p->prev->next = p->next;
	else
		packet_head = p->next;

	struct input_client_entry *i = p->input;
	struct input_packet *input_pkt = p->input_pkt;
	struct packet_multipart *multipart = p->multipart;
	unsigned char *buff = p->buff;

	memset(p, 0, sizeof(struct packet));
	
	// Add it back to the unused list
	
	p->next = packet_unused_head;
	if (p->next)
		p->next->prev = p;
	packet_unused_head = p;

	pom_mutex_unlock(&packet_list_mutex);

	int res = POM_OK;

	if (input_pkt) {
		if (input_client_release_packet(i, input_pkt) != POM_OK) {
			res = POM_ERR;
			pomlog(POMLOG_ERR "Error while releasing packet from the buffer");
		}
	} else {
		// Packet doesn't come from an input -> free the buffer
		free(buff);
	}

	if (multipart) {  // Cleanup multipart if any
		if (packet_multipart_cleanup(multipart) != POM_OK) {
			res = POM_ERR;
			pomlog(POMLOG_ERR "Error while releasing the multipart");
		}
	}

	return res;
}

int packet_pool_cleanup() {

	pom_mutex_lock(&packet_list_mutex);

	struct packet *tmp = packet_head;
	while (tmp) {
		pomlog(POMLOG_WARN "A packet was not released, refcount : %u", tmp->refcount);
		packet_head = tmp->next;

		free(tmp);
		tmp = packet_head;
	}

	tmp = packet_unused_head;

	while (tmp) {
		packet_unused_head = tmp->next;
		free(tmp);
		tmp = packet_unused_head;
	}

	pom_mutex_unlock(&packet_list_mutex);

	return POM_OK;
}

int packet_info_pool_init(struct packet_info_pool *pool) {

	if (pthread_mutex_init(&pool->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing the pkt_info_pool lock : ", pom_strerror(errno));
		return POM_ERR;
	}

	return POM_OK;
}

struct packet_info *packet_info_pool_get(struct proto_reg *p) {

	struct packet_info *info = NULL;

	pom_mutex_lock(&p->pkt_info_pool.lock);

	if (!p->pkt_info_pool.unused) {
		// Allocate new packet_info
		info = malloc(sizeof(struct packet_info));
		if (!info) {
			pom_mutex_unlock(&p->pkt_info_pool.lock);
			pom_oom(sizeof(struct packet_info));
			return NULL;
		}
		memset(info, 0, sizeof(struct packet_info));
		struct proto_pkt_field *fields = p->info->pkt_fields;
		int i;
		for (i = 0; fields[i].name; i++);

		info->fields_value = malloc(sizeof(struct ptype*) * (i + 1));
		memset(info->fields_value, 0, sizeof(struct ptype*) * (i + 1));

		for (; i--; ){
			info->fields_value[i] = ptype_alloc_from(fields[i].value_template);
			if (!info->fields_value[i]) {
				i++;
				for (; fields[i].name; i++)
					ptype_cleanup(info->fields_value[i]);
				free(info);
				pom_mutex_unlock(&p->pkt_info_pool.lock);
				return NULL;
			}
		}

	} else {
		// Dequeue the packet_info from the unused pool
		info = p->pkt_info_pool.unused;
		p->pkt_info_pool.unused = info->pool_next;
		if (p->pkt_info_pool.unused)
			p->pkt_info_pool.unused->pool_prev = NULL;
	}


	// Queue the packet_info in the used pool
	info->pool_prev = NULL;
	info->pool_next = p->pkt_info_pool.used;
	if (info->pool_next)
		info->pool_next->pool_prev = info;
	p->pkt_info_pool.used = info;

	pom_mutex_unlock(&p->pkt_info_pool.lock);
	return info;
}


int packet_info_pool_release(struct packet_info_pool *pool, struct packet_info *info) {

	if (!pool || !info)
		return POM_ERR;

	pom_mutex_lock(&pool->lock);

	// Dequeue from used and queue to unused

	if (info->pool_prev)
		info->pool_prev->pool_next = info->pool_next;
	else
		pool->used = info->pool_next;

	if (info->pool_next)
		info->pool_next->pool_prev = info->pool_prev;

	
	info->pool_next = pool->unused;
	if (info->pool_next)
		info->pool_next->pool_prev = info;
	pool->unused = info;

	pom_mutex_unlock(&pool->lock);
	return POM_OK;
}


int packet_info_pool_cleanup(struct packet_info_pool *pool) {

	pthread_mutex_destroy(&pool->lock);

	struct packet_info *tmp = NULL;
	while (pool->used) {	
		printf("Unreleased packet info !\n");
		tmp = pool->used;
		pool->used = tmp->pool_next;

		int i;
		for (i = 0; tmp->fields_value[i]; i++)
			ptype_cleanup(tmp->fields_value[i]);

		free(tmp->fields_value);

		free(tmp);
	}

	while (pool->unused) {
		tmp = pool->unused;
		pool->unused = tmp->pool_next;

		int i;
		for (i = 0; tmp->fields_value[i]; i++)
			ptype_cleanup(tmp->fields_value[i]);

		free(tmp->fields_value);

		free(tmp);
	}


	return POM_OK;
}


struct packet_multipart *packet_multipart_alloc(struct proto_dependency *proto_dep, unsigned int flags) {

	struct packet_multipart *res = malloc(sizeof(struct packet_multipart));
	if (!res) {
		pom_oom(sizeof(struct packet_multipart));
		return NULL;
	}
	memset(res, 0, sizeof(struct packet_multipart));

	proto_dependency_refcount_inc(proto_dep);
	res->proto = proto_dep;
	if (!res->proto) {
		free(res);
		res = NULL;
	}

	res->flags = flags;

	return res;
}

int packet_multipart_cleanup(struct packet_multipart *m) {

	if (!m)
		return POM_ERR;

	struct packet_multipart_pkt *tmp;

	while (m->head) {
		tmp = m->head;
		m->head = tmp->next;

		packet_pool_release(tmp->pkt);
		free(tmp);

	}

	proto_remove_dependency(m->proto);

	free(m);

	return POM_OK;

}


int packet_multipart_add_packet(struct packet_multipart *multipart, struct packet *pkt, size_t offset, size_t len, size_t pkt_buff_offset) {

	struct packet_multipart_pkt *tmp = multipart->tail;

	// Check where to add the packet
	while (tmp) {

		if (tmp->offset + tmp->len <= offset)
			break; // Packet is after is one

		if (tmp->offset == offset) {
			if (tmp->len != len)
				pomlog(POMLOG_WARN "Size missmatch for packet already in the buffer");
			return POM_OK;
		}

		if (tmp->offset > offset) {
			pomlog(POMLOG_WARN "Offset missmatch for packet already in the buffer");
			return POM_OK;
		}
		
		tmp = tmp->next;

	}

	struct packet_multipart_pkt *res = malloc(sizeof(struct packet_multipart_pkt));
	if (!res) {
		pom_oom(sizeof(struct packet_multipart_pkt));
		return POM_ERR;
	}
	memset(res, 0, sizeof(struct packet_multipart_pkt));

	res->offset = offset;
	res->pkt_buff_offset = pkt_buff_offset;
	res->len = len;


	// Copy the packet

	
	res->pkt = packet_clone(pkt, multipart->flags);
	if (!res->pkt) {
		free(res);
		return POM_ERR;
	}

	multipart->cur += len;

	if (tmp) {
		// Packet is after this one, add it
	
		res->prev = tmp;
		res->next = tmp->next;

		tmp->next = res;

		if (res->next) {
			res->next->prev = res;

			if ((res->next->offset == res->offset + res->len) &&
				(res->prev->offset + res->prev->len == res->offset))
				// A gap was filled
				multipart->gaps--;
			else if ((res->next->offset > res->offset + res->len) &&
				(res->prev->offset + res->prev->len < res->offset))
				// A gap was created
				multipart->gaps++;

		} else {
			multipart->tail = res;
		}


		return POM_OK;
	} else {
		// Add it at the head
		res->next = multipart->head;
		if (res->next)
			res->next->prev = res;
		else
			multipart->tail = res;
		multipart->head = res;

		if (res->offset) {
			// There is a gap at the begining
			multipart->gaps++;
		} else if (res->next && res->len == res->next->offset) {
			// Gap filled
			multipart->gaps--;
		}
	}

	return POM_OK;
}

int packet_multipart_process(struct packet_multipart *multipart, struct proto_process_stack *stack, unsigned int stack_index) {

	struct packet *p = packet_pool_get();
	if (!p) {
		packet_multipart_cleanup(multipart);
		return PROTO_ERR;
	}

	p->buff = malloc(multipart->cur);
	if (!p->buff) {
		packet_pool_release(p);
		packet_multipart_cleanup(multipart);
		pom_oom(multipart->cur);
		return PROTO_ERR;
	}

	struct packet_multipart_pkt *tmp = multipart->head;
	for (; tmp; tmp = tmp->next) {
		memcpy(p->buff + tmp->offset, tmp->pkt->buff + tmp->pkt_buff_offset, tmp->len);
	}

	memcpy(&p->ts, &multipart->tail->pkt->ts, sizeof(struct timeval));
	
	p->multipart = multipart;
	p->len = multipart->cur;
	p->datalink = multipart->proto->proto;
	stack[stack_index].pload = p->buff;
	stack[stack_index].plen = p->len;
	stack[stack_index].proto = p->datalink;

	int res = core_process_multi_packet(stack, stack_index, p);
	packet_pool_release(p);

	return res;
}


struct packet_stream* packet_stream_alloc(uint32_t start_seq, uint32_t max_buff_size, unsigned int flags) {
	
	struct packet_stream *res = malloc(sizeof(struct packet_stream));
	if (!res) {
		pom_oom(sizeof(struct packet_stream));
		return NULL;
	}

	memset(res, 0, sizeof(struct packet_stream));
	res->cur_seq = start_seq;
	res->max_buff_size = max_buff_size;

	if (pthread_mutex_init(&res->list_lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing packet_stream list mutex : %s", pom_strerror(errno));
		return NULL;
	}

	if (pthread_mutex_init(&res->processing_lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing packet_stream processing mutex : %s", pom_strerror(errno));
		return NULL;
	}

	res->flags = flags;

	return res;
}

int packet_stream_cleanup(struct packet_stream *stream) {

	struct packet_stream_pkt *p = stream->head;
	while (p) {
		stream->head = p->next;
		packet_pool_release(p->pkt);
		packet_info_pool_release(&p->proto->pkt_info_pool, p->pkt_info);
		free(p);
		p = stream->head;
	}

	pthread_mutex_destroy(&stream->list_lock);
	pthread_mutex_destroy(&stream->processing_lock);

	free(stream);

	return POM_OK;
}


int packet_stream_add_packet(struct packet_stream *stream, struct packet *pkt, struct proto_process_stack *cur_stack, uint32_t seq) {

	if (!stream || !pkt || !cur_stack)
		return POM_ERR;

	int res = 0;

	pom_mutex_lock(&stream->list_lock);
	if (stream->cur_seq != seq) {

		if ((stream->cur_seq < seq && seq - stream->cur_seq < PACKET_HALF_SEQ)
			|| (stream->cur_seq > seq && stream->cur_seq - seq > PACKET_HALF_SEQ))
			// cur_seq is before the packet
			res = -1;
		else if ((stream->cur_seq > (seq + cur_stack->plen) && stream->cur_seq - (seq + cur_stack->plen) < PACKET_HALF_SEQ)
			|| (stream->cur_seq < (seq + cur_stack->plen) && (seq + cur_stack->plen) - stream->cur_seq > PACKET_HALF_SEQ)) {
			// cur_seq is after the packet
			pom_mutex_unlock(&stream->list_lock);
			return POM_OK;
		}

		// cur_seq is inside the packet
	}


	struct packet_stream_pkt *p = malloc(sizeof(struct packet_stream_pkt));
	if (!p) {
		pom_mutex_unlock(&stream->list_lock);
		pom_oom(sizeof(struct packet_stream_pkt));
		return POM_ERR;
	}
	memset(p, 0 , sizeof(struct packet_stream_pkt));
	p->seq = seq;
	p->len = cur_stack->plen;
	p->pkt_info = cur_stack->pkt_info;
	p->pkt_buff_offset = cur_stack->pload - pkt->buff; 
	p->proto = cur_stack->proto;
	cur_stack->pload = NULL;
	cur_stack->plen = 0;
	cur_stack->proto = NULL;
	cur_stack->pkt_info = NULL;

	unsigned int pkt_flags = stream->flags;

	if (!stream->tail) {
		stream->head = p;
		stream->tail = p;
	} else { 

		struct packet_stream_pkt *tmp = stream->tail;
		while ( tmp && 
			((tmp->seq > seq && tmp->seq - seq < PACKET_HALF_SEQ)
			|| (tmp->seq < seq && seq - tmp->seq > PACKET_HALF_SEQ))) {

			tmp = tmp->prev;

		}

		if (!tmp) {
			// Packet goes at the begining of the list
			p->next = stream->head;
			if (p->next)
				p->next->prev = p;
			else
				stream->tail = p;
			stream->head = p;

		} else {
			// Insert the packet after the current one
			p->next = tmp->next;
			p->prev = tmp;

			if (p->next)
				p->next->prev = p;
			else
				stream->tail = p;

			tmp->next = p;

		}
	}

	if (!p->prev &&  (stream->cur_seq == p->seq || stream->cur_buff_size > stream->max_buff_size)) {
		// Packet will be dequeued immediately, don't copy it
		pkt_flags |= PACKET_FLAG_FORCE_NO_COPY;
	}

	p->pkt = packet_clone(pkt, pkt_flags);
	if (!p->pkt) {
		
		if (p->prev) {
			p->prev->next = p->next;
		} else {
			stream->head = p->next;
			if (stream->head)
				stream->head->prev = NULL;
		}

		if (p->next) {
			p->next->prev = p->prev;
		} else {
			stream->tail = p->prev;
			if (stream->tail)
				stream->tail->next = NULL;
		}

		free(p);
		pom_mutex_unlock(&stream->list_lock);
		return POM_ERR;
	}
	stream->cur_buff_size += p->len;
	pom_mutex_unlock(&stream->list_lock);
	return POM_OK;
}


struct packet_stream_pkt *packet_stream_get_next(struct packet_stream *stream, struct proto_process_stack *cur_stack) {

	if (!stream)
		return NULL;

	if (pthread_mutex_trylock(&stream->processing_lock)) {
		
		// Clear the stack make sure it's not processed
		packet_info_pool_release(&cur_stack->proto->pkt_info_pool, cur_stack->pkt_info);
		cur_stack->pkt_info = NULL;
		cur_stack->pload = NULL;
		cur_stack->proto = NULL;
		cur_stack->plen = 0;

		return NULL;

	}

	pom_mutex_lock(&stream->list_lock);

	// FIXME : Improve this to mangle useless parts of the packets
	if (!stream->head) {
		pom_mutex_unlock(&stream->processing_lock);
		pom_mutex_unlock(&stream->list_lock);
		return NULL;
	}

	// Check if first packet match
	if (stream->cur_seq != stream->head->seq && stream->cur_buff_size < stream->max_buff_size) {
		pom_mutex_unlock(&stream->processing_lock);
		pom_mutex_unlock(&stream->list_lock);
		return NULL;
	}

	struct packet_stream_pkt *res = stream->head;
	if (res->prev) {
		pomlog(POMLOG_WARN "Warning, dequeued packet wasn't the first !!!");
		res->prev->next = res->next;
	} else {
		stream->head = res->next;
		if (stream->head)
			stream->head->prev = NULL;
	}


	// Check if packet containes duplicate bytes
	while (res->next) {
		
		struct packet_stream_pkt *next = res->next;
		uint32_t next_seq = res->seq + res->len;

		// Check if we need to truncate this packet or not
		if ((next_seq <= next->seq && next->seq - next_seq < PACKET_HALF_SEQ)
			|| (next_seq > next->seq && next_seq - next->seq > PACKET_HALF_SEQ))
			// No overlap
			break;

		

		uint32_t next_next_seq = next->seq + next->len;
		if ((next_seq > next_next_seq && next_seq - next_next_seq < PACKET_HALF_SEQ)
			|| (next_seq < next_next_seq && next_next_seq - next_seq > PACKET_HALF_SEQ)) {

			// Next packet is completely duplicate, discard it
			res->next = next->next;
			if (res->next)
				res->next->prev = res;
			packet_pool_release(next->pkt);
			free(next);
		} else {
			uint32_t dupe;
			if (next_seq > next->seq)
				dupe = next_seq - next->seq;
			else
				dupe = next->seq - next_seq;

			if (dupe > next->len) {
				pomlog(POMLOG_ERR "Internal error while computing duplicate bytes");
				pom_mutex_unlock(&stream->list_lock);
				return NULL;
			}
			next->seq += dupe;
			next->pkt_buff_offset += dupe;
			next->len -= dupe;
			break;
			
		}
	}

	if (res->next) {
		res->next->prev = res->prev;

	} else {
		stream->tail = res->prev;
		if (stream->tail)
			stream->tail->next = NULL;
	}

	stream->cur_seq += res->len;
	stream->cur_buff_size -= res->len;	

	pom_mutex_unlock(&stream->list_lock);



	packet_info_pool_release(&cur_stack->proto->pkt_info_pool, cur_stack->pkt_info);

	cur_stack->pload = res->pkt->buff + res->pkt_buff_offset;
	cur_stack->plen = res->len;
	cur_stack->pkt_info = res->pkt_info;
	cur_stack->proto = res->proto;


	return res;
}


int packet_stream_release_packet(struct packet_stream *stream, struct packet_stream_pkt *pkt) {

	if (!stream || !pkt)
		return POM_ERR;

	if (!pthread_mutex_trylock(&stream->processing_lock)) {
		pomlog(POMLOG_ERR "packet_stream_release_packet() called without a call to packet_stream_get_next() before");
		pom_mutex_unlock(&stream->processing_lock);
		return POM_ERR;
	}

	pom_mutex_unlock(&stream->processing_lock);

	packet_pool_release(pkt->pkt);
	free(pkt);

	return POM_OK;

}


struct packet_stream_parser *packet_stream_parser_alloc(unsigned int max_line_size) {
	
	struct packet_stream_parser *res = malloc(sizeof(struct packet_stream_parser));
	if (!res) {
		pom_oom(sizeof(struct packet_stream_parser));
		return NULL;
	}

	memset(res, 0, sizeof(struct packet_stream_parser));

	res->max_line_size = max_line_size;

	return res;
}


int packet_stream_parser_add_payload(struct packet_stream_parser *sp, void *pload, unsigned int len) {

	if (sp->pload || sp->plen)
		pomlog(POMLOG_WARN "Warning, payload of last packet not entirely consumed !");

	sp->pload = pload;
	sp->plen = len;

	return POM_OK;
}


int packet_stream_parser_get_line(struct packet_stream_parser *sp, char **line, unsigned int *len) {

	if (!line || !len)
		return POM_ERR;

	// Find the next line return in the current payload
	
	char *pload = sp->pload;
	
	int str_len = sp->plen, tmp_len;
	
	char *lf = memchr(pload, '\n', sp->plen);
	if (lf) {
		tmp_len = lf - pload;
		str_len = tmp_len + 1;
		if (lf > pload && *(lf - 1) == '\r')
			tmp_len--;
	}

	if (sp->buffpos || !lf) {
		// If there is a buffer or line return is not found, we need to add to the buffer
		unsigned int new_len = sp->buffpos + tmp_len;
		if (sp->bufflen < new_len) {
			sp->buff = realloc(sp->buff, new_len);
			if (!sp->buff) {
				pom_oom(new_len + 1);
				return POM_ERR;
			}
			sp->bufflen = new_len + 1;
		}
		memcpy(sp->buff + sp->buffpos, sp->pload, tmp_len);
		sp->buffpos += tmp_len;

		if (sp->buffpos > sp->max_line_size) {
			// What to do ? discard it and sned new partial line ?
			// Send it as is and send a new line afterwards ?
			// I'll take option two
			pomlog(POMLOG_DEBUG "Line longer than max size : %u , max %u", sp->buffpos, sp->max_line_size);
		}
	}

	if (!lf) {
		// \n not found
		*line = NULL;
		*len = 0;
		sp->pload = NULL;
		sp->plen = 0;
		return POM_OK;
	}

	
	if (sp->buffpos) {
		pload = sp->buff;
		tmp_len = sp->buffpos;
		sp->buffpos = 0;
		return POM_OK;
	} else {
		sp->plen -= str_len;
		if (!sp->plen)
			sp->pload = NULL;
		else
			sp->pload += str_len;
	}

	// Trim the string
	while (*pload == ' ' && tmp_len) {
		pload++;
		tmp_len--;
	}
	while (pload[tmp_len] == ' ' && tmp_len)
		tmp_len--;

	*line = pload;
	*len = tmp_len;

	return POM_OK;
}



int packet_stream_parser_cleanup(struct packet_stream_parser *sp) {

	if (sp->buff)
		free(sp->buff);

	free(sp);

	return POM_OK;
}
