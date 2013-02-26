/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/ptype.h>

#if 0
#define debug_stream_parser(x ...) pomlog(POMLOG_DEBUG "stream_parser: " x)
#else
#define debug_stream_parser(x ...)
#endif

#if 0
#define debug_stream(x ...) pomlog(POMLOG_DEBUG "stream: " x)
#else
#define debug_stream(x ...)
#endif

#if 0
#define debug_info_pool(x ...) pomlog(POMLOG_DEBUG "info_pool: " x)
#else
#define debug_info_pool(x ...)
#endif

#if 0
#define debug_packet_pool(x ...) pomlog(POMLOG_DEBUG "packet_pool: " x)
#else
#define debug_packet_pool(x ...)
#endif

// Define to debug packet_info_pool allocation
#undef PACKET_INFO_POOL_ALLOC_DEBUG


// Packet pool stuff
static __thread struct packet *packet_pool_head = NULL;
static __thread struct packet *packet_pool_tail = NULL;
static struct packet *packet_pool_global_head = NULL;
static pthread_mutex_t packet_pool_lock = PTHREAD_MUTEX_INITIALIZER;


// Packet buffer pool stuff
#define PACKET_BUFFER_POOL_COUNT 9
static size_t packet_buffer_pool_size[PACKET_BUFFER_POOL_COUNT] = {
	80, // For small packets
	200, // Special one for MPEG packets which are 188 bytes long
	600, // Many packets are 576 bytes long
	1300, // Intermediate one
	1600, // For packets of size 1500 (and a bit more in case of vlan/wifi/etc)
	2048, // Big packets
	4096, // Even bigger packets
	9100, // Jumbo frames
	65535, // Very rare situations where captured packets are not downsized to MTU yet
};

static __thread struct packet_buffer *packet_buffer_pool_head[PACKET_BUFFER_POOL_COUNT] = { 0 };
static __thread struct packet_buffer *packet_buffer_pool_tail[PACKET_BUFFER_POOL_COUNT] = { 0 };
static struct packet_buffer *packet_buffer_global_pool = NULL;
static pthread_mutex_t packet_buffer_pool_lock = PTHREAD_MUTEX_INITIALIZER;

// Packet info pool stuff
static __thread struct packet_info **packet_info_pool;

int packet_buffer_pool_get(struct packet *pkt, size_t size, size_t align_offset) {

	if (align_offset >= PACKET_BUFFER_ALIGNMENT) {
		pomlog(POMLOG_ERR "Alignment offset too big");
		return POM_ERR;
	}

	size_t tot_size = size + align_offset + PACKET_BUFFER_ALIGNMENT;

	if (tot_size > packet_buffer_pool_size[PACKET_BUFFER_POOL_COUNT - 1]) {
		pomlog(POMLOG_ERR "Requested size too big : %llu", size);
		return POM_ERR;
	}

	unsigned int pool_id;
	for (pool_id = 0; pool_id < PACKET_BUFFER_POOL_COUNT && packet_buffer_pool_size[pool_id] < tot_size; pool_id++);

	struct packet_buffer *pb = packet_buffer_pool_head[pool_id];
	unsigned int i, num_threads = core_get_num_threads();


	for (i = 0; pb && i < num_threads; i++) {
		if (pb->pool_id != PACKET_BUFFER_POOL_ID_UNUSED) {
			pb = pb->next;
		} else {
			break;
		}
	}

	if (!pb || i >= num_threads) {

		// Allocate a new one
		size_t alloc_size = packet_buffer_pool_size[pool_id] + sizeof(struct packet_buffer);

		pb = malloc(alloc_size);
		if (!pb) {
			pom_oom(alloc_size);
			return POM_ERR;
		}
		memset(pb, 0, alloc_size);

		pb->base_buff = (void*)pb + sizeof(struct packet_buffer);
		pb->aligned_buff = (void*) (((long)pb->base_buff & ~(PACKET_BUFFER_ALIGNMENT - 1)) + PACKET_BUFFER_ALIGNMENT + align_offset);

	} else {
		// Remove the packet from the queue

		if (pb->next)
			pb->next->prev = pb->prev;
		else
			packet_buffer_pool_tail[pool_id] = pb->prev;

		if (pb->prev)
			pb->prev->next = pb->next;
		else
			packet_buffer_pool_head[pool_id] = pb->next;

	}

	pb->pool_id = pool_id;
	pkt->pkt_buff = pb;
	pkt->len = size;
	pkt->buff = pb->aligned_buff;

	// Add it back to the end of the pool
	pb->prev = packet_buffer_pool_tail[pool_id];
	if (pb->prev)
		pb->prev->next = pb;
	else
		packet_buffer_pool_head[pool_id] = pb;
	packet_buffer_pool_tail[pool_id] = pb;

	return POM_OK;
}

void packet_buffer_pool_release(struct packet_buffer *pb) {

	pb->pool_id = PACKET_BUFFER_POOL_ID_UNUSED;
}

void packet_buffer_pool_thread_cleanup() {

	pom_mutex_lock(&packet_buffer_pool_lock);

	unsigned int i;
	for (i = 0; i < PACKET_BUFFER_POOL_COUNT; i++) {
		if (!packet_buffer_pool_head[i])
			continue;

		packet_buffer_pool_tail[i]->next = packet_buffer_global_pool;
		packet_buffer_global_pool = packet_buffer_pool_head[i];

		packet_buffer_pool_tail[i] = NULL;
		packet_buffer_pool_head[i] = NULL;
	}
	pom_mutex_unlock(&packet_buffer_pool_lock);
}

int packet_buffer_pool_cleanup() {

	struct packet_buffer *tmp = packet_buffer_global_pool;

	while (tmp) {
		if (tmp->pool_id != PACKET_BUFFER_POOL_ID_UNUSED)
			pomlog(POMLOG_WARN "A buffer was still in use on packet_buffer_pool_cleanup().");

		packet_buffer_global_pool = tmp->next;
		free(tmp);
		tmp = packet_buffer_global_pool;
	}

	return POM_OK;
}

struct packet *packet_pool_get() {

	struct packet *tmp = packet_pool_head;

	unsigned int i, num_threads = core_get_num_threads();

	// Try to find a free packet in the pool for at least the number of threads
	for (i = 0; tmp && i < num_threads; i++) {
		if (tmp->refcount)
			tmp = tmp->next;
		else
			break;
	}

	if (!tmp || i >= num_threads) {
		// No free packet found
		// Alloc a new packet
		tmp = malloc(sizeof(struct packet));
		if (!tmp) {
			pom_oom(sizeof(struct packet));
			return NULL;
		}
	} else {
		// Remove the packet from the queue
		if (tmp->next)
			tmp->next->prev = tmp->prev;
		else
			packet_pool_tail = tmp->prev;

		if (tmp->prev)
			tmp->prev->next = tmp->next;
		else
			packet_pool_head = tmp->next;

		if (tmp->pkt_buff) {
			packet_buffer_pool_release(tmp->pkt_buff);

		}
	}


	memset(tmp, 0, sizeof(struct packet));

	// Add the packet at the end of the pool
	
	tmp->prev = packet_pool_tail;
	if (tmp->prev)
		tmp->prev->next = tmp;
	else
		packet_pool_head = tmp;
	packet_pool_tail = tmp;

	// Init the refcount
	tmp->refcount = 1;

	return tmp;
}

struct packet *packet_clone(struct packet *src, unsigned int flags) {

	struct packet *dst = NULL;

	if (!(flags & PACKET_FLAG_FORCE_NO_COPY) && !src->pkt_buff) {
		// If it doesn't have a pkt_buff structure, it means it was not allocated by us
		// That means that the packet is somewhere probably in a ringbuffer (pcap)
		dst = packet_pool_get();
		if (!dst)
			return NULL;
		// FIXME get the alignment offset from the input
		if (packet_buffer_pool_get(dst, src->len, 0) != POM_OK) {
			packet_pool_release(dst);
			return NULL;
		}

		dst->ts = src->ts;
		memcpy(dst->buff, src->buff, src->len);

		dst->datalink = src->datalink;
		dst->input = src->input;

		// Multipart and stream are not copied
		
		return dst;
	}

	__sync_fetch_and_add(&src->refcount, 1);
	return src;
}

int packet_pool_release(struct packet *p) {

	// Release the multipart
	struct packet_multipart *multipart = __sync_fetch_and_and(&p->multipart, 0);
	if (multipart && packet_multipart_cleanup(multipart) != POM_OK)
		return POM_ERR;

	// The packet refcount will be 0 afterwards
	// We can clean up the buffer if any
	if (p->refcount == 1 && p->pkt_buff) {
		packet_buffer_pool_release(p->pkt_buff);
		p->pkt_buff = NULL;
	}

	__sync_fetch_and_sub(&p->refcount, 1);

	return POM_OK;
}

void packet_pool_thread_cleanup() {
	
	if (!packet_pool_head)
		return;

	pom_mutex_lock(&packet_pool_lock);
	packet_pool_tail->next = packet_pool_global_head;
	packet_pool_global_head = packet_pool_head;
	pom_mutex_unlock(&packet_pool_lock);

	packet_pool_head = NULL;
	packet_pool_tail = NULL;
}

int packet_pool_cleanup() {


	struct packet *tmp = packet_pool_global_head;
	while (tmp) {
		if (tmp->refcount)
			pomlog(POMLOG_WARN "A packet was not released, refcount : %u", tmp->refcount);

		if (tmp->pkt_buff)
			packet_buffer_pool_release(tmp->pkt_buff);
	
		packet_pool_global_head = tmp->next;
		free(tmp);
		tmp = packet_pool_global_head;
	}

	return POM_OK;
}

int packet_info_pool_init() {

	unsigned int proto_count = proto_get_count();

	size_t size = sizeof(struct packet_info*) * proto_count;

	packet_info_pool = malloc(size);
	if (!packet_info_pool) {
		pom_oom(size);
		return POM_ERR;
	}
	memset(packet_info_pool, 0, size);

	return POM_OK;
}

struct packet_info *packet_info_pool_get(struct proto *p) {

	struct packet_info *info = NULL;

	struct packet_info **pool = &packet_info_pool[p->id];

	if (*pool) {
		// We can reuse the old one
		info = *pool;
		*pool = (*pool)->next;
		
		debug_info_pool("Used info %p for proto %s", info, p->info->name);
	} else {
		// Allocate new packet_info
		info = malloc(sizeof(struct packet_info));
		if (!info) {
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
			info->fields_value[i] = ptype_alloc_from_type(fields[i].value_type);
			if (!info->fields_value[i]) {
				i++;
				for (; fields[i].name; i++)
					ptype_cleanup(info->fields_value[i]);
				free(info);
				return NULL;
			}
		}

		debug_info_pool("Allocated info %p for proto %s", info, p->info->name);
	}

	return info;
}

struct packet_info *packet_info_pool_clone(struct proto *p, struct packet_info *info) {

	struct packet_info *new_info = packet_info_pool_get(p);
	if (!new_info)
		return NULL;

	struct proto_pkt_field *fields = p->info->pkt_fields;
	int i;
	for (i = 0; fields[i].name; i++) {
		if (ptype_copy(new_info->fields_value[i], info->fields_value[i]) != POM_OK) {
			packet_info_pool_release(new_info, p->id);
			return NULL;
		}
	}

	return new_info;
}


int packet_info_pool_release(struct packet_info *info, unsigned int protocol_id) {

	if (!info)
		return POM_OK;

	info->next = packet_info_pool[protocol_id];
	packet_info_pool[protocol_id] = info;


	return POM_OK;
}


int packet_info_pool_cleanup() {

	unsigned int proto_count = proto_get_count();

	unsigned int i;
	
	for (i = 0; i < proto_count; i++) {

		struct packet_info *pool = packet_info_pool[i];
		
		while (pool) {

			struct packet_info *tmp = pool;

			int j;
			for (j = 0; tmp->fields_value[j]; j++)
				ptype_cleanup(tmp->fields_value[j]);

			free(tmp->fields_value);

			pool = tmp->next;
			free(tmp);
			
		}
	}

	free(packet_info_pool);
	packet_info_pool = NULL;


	return POM_OK;
}


struct packet_multipart *packet_multipart_alloc(struct proto *proto, unsigned int flags) {

	struct packet_multipart *res = malloc(sizeof(struct packet_multipart));
	if (!res) {
		pom_oom(sizeof(struct packet_multipart));
		return NULL;
	}
	memset(res, 0, sizeof(struct packet_multipart));

	res->proto = proto;
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

		tmp = tmp->prev;

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

			if (tmp->offset + tmp->len < res->offset)
				multipart->gaps++;

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


	// FIXME align offset
	if (packet_buffer_pool_get(p, multipart->cur, 0)) {
		packet_pool_release(p);
		packet_multipart_cleanup(multipart);
		pom_oom(multipart->cur);
		return PROTO_ERR;
	}

	struct packet_multipart_pkt *tmp = multipart->head;
	for (; tmp; tmp = tmp->next) {
		if (tmp->offset + tmp->len > multipart->cur) {
			pomlog(POMLOG_DEBUG "Offset in packet fragment is bigger than packet size.");
			packet_pool_release(p);
			packet_multipart_cleanup(multipart);
			return PROTO_INVALID;
		}
		memcpy(p->buff + tmp->offset, tmp->pkt->buff + tmp->pkt_buff_offset, tmp->len);
	}

	p->ts = multipart->tail->pkt->ts;
	
	p->multipart = multipart;
	p->len = multipart->cur;
	p->datalink = multipart->proto;
	p->input = multipart->head->pkt->input;
	stack[stack_index].pload = p->buff;
	stack[stack_index].plen = p->len;
	stack[stack_index].proto = p->datalink;

	int res = core_process_multi_packet(stack, stack_index, p);

	packet_pool_release(p);

	return res;
}

struct packet_stream_parser *packet_stream_parser_alloc(unsigned int max_line_size) {
	
	struct packet_stream_parser *res = malloc(sizeof(struct packet_stream_parser));
	if (!res) {
		pom_oom(sizeof(struct packet_stream_parser));
		return NULL;
	}

	memset(res, 0, sizeof(struct packet_stream_parser));

	res->max_line_size = max_line_size;

	debug_stream_parser("entry %p, allocated with max_line_size %u", res, max_line_size);

	return res;
}


int packet_stream_parser_add_payload(struct packet_stream_parser *sp, void *pload, unsigned int len) {

	if (!sp->pload && sp->buff) {
		// Payload was fully used, we can discard the buffer
		free(sp->buff);
		sp->buff = NULL;
		sp->buff_len = 0;
		sp->buff_pos = 0;

	}

	if (sp->buff) {
		// There is some leftovers, append the new payload
		if (sp->buff_len - sp->buff_pos < len) {
			sp->buff = realloc(sp->buff, sp->buff_pos + len);
			if (!sp->buff) {
				pom_oom(sp->buff_pos + len);
				return POM_ERR;
			}
			sp->buff_len = sp->buff_pos + len;
		}
		memcpy(sp->buff + sp->buff_pos, pload, len);
		sp->buff_pos += len;
		sp->pload = sp->buff;
		sp->plen = sp->buff_pos;
	} else {
		// No need to buffer anything, let's just process it
		sp->pload = pload;
		sp->plen = len;
	}

	debug_stream_parser("entry %p, added pload %p with len %u", sp, pload, len);

	return POM_OK;
}

int packet_stream_parser_skip_bytes(struct packet_stream_parser *sp, unsigned int len) {

	if (sp->plen < len)
		return POM_ERR;
	
	sp->pload += len;
	sp->plen -= len;

	return POM_OK;
}

int packet_stream_parser_get_remaining(struct packet_stream_parser *sp, void **pload, unsigned int *len) {

	debug_stream_parser("entry %p, providing remaining pload %p with len %u", sp, sp->pload, sp->plen);
	*pload = sp->pload;
	*len = sp->plen;

	return POM_OK;
}

int packet_stream_parser_empty(struct packet_stream_parser *sp) {

	sp->pload = NULL;
	sp->plen = 0;

	return POM_OK;
};

int packet_stream_parser_get_line(struct packet_stream_parser *sp, char **line, unsigned int *len) {

	if (!line || !len)
		return POM_ERR;

	// Find the next line return in the current payload
	
	char *pload = sp->pload;
	
	int str_len = sp->plen, tmp_len = 0;
	
	char *lf = memchr(pload, '\n', sp->plen);
	if (!lf) {

		if (sp->buff) {
			memmove(sp->buff, sp->pload, sp->plen);
			sp->buff_pos = sp->plen;
		} else {
			sp->buff = malloc(sp->plen);
			if (!sp->buff) {
				pom_oom(sp->plen);
				return POM_ERR;
			}
			memcpy(sp->buff, sp->pload, sp->plen);
			sp->buff_len = sp->plen;
			sp->buff_pos = sp->plen;
		}

		// \n not found
		*line = NULL;
		*len = 0;
		debug_stream_parser("entry %p, no line found", sp);
		return POM_OK;
	}


	tmp_len = lf - pload;
	str_len = tmp_len + 1;
	if (lf > pload && *(lf - 1) == '\r')
		tmp_len--;

	
	sp->plen -= str_len;
	if (!sp->plen)
		sp->pload = NULL;
	else
		sp->pload += str_len;

	// Trim the string
	while (*pload == ' ' && tmp_len) {
		pload++;
		tmp_len--;
	}
	while (pload[tmp_len] == ' ' && tmp_len)
		tmp_len--;

	*line = pload;
	*len = tmp_len;

	debug_stream_parser("entry %p, got line of %u bytes", sp, tmp_len);

	return POM_OK;
}



int packet_stream_parser_cleanup(struct packet_stream_parser *sp) {

	if (sp->buff)
		free(sp->buff);

	free(sp);

	return POM_OK;
}
