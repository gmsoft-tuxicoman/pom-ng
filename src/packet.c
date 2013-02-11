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

int packet_info_pool_init(struct packet_info_pool *pool) {

	if (pthread_mutex_init(&pool->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing the pkt_info_pool lock : ", pom_strerror(errno));
		return POM_ERR;
	}

	return POM_OK;
}

struct packet_info *packet_info_pool_get(struct proto *p) {

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
			info->fields_value[i] = ptype_alloc_from_type(fields[i].value_type);
			if (!info->fields_value[i]) {
				i++;
				for (; fields[i].name; i++)
					ptype_cleanup(info->fields_value[i]);
				free(info);
				pom_mutex_unlock(&p->pkt_info_pool.lock);
				return NULL;
			}
		}

		debug_info_pool("Allocated info %p for proto %s", info, p->info->name);

	} else {
		// Dequeue the packet_info from the unused pool
		info = p->pkt_info_pool.unused;
		p->pkt_info_pool.unused = info->pool_next;
		if (p->pkt_info_pool.unused)
			p->pkt_info_pool.unused->pool_prev = NULL;

		debug_info_pool("Used info %p for proto %s", info, p->info->name);
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

struct packet_info *packet_info_pool_clone(struct proto *p, struct packet_info *info) {

	struct packet_info *new_info = packet_info_pool_get(p);
	if (!new_info)
		return NULL;

	struct proto_pkt_field *fields = p->info->pkt_fields;
	int i;
	for (i = 0; fields[i].name; i++) {
		if (ptype_copy(new_info->fields_value[i], info->fields_value[i]) != POM_OK) {
			packet_info_pool_release(&p->pkt_info_pool, new_info);
			return NULL;
		}
	}

	return new_info;
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

	debug_info_pool("Released info %p", info);
	
	pom_mutex_unlock(&pool->lock);
	return POM_OK;
}


int packet_info_pool_cleanup(struct packet_info_pool *pool) {

	pthread_mutex_destroy(&pool->lock);

	struct packet_info *tmp = NULL;
#ifndef PACKET_INFO_POOL_ALLOC_DEBUG
	while (pool->used) {
		tmp = pool->used;
		printf("Unreleased packet info %p !\n", tmp);
		pool->used = tmp->pool_next;

		int i;
		for (i = 0; tmp->fields_value[i]; i++)
			ptype_cleanup(tmp->fields_value[i]);

		free(tmp->fields_value);
		free(tmp);
	}
#endif
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


struct packet_stream* packet_stream_alloc(uint32_t start_seq, uint32_t start_ack, int direction, uint32_t max_buff_size, struct conntrack_entry *ce, unsigned int flags) {
	
	struct packet_stream *res = malloc(sizeof(struct packet_stream));
	if (!res) {
		pom_oom(sizeof(struct packet_stream));
		return NULL;
	}

	memset(res, 0, sizeof(struct packet_stream));
	
	int rev_direction = POM_DIR_REVERSE(direction);
	res->cur_seq[direction] = start_seq;
	res->cur_ack[direction] = start_ack;
	res->cur_seq[rev_direction] = start_ack;
	res->cur_ack[rev_direction] = start_seq;
	res->max_buff_size = max_buff_size;
	res->ce = ce;
	if (pthread_mutex_init(&res->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing stream lock : %s", pom_strerror(errno));
		free(res);
		return NULL;
	}
	if (pthread_mutex_init(&res->wait_lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing stream wait lock : %s", pom_strerror(errno));
		free(res);
		return NULL;
	}

	res->flags = flags;

	debug_stream("thread %p, entry %p, allocated, start_seq %u, start_ack %u, direction %u", pthread_self(), res, start_seq, start_ack, direction);

	return res;
}

int packet_stream_set_timeout(struct packet_stream *stream, unsigned int same_dir_timeout, unsigned int rev_dir_timeout, int (*handler) (struct conntrack_entry *ce, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index)) {


	if (!stream->t) {
		stream->t = conntrack_timer_alloc(stream->ce, packet_stream_timeout, stream);
		if (!stream->t)
			return POM_ERR;
	}
	stream->handler = handler;
	stream->same_dir_timeout = same_dir_timeout;
	stream->rev_dir_timeout = rev_dir_timeout;

	return POM_OK;
}

int packet_stream_cleanup(struct packet_stream *stream) {


	if (stream->wait_list_head) {
		pomlog(POMLOG_ERR "Internal error, cleaning up stream while packets still present!");
		return POM_ERR;
	}

	while (stream->head[0] || stream->head[1]) {
		if (packet_stream_force_dequeue(stream) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while processing remaining packets in the stream");
			break;
		}
	}

	if (stream->t)
		conntrack_timer_cleanup(stream->t);

	if (pthread_mutex_destroy(&stream->lock)) 
		pomlog(POMLOG_ERR "Error while destroying stream lock : %s", pom_strerror(errno));
	if (pthread_mutex_destroy(&stream->wait_lock)) 
		pomlog(POMLOG_ERR "Error while destroying stream wait lock : %s", pom_strerror(errno));

	while (stream->wait_list_unused) {
		struct packet_stream_thread_wait *tmp = stream->wait_list_unused;
		stream->wait_list_unused = tmp->next;
		if (pthread_cond_destroy(&tmp->cond))
			pomlog(POMLOG_WARN "Error while destroying list condition");
		free(tmp);
	}
	
	free(stream);

	debug_stream("thread %p, entry %p, released", pthread_self(), stream);

	return POM_OK;
}

int packet_stream_timeout(struct conntrack_entry *ce, void *priv) {

	struct packet_stream *stream = priv;
	int res = POM_OK;
	
	pom_mutex_lock(&stream->lock);
	res = packet_stream_force_dequeue(stream);
	pom_mutex_unlock(&stream->lock);

	return res;
}

static int packet_stream_is_packet_old_dupe(struct packet_stream *stream, struct packet_stream_pkt *pkt, int direction) {

	uint32_t end_seq = pkt->seq + pkt->plen;
	uint32_t cur_seq = stream->cur_seq[direction];

	if ((cur_seq >= end_seq && cur_seq - end_seq < PACKET_HALF_SEQ)
		|| (cur_seq < end_seq && end_seq - cur_seq > PACKET_HALF_SEQ)) {
		// cur_seq is after the end of the packet, discard it
		return 1;
	}
	
	return 0;
}

static int packet_stream_remove_dupe_bytes(struct packet_stream *stream, struct packet_stream_pkt *pkt, int direction) {

	uint32_t cur_seq = stream->cur_seq[direction];
	if ((cur_seq > pkt->seq && cur_seq - pkt->seq < PACKET_HALF_SEQ)
		|| (cur_seq < pkt->seq && pkt->seq - cur_seq > PACKET_HALF_SEQ)) {
		// We need to discard some of the packet
		uint32_t dupe = cur_seq - pkt->seq;

		if (dupe > pkt->plen) {
			pomlog(POMLOG_ERR "Internal error while computing duplicate bytes");
			return POM_ERR;
		}
		pkt->stack[pkt->stack_index].pload += dupe;
		pkt->stack[pkt->stack_index].plen -= dupe;
		pkt->plen -= dupe;
		pkt->seq += dupe;
	}

	return POM_OK;
}

static int packet_stream_is_packet_next(struct packet_stream *stream, struct packet_stream_pkt *pkt, int direction) {

	int rev_direction = POM_DIR_REVERSE(direction);
	uint32_t cur_seq = stream->cur_seq[direction];
	uint32_t rev_seq = stream->cur_seq[rev_direction];


	// Check that there is no gap with what we expect
	if ((cur_seq < pkt->seq && pkt->seq - cur_seq < PACKET_HALF_SEQ)
		|| (cur_seq > pkt->seq && cur_seq - pkt->seq > PACKET_HALF_SEQ)) {
		// There is a gap
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : GAP : cur_seq %u, rev_seq %u", pthread_self(), stream, pom_ptime_sec(pkt->pkt->ts), pom_ptime_usec(pkt->pkt->ts), pkt->seq, pkt->ack, cur_seq, rev_seq);
		return 0;
	}


	if (stream->flags & PACKET_FLAG_STREAM_BIDIR) {
		// There is additional checking for bi dir stream

	
		if ((rev_seq < pkt->ack && pkt->ack - rev_seq < PACKET_HALF_SEQ)
			|| (rev_seq > pkt->ack && rev_seq - pkt->ack > PACKET_HALF_SEQ)) {
			// The host processed data in the reverse direction which we haven't processed yet
			if (stream->t)
				conntrack_timer_queue(stream->t, stream->rev_dir_timeout);
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : reverse missing : cur_seq %u, rev_seq %u", pthread_self(), stream, pom_ptime_sec(pkt->pkt->ts), pom_ptime_usec(pkt->pkt->ts), pkt->seq, pkt->ack, cur_seq, rev_seq);
			return 0;
		}

	}


	// This packet can be processed
	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : is next : cur_seq %u, rev_seq %u", pthread_self(), stream, pom_ptime_sec(pkt->pkt->ts), pom_ptime_usec(pkt->pkt->ts), pkt->seq, pkt->ack, cur_seq, rev_seq);

	return 1;

}

static void packet_stream_end_process_packet(struct packet_stream *stream) {

	pom_mutex_unlock(&stream->lock);
	pom_mutex_lock(&stream->wait_lock);
	if (stream->wait_list_head) {
		debug_stream("thread %p, entry %p : signaling thread %p", pthread_self(), stream, stream->wait_list_head->thread);
		pthread_cond_broadcast(&stream->wait_list_head->cond);
	}
	pom_mutex_unlock(&stream->wait_lock);
}

static void packet_stream_free_packet(struct packet_stream_pkt *p) {

	int i;
	for (i = 1; i < CORE_PROTO_STACK_MAX && p->stack[i].proto; i++)
		packet_info_pool_release(&p->stack[i].proto->pkt_info_pool, p->stack[i].pkt_info);
	free(p->stack);
	packet_pool_release(p->pkt);
	free(p);
}

int packet_stream_process_packet(struct packet_stream *stream, struct packet *pkt, struct proto_process_stack *stack, unsigned int stack_index, uint32_t seq, uint32_t ack) {

	if (!stream || !pkt || !stack)
		return PROTO_ERR;

	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : start", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);

	struct proto_process_stack *cur_stack = &stack[stack_index];
	int direction = cur_stack->direction;

	int must_wait = 0;

	pom_mutex_lock(&stream->wait_lock);

	int res = pthread_mutex_trylock(&stream->lock);
	if (res == EBUSY) {
		// Already locked, let's wait a bit
		must_wait = 1;
	} else if (res) {
		pomlog(POMLOG_ERR "Error while locking packet stream lock : %s", pom_strerror(errno));
		abort();
		return POM_ERR;
	} else {

		// We got the processing lock. But was it really this thread's turn ?

		struct packet_stream_thread_wait *tmp = stream->wait_list_head;
		// A thread with a packet preceding ours is waiting
		if (tmp && (tmp->ts < pkt->ts)) {
			// No it wasn't, release it and signal the right thread
			must_wait = 2;
			pom_mutex_unlock(&stream->lock);
			debug_stream("thread %p, entry %p : signaling thread %p", pthread_self(), stream, stream->wait_list_head->thread);
			pthread_cond_broadcast(&stream->wait_list_head->cond);
		} else {
			// Yes it was. YAY !
			pom_mutex_unlock(&stream->wait_lock);
		}

	}


	if (must_wait) {

		// Add ourself in the waiting list
		struct packet_stream_thread_wait *lst = NULL;
		if (stream->wait_list_unused) {
			lst = stream->wait_list_unused;
			stream->wait_list_unused = lst->next;
			lst->next = NULL;
		} else {
			lst = malloc(sizeof(struct packet_stream_thread_wait));
			if (!lst) {
				pom_oom(sizeof(struct packet_stream_thread_wait));
				pom_mutex_unlock(&stream->wait_lock);
				return POM_ERR;
			}
			memset(lst, 0, sizeof(struct packet_stream_thread_wait));
			
			if (pthread_cond_init(&lst->cond, NULL)) {
				pomlog(POMLOG_ERR "Error while initializing wait list condition : %s", pom_strerror(errno));
				free(lst);
				return POM_ERR;
			}
		}
		lst->ts = pkt->ts;
		lst->thread = pthread_self();

		struct packet_stream_thread_wait *tmp;
		for (tmp = stream->wait_list_head; tmp && (tmp->ts < lst->ts); tmp = tmp->next);
		if (tmp) {

			lst->prev = tmp->prev;
			if (lst->prev)
				lst->prev->next = lst;
			else
				stream->wait_list_head = lst;

			lst->next = tmp;
			lst->next->prev = lst;
		} else {
			lst->prev = stream->wait_list_tail;
			if (lst->prev)
				lst->prev->next = lst;
			else
				stream->wait_list_head = lst;

			stream->wait_list_tail = lst;
		}


		while (1) {
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : waiting", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
			if (pthread_cond_wait(&lst->cond, &stream->wait_lock)) {
				pomlog(POMLOG_ERR "Error while waiting for the packet stream wait cond : %s", pom_strerror(errno));
				abort();
				return POM_ERR;
			}

			if (stream->wait_list_head != lst) {
				// There is a small chance that another stream lock stream->wait_lock while pthread_cond_wait acquires it
				// If we are not the right thread, then simply signal the right one and wait again for our turn
				debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : wrong thread woke up", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
				pthread_cond_broadcast(&stream->wait_list_head->cond);
				continue;
			}
			break;
		}

		tmp = stream->wait_list_head;
		stream->wait_list_head = tmp->next;
		if (stream->wait_list_head)
			stream->wait_list_head->prev = NULL;
		else
			stream->wait_list_tail = NULL;

		tmp->next = stream->wait_list_unused;
		tmp->prev = NULL;
		stream->wait_list_unused = tmp;

		pom_mutex_unlock(&stream->wait_lock);
		pom_mutex_lock(&stream->lock);

	}

	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : start locked", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);

	// Update the stream flags
	if (stream->flags & PACKET_FLAG_STREAM_BIDIR) {

		// Update flags
		if (direction == POM_DIR_FWD && !(stream->flags & PACKET_FLAG_STREAM_GOT_FWD_DIR)) {
			stream->flags |= PACKET_FLAG_STREAM_GOT_FWD_DIR;
		} else if (direction == POM_DIR_REV && !(stream->flags & PACKET_FLAG_STREAM_GOT_REV_DIR)) {
			stream->flags |= PACKET_FLAG_STREAM_GOT_REV_DIR;
		}

	}

	// Put this packet in our struct packet_stream_pkt
	struct packet_stream_pkt spkt = {0};
	spkt.pkt = pkt;
	spkt.seq = seq;
	spkt.ack = ack;
	spkt.plen = cur_stack->plen;
	spkt.stack = stack;
	spkt.stack_index = stack_index;


	// Check if the packet is worth processing
	uint32_t cur_seq = stream->cur_seq[direction];
	if (cur_seq != seq) {
		if (packet_stream_is_packet_old_dupe(stream, &spkt, direction)) {
			// cur_seq is after the end of the packet, discard it
			packet_stream_end_process_packet(stream);
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : discard", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
			return PROTO_OK;
		}

		if (packet_stream_remove_dupe_bytes(stream, &spkt, direction) == POM_ERR) {
			packet_stream_end_process_packet(stream);
			return PROTO_ERR;
		}
	}


	// Ok let's process it then

	// Check if it is the packet we're waiting for
	if (packet_stream_is_packet_next(stream, &spkt, direction)) {

		// Process it
		stream->cur_seq[direction] += cur_stack->plen;
		stream->cur_ack[direction] = ack;
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);

		int res = stream->handler(stream->ce, pkt, stack, stack_index);
		if (res == PROTO_ERR) {
			packet_stream_end_process_packet(stream);
			return PROTO_ERR;
		}

		// Check if additional packets can be processed
		struct packet_stream_pkt *p = NULL;
		unsigned int cur_dir = direction, additional_processed = 0;
		while ((p = packet_stream_get_next(stream, &cur_dir))) {


			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process additional", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack);

			if (stream->handler(stream->ce, p->pkt, p->stack, p->stack_index) == POM_ERR) {
				packet_stream_end_process_packet(stream);
				return PROTO_ERR;
			}

			stream->cur_seq[cur_dir] += p->plen;
			stream->cur_ack[cur_dir] = p->ack;
	
			packet_stream_free_packet(p);

			additional_processed = 1;
		}

		if (additional_processed) {
			if (!stream->head[POM_DIR_FWD] && !stream->head[POM_DIR_REV])
				conntrack_timer_dequeue(stream->t);
			else
				conntrack_timer_queue(stream->t, stream->same_dir_timeout);
		}

		packet_stream_end_process_packet(stream);
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : done processed", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
		return res;
	}

	// Queue the packet then

	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : queue", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);

	struct packet_stream_pkt *p = malloc(sizeof(struct packet_stream_pkt));
	if (!p) {
		pom_oom(sizeof(struct packet_stream_pkt));
		packet_stream_end_process_packet(stream);
		return PROTO_ERR;
	}
	memset(p, 0 , sizeof(struct packet_stream_pkt));


	if (cur_stack->plen) {
		// No need to backup this if there is no payload
		p->pkt = packet_clone(pkt, stream->flags);
		if (!p->pkt) {
			packet_stream_end_process_packet(stream);
			free(p);
			return PROTO_ERR;
		}
		p->stack = core_stack_backup(stack, pkt, p->pkt);
		if (!p->stack) {
			packet_stream_end_process_packet(stream);
			packet_pool_release(p->pkt);
			free(p);
			return PROTO_ERR;
		}
	}


	p->plen = cur_stack->plen;
	p->seq = seq;
	p->ack = ack;
	p->stack_index = stack_index;


	if (!stream->tail[direction]) {
		stream->head[direction] = p;
		stream->tail[direction] = p;
	} else { 

		struct packet_stream_pkt *tmp = stream->tail[direction];
		while ( tmp && 
			((tmp->seq >= seq && tmp->seq - seq < PACKET_HALF_SEQ)
			|| (tmp->seq <= seq && seq - tmp->seq > PACKET_HALF_SEQ))) {

			tmp = tmp->prev;

		}

		if (!tmp) {
			// Packet goes at the begining of the list
			p->next = stream->head[direction];
			if (p->next)
				p->next->prev = p;
			else
				stream->tail[direction] = p;
			stream->head[direction] = p;

		} else {
			// Insert the packet after the current one
			p->next = tmp->next;
			p->prev = tmp;

			if (p->next)
				p->next->prev = p;
			else
				stream->tail[direction] = p;

			tmp->next = p;

		}
	}
	
	stream->cur_buff_size += cur_stack->plen;

	
	if (stream->cur_buff_size >= stream->max_buff_size) {
		// Buffer overflow
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : buffer overflow, forced dequeue", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
		if (packet_stream_force_dequeue(stream) != POM_OK) {
			packet_stream_end_process_packet(stream);
			return POM_ERR;
		}

		if (stream->t)
			conntrack_timer_dequeue(stream->t);
	}

	// Add timeout
	if (stream->t && (stream->head[POM_DIR_FWD] || stream->head[POM_DIR_REV])) 
		conntrack_timer_queue(stream->t, stream->same_dir_timeout);
	packet_stream_end_process_packet(stream);

	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : done queued", pthread_self(),  stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
	return PROTO_OK;
}

int packet_stream_force_dequeue(struct packet_stream *stream) {

	struct packet_stream_pkt *p = NULL;
	unsigned int next_dir = 0;

	while (1) {

		if (!stream->head[POM_DIR_FWD] && !stream->head[POM_DIR_REV])
			return POM_OK;


		if (!stream->head[POM_DIR_FWD]) {
			next_dir = POM_DIR_REV;
		} else if (!stream->head[POM_DIR_REV]) {
			next_dir = POM_DIR_FWD;
		} else {
			// We have packets in both direction, lets see which one we'll process first
			int i;
			for (i = 0; i < POM_DIR_TOT; i++) {
				int r = POM_DIR_REVERSE(i);
				struct packet_stream_pkt *a = stream->head[i], *b = stream->head[r];
				uint32_t end_seq = a->seq + a->plen;
				if ((end_seq <= b->ack && b->ack - end_seq < PACKET_HALF_SEQ) ||
					(b->ack > end_seq && end_seq - b->ack > PACKET_HALF_SEQ))
					break;

			}
			if (i == POM_DIR_TOT) {
				// There is a gap in both direction
				// Process the first packet received
				struct packet *a = stream->head[POM_DIR_FWD]->pkt, *b = stream->head[POM_DIR_REV]->pkt;
				if (a->ts < b->ts) {
					next_dir = POM_DIR_FWD;
				} else {
					next_dir = POM_DIR_REV;
				}
				debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : processing next by timestamp", pthread_self(), stream, pom_ptime_sec(stream->head[next_dir]->pkt->ts), pom_ptime_usec(stream->head[next_dir]->pkt->ts), stream->head[next_dir]->seq, stream->head[next_dir]->ack);
			} else {
				next_dir = i;
			}
		}

		p = stream->head[next_dir];
		if (p->next)
			p->next->prev = NULL;
		else
			stream->tail[next_dir] = NULL;
		
		stream->head[next_dir] = p->next;
		stream->cur_buff_size -= p->plen;


		if (packet_stream_is_packet_old_dupe(stream, p, next_dir)) {
			packet_stream_free_packet(p);
		} else {
			break;
		}
	}

	if (packet_stream_remove_dupe_bytes(stream, p, next_dir) == POM_ERR)
		return POM_ERR;


	uint32_t gap = p->seq - stream->cur_seq[next_dir];

	int res = PROTO_OK;

	if (gap) {
		
		if (gap < stream->max_buff_size) {
		
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : filling gap of %u", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack, gap);
			uint32_t gap_step = gap;
			if (gap_step > 2048)
				gap_step = 2048;

			void *zero = malloc(gap_step);
			if (!zero) {
				pom_oom(gap_step);
				return POM_ERR;
			}
			memset(zero, 0, gap_step);
			
			struct proto_process_stack *s = &p->stack[p->stack_index];
			uint32_t plen_old = s->plen;
			void *pload_old = s->pload;


			uint32_t pos;
			for (pos = 0; pos < gap; pos += gap_step) {
				if (pos + gap_step < gap)
					s->plen = gap_step;
				else
					s->plen = gap - pos;
				s->pload = zero;
				res = stream->handler(stream->ce, p->pkt, p->stack, p->stack_index);
				s->direction = next_dir;
				if (res == PROTO_ERR)
					break;
			}

			free(zero);

			s->pload = pload_old;
			s->plen = plen_old;

		} else {
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : gap of %u too big. not filling", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack, gap);
		}
		
	}

	if (res != PROTO_ERR) {
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process forced", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack);
		res = stream->handler(stream->ce, p->pkt, p->stack, p->stack_index);
	}

	stream->cur_seq[next_dir] = p->seq + p->plen;
	stream->cur_ack[next_dir] = p->ack;

	packet_stream_free_packet(p);


	if (res == PROTO_ERR) 
		return POM_ERR;

	// See if we can process additional packets

	// Check if additional packets can be processed
	while ((p = packet_stream_get_next(stream, &next_dir))) {

		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process additional", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack);

		if (stream->handler(stream->ce, p->pkt, p->stack, p->stack_index) == PROTO_ERR)
			return POM_ERR;

		stream->cur_seq[next_dir] += p->plen;
		stream->cur_ack[next_dir] = p->ack;

		packet_stream_free_packet(p);
	}

	return POM_OK;
}

struct packet_stream_pkt *packet_stream_get_next(struct packet_stream *stream, unsigned int *direction) {

	struct packet_stream_pkt *res = NULL;

	int dirs[2] = { *direction, POM_DIR_REVERSE(*direction) };

	int i, cur_dir;
	for (i = 0; i < 2 && !res; i++) {
		
		*direction = dirs[i];
		cur_dir = *direction;

		while (stream->head[cur_dir]) {
			
			res = stream->head[cur_dir];

			if (!packet_stream_is_packet_next(stream, res, cur_dir)) {
				res = NULL;
				break;
			}

			uint32_t cur_seq = stream->cur_seq[cur_dir];
			uint32_t seq = res->seq;
			// Check for duplicate bytes
			if (cur_seq != seq) {

				if (packet_stream_is_packet_old_dupe(stream, res, cur_dir)) {
					// Packet is a duplicate, remove it
					stream->head[cur_dir] = res->next;
					if (res->next) {
						res->next->prev = NULL;
					} else {
						stream->tail[cur_dir] = NULL;
					}

					if (res->prev) {
						pomlog(POMLOG_WARN "Dequeing packet which wasn't the first in the list. This shouldn't happen !");
						res->prev->next = res->next;
					}
					
					stream->cur_buff_size -= res->plen;
					packet_stream_free_packet(res);
					res = NULL;

					// Next packet please
					continue;
				} else {
					if (packet_stream_remove_dupe_bytes(stream, res, cur_dir) == POM_ERR)
						return NULL;

				}
			}

			
			break;
			
		}
		
	}

	if (!res)
		return NULL;

	// Dequeue the packet
	

	stream->head[cur_dir] = res->next;
	if (res->next) {
		res->next->prev = res->prev;
	} else {
		stream->tail[cur_dir] = NULL;
	}

	stream->cur_buff_size -= res->plen;

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
