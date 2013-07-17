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


#include "stream.h"
#include "core.h"
#include "packet.h"
#include "proto.h"

#if 0
#define debug_stream(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_stream(x ...)
#endif

struct stream* stream_alloc(uint32_t max_buff_size, struct conntrack_entry *ce, unsigned int flags, int (*handler) (struct conntrack_entry *ce, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index)) {
	
	struct stream *res = malloc(sizeof(struct stream));
	if (!res) {
		pom_oom(sizeof(struct stream));
		return NULL;
	}

	memset(res, 0, sizeof(struct stream));
	
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
	res->handler = handler;

	debug_stream("thread %p, entry %p, allocated", pthread_self(), res);

	return res;
}

int stream_set_timeout(struct stream *stream, unsigned int timeout) {

	stream->timeout = timeout;

	return POM_OK;
}

int stream_cleanup(struct stream *stream) {


	if (stream->wait_list_head) {
		pomlog(POMLOG_ERR "Internal error, cleaning up stream while packets still present!");
		return POM_ERR;
	}

	while (stream->head[0] || stream->head[1]) {
		if (stream_force_dequeue(stream) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while processing remaining packets in the stream");
			break;
		}
	}

	conntrack_delayed_cleanup(stream->ce, 0, stream->last_ts);

	int res = pthread_mutex_destroy(&stream->lock);
	if (res){
		pomlog(POMLOG_ERR "Error while destroying stream lock : %s", pom_strerror(res));
	}

	res = pthread_mutex_destroy(&stream->wait_lock);
	if (res){
		pomlog(POMLOG_ERR "Error while destroying stream wait lock : %s", pom_strerror(res));
	}

	while (stream->wait_list_unused) {
		struct stream_thread_wait *tmp = stream->wait_list_unused;
		stream->wait_list_unused = tmp->next;
		if (pthread_cond_destroy(&tmp->cond))
			pomlog(POMLOG_WARN "Error while destroying list condition");
		free(tmp);
	}
	
	free(stream);

	debug_stream("thread %p, entry %p, released", pthread_self(), stream);

	return POM_OK;
}

static void stream_end_process_packet(struct stream *stream) {

	conntrack_delayed_cleanup(stream->ce, stream->timeout, stream->last_ts);

	pom_mutex_unlock(&stream->lock);
	pom_mutex_lock(&stream->wait_lock);
	if (stream->wait_list_head) {
		debug_stream("thread %p, entry %p : signaling thread %p", pthread_self(), stream, stream->wait_list_head->thread);
		pthread_cond_broadcast(&stream->wait_list_head->cond);
	}
	pom_mutex_unlock(&stream->wait_lock);
}

static int stream_is_packet_old_dupe(struct stream *stream, struct stream_pkt *pkt, int direction) {

	// Don't discard packets if there were not packets processed yet
	if (!(stream->flags & STREAM_FLAG_RUNNING))
		return 0;

	uint32_t end_seq = pkt->seq + pkt->plen;
	uint32_t cur_seq = stream->cur_seq[direction];

	if ((cur_seq >= end_seq && cur_seq - end_seq < STREAM_HALF_SEQ)
		|| (cur_seq < end_seq && end_seq - cur_seq > STREAM_HALF_SEQ)) {
		// cur_seq is after the end of the packet, discard it
		return 1;
	}
	
	return 0;
}

static int stream_remove_dupe_bytes(struct stream *stream, struct stream_pkt *pkt, int direction) {

	// Don't discard bytes if nothing was processed yet
	if (!(stream->flags & STREAM_FLAG_RUNNING))
		return POM_OK;

	uint32_t cur_seq = stream->cur_seq[direction];
	if ((cur_seq > pkt->seq && cur_seq - pkt->seq < STREAM_HALF_SEQ)
		|| (cur_seq < pkt->seq && pkt->seq - cur_seq > STREAM_HALF_SEQ)) {
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

static int stream_is_packet_next(struct stream *stream, struct stream_pkt *pkt, int direction) {

	int rev_direction = POM_DIR_REVERSE(direction);
	uint32_t cur_seq = stream->cur_seq[direction];
	uint32_t rev_seq = stream->cur_seq[rev_direction];


	// Check that there is no gap with what we expect
	if ((cur_seq < pkt->seq && pkt->seq - cur_seq < STREAM_HALF_SEQ)
		|| (cur_seq > pkt->seq && cur_seq - pkt->seq > STREAM_HALF_SEQ)) {
		// There is a gap
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : GAP : cur_seq %u, rev_seq %u", pthread_self(), stream, pom_ptime_sec(pkt->pkt->ts), pom_ptime_usec(pkt->pkt->ts), pkt->seq, pkt->ack, cur_seq, rev_seq);
		return 0;
	}


	if (stream->flags & STREAM_FLAG_BIDIR) {
		// There is additional checking for bi dir stream

	
		if ((rev_seq < pkt->ack && pkt->ack - rev_seq < STREAM_HALF_SEQ)
			|| (rev_seq > pkt->ack && rev_seq - pkt->ack > STREAM_HALF_SEQ)) {
			// The host processed data in the reverse direction which we haven't processed yet
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : reverse missing : cur_seq %u, rev_seq %u", pthread_self(), stream, pom_ptime_sec(pkt->pkt->ts), pom_ptime_usec(pkt->pkt->ts), pkt->seq, pkt->ack, cur_seq, rev_seq);
			return 0;
		}

	}


	// This packet can be processed
	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : is next : cur_seq %u, rev_seq %u", pthread_self(), stream, pom_ptime_sec(pkt->pkt->ts), pom_ptime_usec(pkt->pkt->ts), pkt->seq, pkt->ack, cur_seq, rev_seq);

	return 1;

}

static void stream_free_packet(struct stream_pkt *p) {

	int i;
	for (i = 1; i < CORE_PROTO_STACK_MAX && p->stack[i].proto; i++)
		packet_info_pool_release(p->stack[i].pkt_info, p->stack[i].proto->id);
	free(p->stack);
	packet_pool_release(p->pkt);
	free(p);
}

int stream_process_packet(struct stream *stream, struct packet *pkt, struct proto_process_stack *stack, unsigned int stack_index, uint32_t seq, uint32_t ack) {

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
		pomlog(POMLOG_ERR "Error while locking packet stream lock : %s", pom_strerror(res));
		abort();
		return POM_ERR;
	} else {

		// We got the processing lock. But was it really this thread's turn ?

		struct stream_thread_wait *tmp = stream->wait_list_head;
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
		struct stream_thread_wait *lst = NULL;
		if (stream->wait_list_unused) {
			lst = stream->wait_list_unused;
			stream->wait_list_unused = lst->next;
			lst->next = NULL;
		} else {
			lst = malloc(sizeof(struct stream_thread_wait));
			if (!lst) {
				pom_oom(sizeof(struct stream_thread_wait));
				pom_mutex_unlock(&stream->wait_lock);
				return POM_ERR;
			}
			memset(lst, 0, sizeof(struct stream_thread_wait));
			
			if (pthread_cond_init(&lst->cond, NULL)) {
				pomlog(POMLOG_ERR "Error while initializing wait list condition : %s", pom_strerror(errno));
				free(lst);
				return POM_ERR;
			}
		}
		lst->ts = pkt->ts;
		lst->thread = pthread_self();

		struct stream_thread_wait *tmp;
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
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : waiting (%u)", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack, must_wait);
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

	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : start locked : cur_seq %u, rev_seq %u", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack, stream->cur_seq[direction], stream->cur_seq[POM_DIR_REVERSE(direction)]);

	// Update the stream flags
	if (stream->flags & STREAM_FLAG_BIDIR) {

		// Update flags
		if (direction == POM_DIR_FWD && !(stream->flags & STREAM_FLAG_GOT_FWD_DIR)) {
			stream->flags |= STREAM_FLAG_GOT_FWD_DIR;
		} else if (direction == POM_DIR_REV && !(stream->flags & STREAM_FLAG_GOT_REV_DIR)) {
			stream->flags |= STREAM_FLAG_GOT_REV_DIR;
		}

	}

	// Update the last timestamp seen on the stream
	if (stream->last_ts < pkt->ts)
		stream->last_ts = pkt->ts;

	// Put this packet in our struct stream_pkt
	struct stream_pkt spkt = {0};
	spkt.pkt = pkt;
	spkt.seq = seq;
	spkt.ack = ack;
	spkt.plen = cur_stack->plen;
	spkt.stack = stack;
	spkt.stack_index = stack_index;


	// Check that we are aware of the start sequence
	// If not, we queue
	int dir_flag = (direction == POM_DIR_FWD ? STREAM_FLAG_GOT_FWD_STARTSEQ : STREAM_FLAG_GOT_REV_STARTSEQ);
	if ( ((stream->flags & STREAM_FLAG_BIDIR) && ((stream->flags & STREAM_FLAG_GOT_BOTH_STARTSEQ) == STREAM_FLAG_GOT_BOTH_STARTSEQ))
		|| (!(stream->flags & STREAM_FLAG_BIDIR) && (stream->flags & dir_flag)) ) {


		// Check if the packet is worth processing
		uint32_t cur_seq = stream->cur_seq[direction];
		if (cur_seq != seq) {
			if (stream_is_packet_old_dupe(stream, &spkt, direction)) {
				// cur_seq is after the end of the packet, discard it
				stream_end_process_packet(stream);
				debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : discard", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
				return PROTO_OK;
			}

			if (stream_remove_dupe_bytes(stream, &spkt, direction) == POM_ERR) {
				stream_end_process_packet(stream);
				return PROTO_ERR;
			}
		}


		// Ok let's process it then

		// Check if it is the packet we're waiting for
		if (stream_is_packet_next(stream, &spkt, direction)) {

			// Process it
			stream->cur_seq[direction] += cur_stack->plen;
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);

			int res = stream->handler(stream->ce, pkt, stack, stack_index);
			if (res == PROTO_ERR) {
				stream_end_process_packet(stream);
				return PROTO_ERR;
			}

			// Flag the stream as running
			stream->flags |= STREAM_FLAG_RUNNING;

			// Check if additional packets can be processed
			struct stream_pkt *p = NULL;
			unsigned int cur_dir = direction;
			while ((p = stream_get_next(stream, &cur_dir))) {


				debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process additional", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack);

				if (stream->handler(stream->ce, p->pkt, p->stack, p->stack_index) == POM_ERR) {
					stream_end_process_packet(stream);
					return PROTO_ERR;
				}

				stream->cur_seq[cur_dir] += p->plen;
		
				stream_free_packet(p);
			}

			stream_end_process_packet(stream);
			debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : done processed", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
			return res;
		}
	} else {
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : start_seq not known yet", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
	}

	// Queue the packet then

	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : queue", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);

	struct stream_pkt *p = malloc(sizeof(struct stream_pkt));
	if (!p) {
		pom_oom(sizeof(struct stream_pkt));
		stream_end_process_packet(stream);
		return PROTO_ERR;
	}
	memset(p, 0 , sizeof(struct stream_pkt));


	int flags = 0;
	if (stream->flags & STREAM_FLAG_PACKET_NO_COPY)
		flags = PACKET_FLAG_FORCE_NO_COPY;
	p->pkt = packet_clone(pkt, flags);
	if (!p->pkt) {
		stream_end_process_packet(stream);
		free(p);
		return PROTO_ERR;
	}
	p->stack = core_stack_backup(stack, pkt, p->pkt);
	if (!p->stack) {
		stream_end_process_packet(stream);
		packet_pool_release(p->pkt);
		free(p);
		return PROTO_ERR;
	}


	p->plen = cur_stack->plen;
	p->seq = seq;
	p->ack = ack;
	p->stack_index = stack_index;


	if (!stream->tail[direction]) {
		stream->head[direction] = p;
		stream->tail[direction] = p;
	} else { 

		struct stream_pkt *tmp = stream->tail[direction];
		while ( tmp && 
			((tmp->seq >= seq && tmp->seq - seq < STREAM_HALF_SEQ)
			|| (tmp->seq <= seq && seq - tmp->seq > STREAM_HALF_SEQ))) {

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
		if (stream_force_dequeue(stream) != POM_OK) {
			stream_end_process_packet(stream);
			return POM_ERR;
		}
	}

	stream_end_process_packet(stream);

	debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : done queued", pthread_self(), stream, pom_ptime_sec(pkt->ts), pom_ptime_usec(pkt->ts), seq, ack);
	return PROTO_OK;
}

int stream_fill_gap(struct stream *stream, struct stream_pkt *p, uint32_t gap, int reverse_dir) {

	if (gap > stream->max_buff_size) {
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : gap of %u too big. not filling", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack, gap);
		return POM_OK;
	}
	
	if (!reverse_dir) {
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : filling gap of %u in forward direction", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack, gap);
	} else {
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : filling gap of %u in reverse direction", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack, gap);
	}
	
	uint32_t gap_step = gap;
	if (gap_step > STREAM_GAP_STEP_MAX)
		gap_step = STREAM_GAP_STEP_MAX;

	void *zero = malloc(gap_step);
	if (!zero) {
		pom_oom(gap_step);
		return POM_ERR;
	}
	memset(zero, 0, gap_step);
	
	struct proto_process_stack *s = &p->stack[p->stack_index];
	uint32_t plen_old = s->plen;
	void *pload_old = s->pload;
	int dir_old = s->direction;
	int dir_new = s->direction;

	if (reverse_dir)
		dir_new = POM_DIR_REVERSE(s->direction);


	uint32_t pos;
	for (pos = 0; pos < gap; pos += gap_step) {
		if (pos + gap_step < gap)
			s->plen = gap_step;
		else
			s->plen = gap - pos;
		s->pload = zero;
		s->direction = dir_new;
		int res = stream->handler(stream->ce, p->pkt, p->stack, p->stack_index);
		if (res == PROTO_ERR)
			break;
	}

	free(zero);

	s->pload = pload_old;
	s->plen = plen_old;
	s->direction = dir_old;

	return POM_OK;
}
		
int stream_force_dequeue(struct stream *stream) {

	struct stream_pkt *p = NULL;
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
				struct stream_pkt *a = stream->head[i], *b = stream->head[r];
				uint32_t end_seq = a->seq + a->plen;
				if ((end_seq <= b->ack && b->ack - end_seq < STREAM_HALF_SEQ) ||
					(b->ack > end_seq && end_seq - b->ack > STREAM_HALF_SEQ))
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


		if (stream_is_packet_old_dupe(stream, p, next_dir)) {
			stream_free_packet(p);
		} else {
			break;
		}
	}

	if (stream_remove_dupe_bytes(stream, p, next_dir) == POM_ERR)
		return POM_ERR;

	// Flag the stream as running
	stream->flags |= STREAM_FLAG_RUNNING;

	// If we didn't we now know about the sequence
	int dir_flag = (next_dir == POM_DIR_FWD ? STREAM_FLAG_GOT_FWD_STARTSEQ : STREAM_FLAG_GOT_REV_STARTSEQ);
	if (!(stream->flags & dir_flag)) {
		stream->flags |= dir_flag;
		stream->cur_seq[next_dir] = p->seq;
	}

	int res = PROTO_OK;
	
	// Check if we were waiting on the reverse direction
	if (stream->flags & STREAM_FLAG_BIDIR) {
	
		unsigned int next_rev_dir = POM_DIR_REVERSE(next_dir);

		int rev_dir_flag = (next_rev_dir == POM_DIR_FWD ? STREAM_FLAG_GOT_FWD_DIR : STREAM_FLAG_GOT_REV_DIR);

		// Only fill a gap in the reverse direction if we've had packets in that direction
		if (stream->flags & rev_dir_flag) {

			uint32_t rev_seq = stream->cur_seq[next_rev_dir];
			if ((rev_seq < p->ack && p->ack - rev_seq < STREAM_HALF_SEQ)
				|| (rev_seq > p->ack && rev_seq - p->ack > STREAM_HALF_SEQ)) {
					

				// We were waiting for reverse
				uint32_t rev_gap = p->ack - stream->cur_seq[next_rev_dir];
				res = stream_fill_gap(stream, p, rev_gap, 1);
				stream->cur_seq[next_rev_dir] = p->ack;

			}
		}
	}

	uint32_t gap = p->seq - stream->cur_seq[next_dir];
	if (gap) {
		if (res != PROTO_ERR)
			res = stream_fill_gap(stream, p, gap, 0);
	}

	// Update the cur_seq in our direction
	stream->cur_seq[next_dir] = p->seq + p->plen;

	if (res != PROTO_ERR) {
		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process forced", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack);
		res = stream->handler(stream->ce, p->pkt, p->stack, p->stack_index);
	}


	stream_free_packet(p);


	if (res == PROTO_ERR) 
		return POM_ERR;

	// See if we can process additional packets

	// Check if additional packets can be processed
	while ((p = stream_get_next(stream, &next_dir))) {

		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process additional", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack);

		if (stream->handler(stream->ce, p->pkt, p->stack, p->stack_index) == PROTO_ERR)
			return POM_ERR;

		stream->cur_seq[next_dir] += p->plen;

		stream_free_packet(p);
	}

	return POM_OK;
}

struct stream_pkt *stream_get_next(struct stream *stream, unsigned int *direction) {

	struct stream_pkt *res = NULL;

	int dirs[2] = { *direction, POM_DIR_REVERSE(*direction) };

	// Make sure we have the sequences before we start looking
	int dir_flag = (*direction == POM_DIR_FWD ? STREAM_FLAG_GOT_FWD_STARTSEQ : STREAM_FLAG_GOT_REV_STARTSEQ);
	if ( ((stream->flags & STREAM_FLAG_BIDIR) && ((stream->flags & STREAM_FLAG_GOT_BOTH_STARTSEQ) != STREAM_FLAG_GOT_BOTH_STARTSEQ))
		|| (!(stream->flags & STREAM_FLAG_BIDIR) && !(stream->flags & dir_flag)) )
		return NULL;

	int i, cur_dir;
	for (i = 0; i < 2 && !res; i++) {
		
		*direction = dirs[i];
		cur_dir = *direction;

		while (stream->head[cur_dir]) {
			
			res = stream->head[cur_dir];

			if (!stream_is_packet_next(stream, res, cur_dir)) {
				res = NULL;
				break;
			}

			uint32_t cur_seq = stream->cur_seq[cur_dir];
			uint32_t seq = res->seq;
			// Check for duplicate bytes
			if (cur_seq != seq) {

				if (stream_is_packet_old_dupe(stream, res, cur_dir)) {
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
					stream_free_packet(res);
					res = NULL;

					// Next packet please
					continue;
				} else {
					if (stream_remove_dupe_bytes(stream, res, cur_dir) == POM_ERR)
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

int stream_increase_seq(struct stream *stream, unsigned int direction, uint32_t inc) {
	// This function must be called locked
	stream->cur_seq[direction] += inc;	

	debug_stream("thread %p, entry %p, seq %u : increasing sequence by %u for direction %u", pthread_self(), stream, stream->cur_seq[direction], inc, direction);
	// Check if additional packets can be processed
	struct stream_pkt *p = NULL;
	while ((p = stream_get_next(stream, &direction))) {

		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process additional", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack);
		// Flag the stream as running
		stream->flags |= STREAM_FLAG_RUNNING;

		if (stream->handler(stream->ce, p->pkt, p->stack, p->stack_index) == PROTO_ERR)
			return POM_ERR;

		stream->cur_seq[direction] += p->plen;

		stream_free_packet(p);
	}

	return POM_OK;
}

int stream_set_start_seq(struct stream *stream, unsigned int direction, uint32_t seq) {

	pom_mutex_lock(&stream->lock);

	if (stream->flags & STREAM_FLAG_RUNNING) {
		debug_stream("thread %p, entry %p : not accepting additional sequence update as the stream stared", pthread_self(), stream);
		stream_end_process_packet(stream);
		return POM_OK;
	}

	int dir_flag = (direction == POM_DIR_FWD ? STREAM_FLAG_GOT_FWD_STARTSEQ : STREAM_FLAG_GOT_REV_STARTSEQ);
	stream->flags |= dir_flag;
	stream->cur_seq[direction] = seq;

	debug_stream("thread %p, entry %p : start_seq for direction %u set to %u", pthread_self(), stream, direction, seq);

	struct stream_pkt *p = NULL;
	while ((p = stream_get_next(stream, &direction))) {

		debug_stream("thread %p, entry %p, packet %u.%06u, seq %u, ack %u : process additional", pthread_self(), stream, pom_ptime_sec(p->pkt->ts), pom_ptime_usec(p->pkt->ts), p->seq, p->ack);
		// Flag the stream as running
		stream->flags |= STREAM_FLAG_RUNNING;

		if (stream->handler(stream->ce, p->pkt, p->stack, p->stack_index) == PROTO_ERR) {
			stream_end_process_packet(stream);
			return POM_ERR;
		}

		stream->cur_seq[direction] += p->plen;

		stream_free_packet(p);
	}

	stream_end_process_packet(stream);
	return POM_OK;
}
