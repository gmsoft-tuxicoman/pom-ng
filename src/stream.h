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


#ifndef __STREAM_H__
#define __STREAM_H__

#include <pom-ng/proto.h>
#include <pom-ng/stream.h>

#define STREAM_HALF_SEQ (uint32_t)(0x1 << 31)

#define STREAM_FLAG_GOT_FWD_DIR		0x04
#define STREAM_FLAG_GOT_REV_DIR		0x08
#define STREAM_FLAG_GOT_BOTH_DIR	(STREAM_FLAG_GOT_FWD_DIR | STREAM_FLAG_GOT_REV_DIR)
#define STREAM_FLAG_GOT_FWD_STARTSEQ	0x10
#define STREAM_FLAG_GOT_REV_STARTSEQ	0x20
#define STREAM_FLAG_GOT_BOTH_STARTSEQ	(STREAM_FLAG_GOT_FWD_STARTSEQ | STREAM_FLAG_GOT_REV_STARTSEQ)
#define STREAM_FLAG_RUNNING		0x40 // The stream has started and no sequence update will be accepted
#define STREAM_FLAG_TIMER_SET		0x80

#define STREAM_GAP_STEP_MAX		2048

struct stream_pkt {

	struct packet *pkt;
	struct proto_process_stack *stack;
	uint32_t seq, ack, plen;
	unsigned int stack_index;
	unsigned int flags;
	struct stream_pkt *prev, *next;

};

struct stream_thread_wait {
	ptime ts;
	pthread_t thread;
	pthread_cond_t cond;
	struct stream_thread_wait *prev, *next;
};

struct stream {

	uint32_t cur_seq[POM_DIR_TOT];
	uint32_t cur_buff_size, max_buff_size;
	unsigned int flags;
	unsigned int timeout;
	struct stream_pkt *head[POM_DIR_TOT], *tail[POM_DIR_TOT];
	int (*handler) (struct conntrack_entry *ce, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
	ptime last_ts;
	struct conntrack_timer *t;
	struct conntrack_entry *ce;
	pthread_mutex_t lock;

	pthread_mutex_t wait_lock;
	struct stream_thread_wait *wait_list_head, *wait_list_tail, *wait_list_unused;
};

int stream_timeout(struct conntrack_entry *ce, void *priv, ptime now);
int stream_force_dequeue(struct stream *stream);
int stream_fill_gap(struct stream *stream, struct stream_pkt *p, uint32_t gap, int reverse_dir);
struct stream_pkt *stream_get_next(struct stream *stream, unsigned int *direction);


#endif
