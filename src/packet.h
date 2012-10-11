/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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



#ifndef __PACKET_H__
#define __PACKET_H__

#include <pom-ng/proto.h>
#include <pom-ng/packet.h>

#define PACKET_HALF_SEQ (0x1 << 31)

#define PACKET_BUFFER_ALIGNMENT 4

#define PACKET_FLAG_STREAM_GOT_FWD_DIR	0x4
#define PACKET_FLAG_STREAM_GOT_REV_DIR	0x8
#define PACKET_FLAG_STREAM_GOT_BOTH_DIR	(PACKET_FLAG_STREAM_GOT_FWD_DIR | PACKET_FLAG_STREAM_GOT_REV_DIR)

struct packet_buffer_pool {
	struct packet_buffer *used;
	struct packet_buffer *unused;

};

struct packet_stream_pkt {

	struct packet *pkt;
	struct proto_process_stack *stack;
	uint32_t seq, ack, plen;
	unsigned int stack_index;
	unsigned int flags;
	struct packet_stream_pkt *prev, *next;

};

struct packet_stream_thread_wait {
	struct timeval ts;
	pthread_t thread;
	pthread_cond_t cond;
	struct packet_stream_thread_wait *prev, *next;
};

struct packet_stream {

	uint32_t cur_seq[POM_DIR_TOT];
	uint32_t cur_ack[POM_DIR_TOT];
	uint32_t cur_buff_size, max_buff_size;
	unsigned int flags;
	unsigned int same_dir_timeout, rev_dir_timeout;
	struct packet_stream_pkt *head[POM_DIR_TOT], *tail[POM_DIR_TOT];
	int (*handler) (struct conntrack_entry *ce, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
	struct conntrack_timer *t;
	struct conntrack_entry *ce;
	pthread_mutex_t lock;

	pthread_mutex_t wait_lock;
	struct packet_stream_thread_wait *wait_list_head, *wait_list_tail, *wait_list_unused;
};

struct packet_stream_parser {
	unsigned int max_line_size;
	char *buff;
	unsigned int buff_len;
	unsigned int buff_pos;
	char *pload;
	unsigned int plen;
};


void packet_buffer_pool_release(struct packet_buffer *pb);
int packet_buffer_pool_cleanup();


int packet_info_pool_init(struct packet_info_pool *pool);
struct packet_info *packet_info_pool_get(struct proto *p);
struct packet_info *packet_info_pool_clone(struct proto *p, struct packet_info *info);
int packet_pool_cleanup();
int packet_info_pool_release(struct packet_info_pool *pool, struct packet_info *info);
int packet_info_pool_cleanup(struct packet_info_pool *pool);

int packet_stream_timeout(struct conntrack_entry *ce, void *priv);
int packet_stream_force_dequeue(struct packet_stream *stream);
struct packet_stream_pkt *packet_stream_get_next(struct packet_stream *stream, unsigned int *direction);

#endif
