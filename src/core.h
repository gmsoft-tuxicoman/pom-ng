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



#ifndef __CORE_H__
#define __CORE_H__

#include <pom-ng/proto.h>
#include <pthread.h>

#define CORE_PROTO_STACK_MAX		16

#define CORE_PKT_QUEUE_MAX		64
#define CORE_PROCESS_THREAD_MAX		64
#define CORE_PROCESS_THREAD_DEFAULT	2

struct core_packet_queue {
	struct packet *pkt;
	struct input_client_entry *input;
	struct core_packet_queue *prev, *next;
};

struct core_processing_thread {
	struct proto_process_stack stack[CORE_PROTO_STACK_MAX];
	int stack_index;
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t restart_cond; // Issued by the reader thread when there is a packet to process

};

int core_init(int num_threads);
int core_cleanup();

int core_spawn_reader_thread(struct input_client_entry *i);
int core_queue_packet(struct packet *p, struct input_client_entry *i);
void *core_processing_thread_func(void *priv);
int core_process_packet(struct packet *p);

void core_get_clock(struct timeval *now);
#endif
