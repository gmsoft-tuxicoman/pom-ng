/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2015 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/core.h>
#include <pom-ng/proto.h>
#include <pom-ng/packet.h>
#include <pom-ng/input.h>
#include <pthread.h>

#define CORE_PROCESS_THREAD_MAX		64
#define CORE_PROCESS_THREAD_DEFAULT	1

#define CORE_THREAD_PKT_QUEUE_MIN	5
#define CORE_THREAD_PKT_QUEUE_MAX	512

#define CORE_REGISTRY "core"
enum core_state {
	core_state_idle = 0, // Core is idle
	core_state_running, // Core is receiving packets from the input
	core_state_finishing, // There are still packets in the input
};

struct core_packet_queue {
	struct packet *pkt;
	struct core_packet_queue *next;
};

struct core_processing_thread {
	pthread_t thread;
	unsigned int thread_id;
	unsigned int pkt_count;
	pthread_mutex_t pkt_queue_lock;
	pthread_cond_t pkt_queue_cond;
	struct core_packet_queue *pkt_queue_head, *pkt_queue_tail; // Thread's own queue
	struct core_packet_queue *pkt_queue_unused;

};

int core_init(unsigned int num_threads);
int core_cleanup(int emergency_cleanup);

int core_spawn_reader_thread(struct input *i);
void *core_processing_thread_func(void *priv);
int core_process_dump_pkt_info(struct proto_process_stack *s, struct packet *p, int res);
int core_process_packet_stack(struct proto_process_stack *s, unsigned int stack_index, struct packet *p);
int core_process_packet(struct packet *p);

void core_wait_state(enum core_state state);
enum core_state core_get_state();
int core_set_state(enum core_state state);

void core_pause_processing();
void core_resume_processing();

struct registry_perf *core_add_perf(const char *name, enum registry_perf_type type, const char *description, const char *unit);

unsigned int core_get_num_threads();

char *core_get_http_admin_password();

#endif
