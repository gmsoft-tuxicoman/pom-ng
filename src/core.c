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
#include "core.h"
#include "input.h"
#include "input_client.h"
#include "packet.h"
#include "conntrack.h"
#include "timer.h"
#include "main.h"

static int core_run = 0; // Set to 1 while the processing thread should run
static enum core_state core_cur_state = core_state_idle;
static pthread_mutex_t core_state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t core_state_cond = PTHREAD_COND_INITIALIZER;
static unsigned int core_thread_active = 0;
static struct timeval core_start_time;

static struct core_processing_thread *core_processing_threads[CORE_PROCESS_THREAD_MAX];
static pthread_rwlock_t core_processing_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct timeval core_clock;
static pthread_mutex_t core_clock_lock = PTHREAD_MUTEX_INITIALIZER;

// Packet queue
static struct core_packet_queue *core_pkt_queue_head = NULL, *core_pkt_queue_tail = NULL;
static struct core_packet_queue *core_pkt_queue_unused = NULL;
static unsigned int core_pkt_queue_usage = 0;
static pthread_cond_t core_pkt_queue_restart_cond;
static pthread_mutex_t core_pkt_queue_mutex = PTHREAD_MUTEX_INITIALIZER;


int core_init(int num_threads) {

	// Initialize the conditions for the sheduler thread
	if (pthread_cond_init(&core_pkt_queue_restart_cond, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing the restart condition : %s", pom_strerror(errno));
		return POM_ERR;
	}

	// Start the processing threads
	int num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (num_cpu < 1) {
		pomlog(POMLOG_WARN "Could not find the number of CPU, assuming %u", CORE_PROCESS_THREAD_DEFAULT);
		num_cpu = CORE_PROCESS_THREAD_DEFAULT;
	}

	if (num_threads < 1)
		num_threads = num_cpu;

	if (num_threads > num_cpu)
		pomlog(POMLOG_WARN "WARNING : Running more processing threads than available CPU is discouraged as it will cause issues by creating higher latencies and eventually dropping packets !!! You have been warned !");

	if (num_threads > CORE_PROCESS_THREAD_MAX)
		num_threads = CORE_PROCESS_THREAD_MAX;
	pomlog(POMLOG_INFO "Starting %u processing thread(s)", num_threads);

	core_run = 1;

	memset(core_processing_threads, 0, sizeof(struct core_processing_thread*) * CORE_PROCESS_THREAD_MAX);

	int i;

	for (i = 0; i < num_threads; i++) {
		struct core_processing_thread *tmp = malloc(sizeof(struct core_processing_thread));
		if (!tmp) {
			pom_oom(sizeof(struct core_processing_thread));
			goto err;
		}
		memset(tmp, 0, sizeof(struct core_processing_thread));
		
		if (pthread_mutex_init(&tmp->lock, NULL)) {
			pomlog(POMLOG_ERR "Error while initializing the processing thread's mutex : %s", pom_strerror(errno));
			free(tmp);
			goto err;
		}

		if (pthread_cond_init(&tmp->restart_cond, NULL)) {
			pomlog(POMLOG_ERR "Error while initializing processing thread's mutex condition : %s", pom_strerror(errno));
			pthread_mutex_destroy(&tmp->lock);
			free(tmp);
			goto err;
		}
		
		if (pthread_create(&tmp->thread, NULL, core_processing_thread_func, tmp)) {
			pomlog(POMLOG_ERR "Error while creating a new processing thread : %s", pom_strerror(errno));
			pthread_mutex_destroy(&tmp->lock);
			pthread_cond_destroy(&tmp->restart_cond);
			free(tmp);
			goto err;
		}


		core_processing_threads[i] = tmp;
	}

	return POM_OK;

err:
	core_cleanup(0);
	return POM_ERR;

}


int core_cleanup(int emergency_cleanup) {


	if (!emergency_cleanup) {
		while (core_pkt_queue_head) {
			pomlog("Waiting for all the packets to be processed");
			if (pthread_cond_broadcast(&core_pkt_queue_restart_cond)) {
				pomlog(POMLOG_ERR "Error while signaling the restart condition : %s", pom_strerror(errno));
				return POM_ERR;
			}
			sleep(1);
		}
	}

	core_run = 0;

	if (pthread_cond_broadcast(&core_pkt_queue_restart_cond)) {
		pomlog(POMLOG_ERR "Error while signaling the restart condition : %s", pom_strerror(errno));
		return POM_ERR;
	}

	int i;
	for (i = 0; i < CORE_PROCESS_THREAD_MAX && core_processing_threads[i]; i++) {
		pthread_join(core_processing_threads[i]->thread, NULL);
		pthread_cond_destroy(&core_processing_threads[i]->restart_cond);
		pthread_mutex_destroy(&core_processing_threads[i]->lock);
		free(core_processing_threads[i]);
	}

	pthread_cond_destroy(&core_pkt_queue_restart_cond);

	while (core_pkt_queue_head) {
		struct core_packet_queue *tmp = core_pkt_queue_head;
		core_pkt_queue_head = tmp->next;
		free(tmp);
		pomlog(POMLOG_WARN "A packet was still in the buffer");
	}

	while (core_pkt_queue_unused) {
		struct core_packet_queue *tmp = core_pkt_queue_unused;
		core_pkt_queue_unused = tmp->next;
		free(tmp);
	}

	
	return POM_OK;
}

int core_queue_packet(struct packet *p, struct input_client_entry *i) {

	pom_mutex_lock(&core_pkt_queue_mutex);

	while (core_pkt_queue_usage >= CORE_PKT_QUEUE_MAX) {
		// Queue full
		if (pthread_cond_wait(&core_pkt_queue_restart_cond, &core_pkt_queue_mutex)) {
			pomlog(POMLOG_ERR "Error while waiting for overrun mutex condition : %s", pom_strerror(errno));
			pom_mutex_unlock(&core_pkt_queue_mutex);
			return POM_ERR;
		}
	}

	struct core_packet_queue *tmp = NULL;

	if (core_pkt_queue_unused) {
		// Get a packet from the already allocated items
		tmp = core_pkt_queue_unused;
		core_pkt_queue_unused = tmp->next;
		if (core_pkt_queue_unused)
			core_pkt_queue_unused->prev = NULL;

	} else {
		// Allocate a new item
		tmp = malloc(sizeof(struct core_packet_queue));
		if (!tmp) {
			pom_mutex_unlock(&core_pkt_queue_mutex);
			pom_oom(sizeof(struct core_packet_queue));
			return POM_ERR;
		}

	}

	memset(tmp, 0, sizeof(struct core_packet_queue));
	tmp->pkt = p;
	tmp->input = i;
	core_pkt_queue_usage++;

	// Add the packet at the end of the queue
	if (core_pkt_queue_tail) {
		tmp->prev = core_pkt_queue_tail;
		core_pkt_queue_tail->next = tmp;
		core_pkt_queue_tail = tmp;
	} else {
		core_pkt_queue_head = tmp;
		core_pkt_queue_tail = tmp;
	}

	if (pthread_cond_broadcast(&core_pkt_queue_restart_cond)) {
		pomlog(POMLOG_ERR "Error while signaling restart condition : %s", pom_strerror(errno));
		pom_mutex_unlock(&core_pkt_queue_mutex);
		return POM_ERR;

	}

	pom_mutex_unlock(&core_pkt_queue_mutex);

	return POM_OK;
}


void *core_processing_thread_func(void *priv) {

	pom_mutex_lock(&core_pkt_queue_mutex);
	core_thread_active++;
	pom_mutex_unlock(&core_pkt_queue_mutex);

	while (core_run) {
		
		pom_mutex_lock(&core_pkt_queue_mutex);
		core_thread_active--;
		while (!core_pkt_queue_head) {
			enum core_state state = core_get_state();
			if (core_thread_active == 0) {
				if (state == core_state_finishing)
					core_set_state(core_state_idle);
			}

			if (!core_run) {
				pom_mutex_unlock(&core_pkt_queue_mutex);
				return NULL;
			}

			if (pthread_cond_wait(&core_pkt_queue_restart_cond, &core_pkt_queue_mutex)) {
				pomlog(POMLOG_ERR "Error while waiting for restart condition : %s", pom_strerror(errno));
				// Should probably abort here
				return NULL;
			}

		}
		core_thread_active++;
		struct core_packet_queue *tmp = core_pkt_queue_head;

		struct packet *pkt = tmp->pkt;

		// Remove the packet from the queue
		core_pkt_queue_head = tmp->next;
		if (core_pkt_queue_head)
			core_pkt_queue_head->prev = NULL;
		else
			core_pkt_queue_tail = NULL;

		// Add it to the unused list
		memset(tmp, 0, sizeof(struct core_packet_queue));
		tmp->next = core_pkt_queue_unused;
		if (tmp->next)
			tmp->next->prev = tmp;
		core_pkt_queue_unused = tmp;

		core_pkt_queue_usage--;

		pom_mutex_unlock(&core_pkt_queue_mutex);

		// Update the current clock
		pom_mutex_lock(&core_clock_lock);
		if ((pkt->ts.tv_sec > core_clock.tv_sec) ||
			((pkt->ts.tv_sec == core_clock.tv_sec) && (pkt->ts.tv_usec > core_clock.tv_sec))) {

			memcpy(&core_clock, &pkt->ts, sizeof(struct timeval));
		}
		pom_mutex_unlock(&core_clock_lock);

		// Lock the processing thread
		if (pthread_rwlock_rdlock(&core_processing_lock)) {
			pomlog(POMLOG_ERR "Error while locking the processing lock : %s", pom_strerror(errno));
			abort();
			return NULL;
		}
	
		// Process timers
		if (timers_process() != POM_OK) {
			pthread_rwlock_unlock(&core_processing_lock);
			return NULL;
		}


		//pomlog(POMLOG_DEBUG "Thread %u processing ...", pthread_self());
		if (core_process_packet(pkt) == POM_ERR) {
			halt("Packet processing encountered an error");
			pthread_rwlock_unlock(&core_processing_lock);
			return NULL;
		}

		if (pthread_rwlock_unlock(&core_processing_lock)) {
			pomlog(POMLOG_ERR "Error while releasing the processing lock : %s", pom_strerror(errno));
			break;
		}

		if (packet_pool_release(pkt) != POM_OK) {
			pomlog(POMLOG_ERR "Error while releasing the packet to the pool");
			break;
		}
		
		pom_mutex_lock(&core_pkt_queue_mutex);
		if (pthread_cond_broadcast(&core_pkt_queue_restart_cond)) {
			pomlog(POMLOG_ERR "Error while signaling the done condition : %s", pom_strerror(errno));
			pom_mutex_unlock(&core_pkt_queue_mutex);
			break;

		}
		pom_mutex_unlock(&core_pkt_queue_mutex);

	}

	halt("Processing thread encountered an error");
	return NULL;
}

int core_process_dump_pkt_info(struct proto_process_stack *s, int res) {
return POM_OK;

	char *res_str = "unknown result code";
	switch (res) {
		case PROTO_OK:
			res_str = "processed ok";
			break;
		case PROTO_INVALID:
			res_str = "invalid packet";
			break;
		case PROTO_STOP:
			res_str = "processing stopped";
			break;
	}

	printf("thread %u | ", (unsigned int)pthread_self());

	// Dump packet info
	int i;	
	for (i = 0; i < CORE_PROTO_STACK_MAX - 1 && s[i].proto; i++) {
		printf("%s { ", s[i].proto->info->name);
		int j;
		for (j = 0; s[i].proto->info->pkt_fields[j].name; j++) {
			char buff[256];
			ptype_print_val(s[i].pkt_info->fields_value[j], buff, sizeof(buff) - 1);
			printf("%s: %s; ", s[i].proto->info->pkt_fields[j].name, buff);
		}

		printf("}; ");
	}
	printf(": %s\n", res_str);

	return POM_OK;
}

int core_process_multi_packet(struct proto_process_stack *s, unsigned int stack_index, struct packet *p) {

	
	int res = core_process_packet_stack(s, stack_index, p);

	if (res != PROTO_ERR) {
		core_process_dump_pkt_info(s, res);
	}
	
	int i;
	// Cleanup pkt_info
	for (i = stack_index; i < CORE_PROTO_STACK_MAX - 1 && s[i].pkt_info; i++)
		packet_info_pool_release(&s[i].proto->pkt_info_pool, s[i].pkt_info);
	
	// Clean the stack
	memset(&s[stack_index], 0, sizeof(struct proto_process_stack) * (CORE_PROTO_STACK_MAX - stack_index));


	return res;
}

int core_process_packet_stack(struct proto_process_stack *stack, unsigned int stack_index, struct packet *p) {
	
	unsigned int i;

	for (i = stack_index; i < CORE_PROTO_STACK_MAX - 1; i++) {

		struct proto_process_stack *s = &stack[i];
		
		s->pkt_info = packet_info_pool_get(s->proto);

		int res = proto_process(p, stack, i);

		if (res == PROTO_ERR) {
			pomlog(POMLOG_ERR "Error while processing packet for proto %s", s->proto->info->name);
			return POM_ERR;
		} else if (res < 0)
			return res;
	
		struct proto_process_stack *s_next = &stack[i + 1];

		if (!s_next->proto)
			break;

		if ((s_next->pload > s_next->pload + s_next->plen) || // Check if next payload is further than the end of current paylod
			(s_next->pload < s->pload) || // Check if next payload is before the start of the current payload
			(s_next->pload + s_next->plen > s->pload + s->plen) || // Check if the end of the next payload is after the end of the current payload
			(s_next->pload + s_next->plen < s_next->pload)) { // Check for integer overflow
			// Invalid packet
			pomlog(POMLOG_INFO "Invalid parsing detected for proto %s", s->proto->info->name);
			break;
		}

	}
	
	return PROTO_OK;

}

int core_process_packet(struct packet *p) {

	struct proto_process_stack s[CORE_PROTO_STACK_MAX + 2]; // Add one entry at the begining and the end 

	memset(s, 0, sizeof(struct proto_process_stack) * (CORE_PROTO_STACK_MAX + 2));
	s[1].pload = p->buff;
	s[1].plen = p->len;
	s[1].proto = p->datalink;

	int res = core_process_packet_stack(s, 1, p);

	if (res == PROTO_OK)
		core_process_dump_pkt_info(s, res);

	// Cleanup pkt_info
	int i;
	for (i = 1; i < CORE_PROTO_STACK_MAX && s[i].pkt_info; i++)
			packet_info_pool_release(&s[i].proto->pkt_info_pool, s[i].pkt_info);
	if (res == PROTO_ERR)
		return PROTO_ERR;
	return PROTO_OK;
}

void core_get_clock(struct timeval *now) {

	pom_mutex_lock(&core_clock_lock);
	memcpy(now, &core_clock, sizeof(struct timeval));
	pom_mutex_unlock(&core_clock_lock);

}

void core_wait_state(enum core_state state) {
	pom_mutex_lock(&core_state_lock);
	while (core_cur_state != state) {
		if (pthread_cond_wait(&core_state_cond, &core_state_lock)) {
			pomlog(POMLOG_ERR "Error while waiting for core cond : %s", pom_strerror(errno));
			abort();
			break;
		}
	}
	pom_mutex_unlock(&core_state_lock);
}

enum core_state core_get_state() {

	pom_mutex_lock(&core_state_lock);
	enum core_state state = core_cur_state;
	pom_mutex_unlock(&core_state_lock);
	return state;
}

int core_set_state(enum core_state state) {

	pom_mutex_lock(&core_state_lock);
	core_cur_state = state;
	pomlog(POMLOG_DEBUG "Core state changed to %u", state);
	if (pthread_cond_broadcast(&core_state_cond)) {
		pomlog(POMLOG_ERR "Unable to signal core state condition : %s", pom_strerror(errno));
		pom_mutex_unlock(&core_state_lock);
		return POM_ERR;
	}

	if (state == core_state_idle) {
		struct timeval now;
		gettimeofday(&now, NULL);
		if (now.tv_usec < core_start_time.tv_usec) {
			now.tv_sec--;
			now.tv_usec += 1000000;
		}

		now.tv_usec -= core_start_time.tv_usec;
		now.tv_sec -= core_start_time.tv_sec;
		pomlog(POMLOG_DEBUG "Core was running for %u.%u secs", now.tv_sec, now.tv_usec);

	} else if (state == core_state_running) {
		gettimeofday(&core_start_time, NULL);
	} else if (state == core_state_finishing) {
		pom_mutex_lock(&core_pkt_queue_mutex);
		if (pthread_cond_broadcast(&core_pkt_queue_restart_cond)) {
			pom_mutex_unlock(&core_pkt_queue_mutex);
			pom_mutex_unlock(&core_state_lock);
			pomlog(POMLOG_ERR "Error while broadcasting restart condition after set state");
			return POM_ERR;
		}
		pom_mutex_unlock(&core_pkt_queue_mutex);
	}
	pom_mutex_unlock(&core_state_lock);
	return POM_OK;
}


void core_pause_processing() {

	if (pthread_rwlock_wrlock(&core_processing_lock)) {
		pomlog(POMLOG_ERR "Error while locking core processing lock : %s", pom_strerror(errno));
		abort();
	}
}

void core_resume_processing() {

	if (pthread_rwlock_unlock(&core_processing_lock)) {
		pomlog(POMLOG_ERR "Error while locking core processing lock : %s", pom_strerror(errno));
		abort();
	}
}
