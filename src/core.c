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
#include "core.h"
#include "input.h"
#include "packet.h"
#include "conntrack.h"
#include "timer.h"
#include "main.h"
#include "proto.h"
#include "dns.h"

#include <pom-ng/ptype_bool.h>

static int core_run = 0; // Set to 1 while the processing thread should run
static enum core_state core_cur_state = core_state_idle;
static pthread_mutex_t core_state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t core_state_cond = PTHREAD_COND_INITIALIZER;
static unsigned int core_thread_active = 0;
static ptime core_start_time;

static struct core_processing_thread *core_processing_threads[CORE_PROCESS_THREAD_MAX];
static int core_num_threads = 0;
static pthread_rwlock_t core_processing_lock = PTHREAD_RWLOCK_INITIALIZER;

static ptime core_clock[CORE_PROCESS_THREAD_MAX];
static pthread_mutex_t core_clock_lock = PTHREAD_MUTEX_INITIALIZER;

static struct registry_class *core_registry_class = NULL;
static struct ptype *core_param_dump_pkt = NULL, *core_param_offline_dns = NULL, *core_param_reset_perf_on_restart = NULL;

// Packet queue
static struct core_packet_queue *core_pkt_queue_head = NULL, *core_pkt_queue_tail = NULL;
static struct core_packet_queue *core_pkt_queue_unused = NULL;
static unsigned int core_pkt_queue_usage = 0;
static pthread_cond_t core_pkt_queue_restart_cond;
static pthread_mutex_t core_pkt_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

// Perf objects
struct registry_perf *perf_pkt_queue = NULL;
struct registry_perf *perf_thread_active = NULL;


int core_init(int num_threads) {

	core_registry_class = registry_add_class(CORE_REGISTRY);
	if (!core_registry_class)
		return POM_ERR;

	perf_pkt_queue = registry_class_add_perf(core_registry_class, "pkt_queue", registry_perf_type_gauge, "Number of packets in the queue waiting to be processed", "pkts");
	perf_thread_active = registry_class_add_perf(core_registry_class, "active_thread", registry_perf_type_gauge, "Number of active threads", "threads");

	if (!perf_pkt_queue || !perf_thread_active)
		return POM_OK;

	core_param_dump_pkt = ptype_alloc("bool");
	if (!core_param_dump_pkt)
		return POM_ERR;

	core_param_offline_dns = ptype_alloc("bool");
	if (!core_param_offline_dns) {
		ptype_cleanup(core_param_dump_pkt);
		core_param_dump_pkt = NULL;
		return POM_ERR;
	}

	core_param_reset_perf_on_restart = ptype_alloc("bool");
	if (!core_param_reset_perf_on_restart) {
		ptype_cleanup(core_param_dump_pkt);
		core_param_dump_pkt = NULL;
		ptype_cleanup(core_param_offline_dns);
		core_param_offline_dns = NULL;
		return POM_ERR;
	}

	struct registry_param *param = registry_new_param("dump_pkt", "no", core_param_dump_pkt, "Dump packets to logs", REGISTRY_PARAM_FLAG_CLEANUP_VAL);
	if (registry_class_add_param(core_registry_class, param) != POM_OK)
		goto err;

	param = registry_new_param("offline_dns", "yes", core_param_offline_dns, "Enable offline DNS resolver", REGISTRY_PARAM_FLAG_CLEANUP_VAL);
	if (registry_class_add_param(core_registry_class, param) != POM_OK)
		goto err;

	param = registry_new_param("reset_perf_on_restart", "no", core_param_reset_perf_on_restart, "Reset performances when core restarts", REGISTRY_PARAM_FLAG_CLEANUP_VAL);
	if (registry_class_add_param(core_registry_class, param) != POM_OK)
		goto err;
	
	param = NULL;

	// Initialize the conditions for the sheduler thread
	if (pthread_cond_init(&core_pkt_queue_restart_cond, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing the restart condition : %s", pom_strerror(errno));
		goto err;
	}

	// Initialize the clock table
	memset(core_clock, 0, sizeof(core_clock));

	// Start the processing threads
	int num_cpu = sysconf(_SC_NPROCESSORS_ONLN) - 1;
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

	core_num_threads = num_threads;	
	pomlog(POMLOG_INFO "Starting %u processing thread(s)", core_num_threads);

	core_run = 1;

	memset(core_processing_threads, 0, sizeof(struct core_processing_thread*) * CORE_PROCESS_THREAD_MAX);

	int i;

	for (i = 0; i < core_num_threads; i++) {
		struct core_processing_thread *tmp = malloc(sizeof(struct core_processing_thread));
		if (!tmp) {
			pom_oom(sizeof(struct core_processing_thread));
			goto err;
		}
		memset(tmp, 0, sizeof(struct core_processing_thread));

		tmp->thread_id = i;

		if (pthread_create(&tmp->thread, NULL, core_processing_thread_func, tmp)) {
			pomlog(POMLOG_ERR "Error while creating a new processing thread : %s", pom_strerror(errno));
			free(tmp);
			goto err;
		}


		core_processing_threads[i] = tmp;
	}

	return POM_OK;

err:

	if (param)
		registry_cleanup_param(param);

	core_cleanup(0);
	return POM_ERR;

}


int core_cleanup(int emergency_cleanup) {

	core_run = 0;

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

	if (pthread_cond_broadcast(&core_pkt_queue_restart_cond)) {
		pomlog(POMLOG_ERR "Error while signaling the restart condition : %s", pom_strerror(errno));
		return POM_ERR;
	}

	int i;
	for (i = 0; i < CORE_PROCESS_THREAD_MAX && core_processing_threads[i]; i++) {
		pthread_join(core_processing_threads[i]->thread, NULL);
		free(core_processing_threads[i]);
	}

	pthread_cond_destroy(&core_pkt_queue_restart_cond);

	while (core_pkt_queue_head) {
		struct core_packet_queue *tmp = core_pkt_queue_head;
		core_pkt_queue_head = tmp->next;
		packet_pool_release(tmp->pkt);
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

int core_queue_packet(struct packet *p, unsigned int flags, unsigned int thread_affinity) {

	
	// Update the counters
	struct input *i = p->input;
	registry_perf_inc(i->perf_pkts_in, 1);
	registry_perf_inc(i->perf_bytes_in, p->len);

	pom_mutex_lock(&core_pkt_queue_mutex);

	while (core_pkt_queue_usage >= CORE_PKT_QUEUE_MAX) {
		// Queue full
		if (pthread_cond_wait(&core_pkt_queue_restart_cond, &core_pkt_queue_mutex)) {
			pomlog(POMLOG_ERR "Error while waiting for overrun mutex condition : %s", pom_strerror(errno));
			pom_mutex_unlock(&core_pkt_queue_mutex);
			return POM_ERR;
		}

		if (!core_run) {
			// We cleaned up early
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
	core_pkt_queue_usage++;
	registry_perf_inc(perf_pkt_queue, 1);

	if (flags & CORE_QUEUE_HAS_THREAD_AFFINITY) {
	
		int affinity_thread = thread_affinity % core_num_threads;
		struct core_processing_thread *t = core_processing_threads[affinity_thread];
	
		if (t->pkt_queue_tail) {
			tmp->prev = t->pkt_queue_tail;
			t->pkt_queue_tail->next = tmp;
			t->pkt_queue_tail = tmp;
		} else {
			t->pkt_queue_head = tmp;
			t->pkt_queue_tail = tmp;
		}

	} else {

		// Add the packet at the end of the shared queue
		if (core_pkt_queue_tail) {
			tmp->prev = core_pkt_queue_tail;
			core_pkt_queue_tail->next = tmp;
			core_pkt_queue_tail = tmp;
		} else {
			core_pkt_queue_head = tmp;
			core_pkt_queue_tail = tmp;
		}

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

	struct core_processing_thread *tpriv = priv;

	pom_mutex_lock(&core_pkt_queue_mutex);

	while (core_run) {
		
		while (!core_pkt_queue_head && !tpriv->pkt_queue_head) {
			if (core_thread_active == 0) {
				if (core_get_state() == core_state_finishing)
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
		registry_perf_inc(perf_thread_active, 1);

		struct core_packet_queue *tmp = NULL;
		
		// Dequeue packets from our own queue first
		struct packet *pkt = NULL;
		if (tpriv->pkt_queue_head) {
			tmp = tpriv->pkt_queue_head;
			pkt = tmp->pkt;

			tpriv->pkt_queue_head = tmp->next;
			if (tpriv->pkt_queue_head)
				tpriv->pkt_queue_head->prev = NULL;
			else
				tpriv->pkt_queue_tail = NULL;

		} else {
			tmp = core_pkt_queue_head;
			pkt = tmp->pkt;

			// Remove the packet from the main queue
			core_pkt_queue_head = tmp->next;
			if (core_pkt_queue_head)
				core_pkt_queue_head->prev = NULL;
			else
				core_pkt_queue_tail = NULL;
		}

		// Add it to the unused list
		memset(tmp, 0, sizeof(struct core_packet_queue));
		tmp->next = core_pkt_queue_unused;
		if (tmp->next)
			tmp->next->prev = tmp;
		core_pkt_queue_unused = tmp;

		core_pkt_queue_usage--;
		registry_perf_dec(perf_pkt_queue, 1);

		pom_mutex_unlock(&core_pkt_queue_mutex);

		// Lock the processing thread
		if (pthread_rwlock_rdlock(&core_processing_lock)) {
			pomlog(POMLOG_ERR "Error while locking the processing lock : %s", pom_strerror(errno));
			abort();
			return NULL;
		}

		// Update the current clock
		pom_mutex_lock(&core_clock_lock);
		core_clock[tpriv->thread_id] = pkt->ts;
		pom_mutex_unlock(&core_clock_lock);

		//pomlog(POMLOG_DEBUG "Thread %u processing ...", pthread_self());
		if (core_process_packet(pkt) == POM_ERR) {
			core_run = 0;
			halt("Packet processing encountered an error", 1);
			pthread_cond_broadcast(&core_pkt_queue_restart_cond);
			pthread_rwlock_unlock(&core_processing_lock);
			return NULL;
		}

		// Process timers
		if (timers_process() != POM_OK) {
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
		core_thread_active--;
		registry_perf_dec(perf_thread_active, 1);

	}
	pom_mutex_unlock(&core_pkt_queue_mutex);

	halt("Processing thread encountered an error", 1);
	return NULL;
}

int core_process_dump_info(struct proto_process_stack *s, struct packet *p, int res) {

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
		case PROTO_ERR:
			res_str = "processing encountered an error";
			break;
	}

	static pthread_mutex_t debug_lock = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&debug_lock);
	printf("thread %u | %u.%u | ", (unsigned int)pthread_self(), (int)pom_ptime_sec(p->ts), (int)pom_ptime_usec(p->ts));

	// Dump packet info
	int i;	
	for (i = 1; i < CORE_PROTO_STACK_MAX - 1 && s[i].proto; i++) {
		printf("%s { ", s[i].proto->info->name);
	
		char buff[256];

		if (s[i].pkt_info) {

			if (s[i].proto->info->pkt_fields) {
				int j;
				for (j = 0; s[i].proto->info->pkt_fields[j].name; j++) {
					ptype_print_val(s[i].pkt_info->fields_value[j], buff, sizeof(buff) - 1);
					printf("%s: %s; ", s[i].proto->info->pkt_fields[j].name, buff);
				}
			}
		} else {
			printf("pkt_info missing ");
		}

		printf("}; ");
	}
	printf(": %s\n", res_str);
	pthread_mutex_unlock(&debug_lock);

	return POM_OK;
}

int core_process_multi_packet(struct proto_process_stack *s, unsigned int stack_index, struct packet *p) {

	
	int res = core_process_packet_stack(s, stack_index, p);

	char *dump_pkt = PTYPE_BOOL_GETVAL(core_param_dump_pkt);
	if (*dump_pkt)
		core_process_dump_info(s, p, res);
	
	// Clean the stack
	memset(&s[stack_index], 0, sizeof(struct proto_process_stack) * (CORE_PROTO_STACK_MAX - stack_index));


	return res;
}

int core_process_packet_stack(struct proto_process_stack *stack, unsigned int stack_index, struct packet *p) {

	unsigned int i;
	int res = PROTO_OK;

	for (i = stack_index; i < CORE_PROTO_STACK_MAX - CORE_PROTO_STACK_START; i++) {

		struct proto_process_stack *s = &stack[i];

		if (!s->proto)
			break;
	
		if (s->proto->info->pkt_fields) {
			if (s->pkt_info)
				pomlog(POMLOG_WARN "Packet info already allocated !");
			s->pkt_info = packet_info_pool_get(s->proto);
		}

		res = proto_process(p, stack, i);

		if (res == PROTO_ERR)
			pomlog(POMLOG_ERR "Error while processing packet for proto %s", s->proto->info->name);

		if (res < 0)
			break;

		struct proto_process_stack *s_next = &stack[i + 1];

		if (!s_next->pload)
			break;
	
	}

	// Process packet listeners
	if (res == PROTO_OK) {
		int j, min = stack_index - 1;
		for (j = i; j >= min; j--) {
			if (proto_process_listeners(p, stack, j) != POM_OK) {
				res = PROTO_ERR;
				break;
			}
		}
	}


	for (; i >= stack_index; i--) {

		if (!stack[i].proto)
			continue;
		
		if (res >= 0) {
			if (proto_post_process(p, stack, i) == POM_ERR) {
				pomlog(POMLOG_ERR "Error while post processing packet for proto %s", stack[stack_index].proto->info->name);
				res = PROTO_ERR;
			}
		}

		if (stack[i].ce)
			conntrack_refcount_dec(stack[i].ce);

		packet_info_pool_release(&stack[i].proto->pkt_info_pool, stack[i].pkt_info);
	}
	
	return res;

}

int core_process_packet(struct packet *p) {

	struct proto_process_stack s[CORE_PROTO_STACK_MAX + 2]; // Add one entry at the begining and the end 

	memset(s, 0, sizeof(struct proto_process_stack) * (CORE_PROTO_STACK_MAX + 2));
	s[CORE_PROTO_STACK_START].pload = p->buff;
	s[CORE_PROTO_STACK_START].plen = p->len;
	s[CORE_PROTO_STACK_START].proto = p->datalink;

	int res = core_process_packet_stack(s, CORE_PROTO_STACK_START, p);

	char *dump_pkt = PTYPE_BOOL_GETVAL(core_param_dump_pkt);
	if (*dump_pkt)
		core_process_dump_info(s, p, res);

	if (res == PROTO_ERR)
		return PROTO_ERR;

	return PROTO_OK;
}

struct proto_process_stack *core_stack_backup(struct proto_process_stack *stack, struct packet* old_pkt, struct packet *new_pkt) {

	struct proto_process_stack *new_stack = malloc(sizeof(struct proto_process_stack) * (CORE_PROTO_STACK_MAX + 2));
	if (!new_stack) {
		pom_oom(sizeof(struct proto_process_stack) * (CORE_PROTO_STACK_MAX + 2));
		return NULL;
	}

	memcpy(new_stack, stack, sizeof(struct proto_process_stack) * (CORE_PROTO_STACK_MAX + 2));
	
	int i;
	for (i = 0; i < CORE_PROTO_STACK_MAX + 2; i++) {
		// Clone pkt_info
		if (stack[i].proto && stack[i].pkt_info) {
			new_stack[i].pkt_info = packet_info_pool_clone(stack[i].proto, stack[i].pkt_info);
			if (!new_stack[i].pkt_info) {
				for (; i; i--) {
					if (new_stack[i].pkt_info)
						packet_info_pool_release(&stack[i].proto->pkt_info_pool, new_stack[i].pkt_info);
				}
				free(new_stack);
				return NULL;
			}
		}
		
		// Adjust pload pointer
		if (stack[i].pload && old_pkt->buff != new_pkt->buff)
			new_stack[i].pload = new_pkt->buff + (stack[i].pload - old_pkt->buff);
	}

	return new_stack;
}

ptime core_get_clock() {

	pom_mutex_lock(&core_clock_lock);

	ptime *now = &core_clock[0];

	// Take only the least recent time
	int i;
	for (i = 1; i < core_num_threads; i++) {
		if (*now > core_clock[i])
			now = &core_clock[i];
	}

	pom_mutex_unlock(&core_clock_lock);

	return *now;
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

// Placeholder for all the stuff to do when processing starts
static int core_processing_start() {

	if (*PTYPE_BOOL_GETVAL(core_param_offline_dns) && dns_init() != POM_OK)
		return POM_ERR;

	if (*PTYPE_BOOL_GETVAL(core_param_reset_perf_on_restart))
		registry_perf_reset_all();

	return POM_OK;
}

// Placeholder for all the stuff to do when processing stops
static int core_processing_stop() {

	if (*PTYPE_BOOL_GETVAL(core_param_offline_dns))
		dns_cleanup();

	// Free all the conntracks
	proto_empty_conntracks();

	return POM_OK;
}

int core_set_state(enum core_state state) {

	int res = POM_OK;

	pom_mutex_lock(&core_state_lock);
	core_cur_state = state;
	pomlog(POMLOG_DEBUG "Core state changed to %u", state);
	if (pthread_cond_broadcast(&core_state_cond)) {
		pomlog(POMLOG_ERR "Unable to signal core state condition : %s", pom_strerror(errno));
		pom_mutex_unlock(&core_state_lock);
		return POM_ERR;
	}

	if (state == core_state_idle) {

		res = core_processing_stop();

		ptime now = pom_gettimeofday();

		pom_mutex_lock(&core_clock_lock);
		memset(&core_clock, 0, sizeof(core_clock));
		pom_mutex_unlock(&core_clock_lock);

		ptime runtime = now - core_start_time;

		pomlog(POMLOG_INFO "Core was running for %u.%06u secs", pom_ptime_sec(runtime), pom_ptime_usec(runtime));

	} else if (state == core_state_running) {
		core_start_time = pom_gettimeofday();
		res = core_processing_start();
	} else if (state == core_state_finishing) {
		//pom_mutex_lock(&core_pkt_queue_mutex);
		if (pthread_cond_broadcast(&core_pkt_queue_restart_cond)) {
			pom_mutex_unlock(&core_pkt_queue_mutex);
			pom_mutex_unlock(&core_state_lock);
			pomlog(POMLOG_ERR "Error while broadcasting restart condition after set state");
			return POM_ERR;
		}
		//pom_mutex_unlock(&core_pkt_queue_mutex);
	}
	pom_mutex_unlock(&core_state_lock);
	return res;
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
