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

#include "timer.h"
#include "common.h"
#include "core.h"
#include <pom-ng/registry.h>


#if 0
#define debug_timer(x...) pomlog(POMLOG_DEBUG x)
#else
#define debug_timer(x...)
#endif

static pthread_mutex_t timer_main_lock = PTHREAD_MUTEX_INITIALIZER;
static struct timer_queue *timer_queues = NULL;

static struct registry_perf *perf_timer_processed = NULL;
static struct registry_perf *perf_timer_queued = NULL;
static struct registry_perf *perf_timer_allocated = NULL;
static struct registry_perf *perf_timer_queues = NULL;

int timers_init() {

	perf_timer_processed = core_add_perf("timer_processed", registry_perf_type_counter, "Number of timers processeds", "timers");
	perf_timer_queued = core_add_perf("timer_queued", registry_perf_type_gauge, "Number of timers queued", "timers");
	perf_timer_allocated = core_add_perf("timer_allocated", registry_perf_type_gauge, "Number of timers allocated", "timers");
	perf_timer_queues = core_add_perf("timer_queues", registry_perf_type_gauge, "Number of timer queues", "queues");

	if (!perf_timer_processed || !perf_timer_queued || !perf_timer_allocated || !perf_timer_queues)
		return POM_OK;

	return POM_OK;
}

int timers_process() {


	static int processing = 0;

	int res = pthread_mutex_trylock(&timer_main_lock);
	if (res == EBUSY) {
		// Already locked, give up
		return POM_OK;
	} else if (res) {
		// Something went wrong
		pomlog(POMLOG_ERR "Error while trying to lock the main timer lock : %s", pom_strerror(res));
		abort();
		return POM_ERR;
	}

	// Another thread is already processing the timers, drop out
	if (processing) {
		pom_mutex_unlock(&timer_main_lock);
		return POM_OK;
	}

	processing = 1;

	ptime now = core_get_clock();

	struct timer_queue *tq;
	tq = timer_queues;

	while (tq) {
		while (tq->head && (tq->head->expires < now)) {
				
			// Dequeue the timer
			struct timer *tmp = tq->head;
			tq->head = tq->head->next;
			if (tq->head)
				tq->head->prev = NULL;
			else
				tq->tail = NULL;

			tmp->next = NULL;
			tmp->prev = NULL;
			tmp->queue = NULL;
			pom_mutex_unlock(&timer_main_lock);
			registry_perf_dec(perf_timer_queued, 1);

			// Process it
			debug_timer( "Timer 0x%lx reached. Starting handler ...", (unsigned long) tmp);
			if ((*tmp->handler) (tmp->priv, now) != POM_OK) {
				return POM_ERR;
			}

			registry_perf_inc(perf_timer_processed, 1);

			pom_mutex_lock(&timer_main_lock);

		}
		tq = tq->next;

	}

	processing = 0;

	pom_mutex_unlock(&timer_main_lock);

	return POM_OK;
}


int timers_cleanup() {


	// Free the timers

	while (timer_queues) {
		struct timer_queue *tmpq;
		tmpq = timer_queues;

		while (tmpq->head) {
			
			struct timer *tmp;
			tmp = tmpq->head;

			tmpq->head = tmpq->head->next;

			free(tmp);

			pomlog(POMLOG_WARN "Timer not dequeued");

		}
		timer_queues = timer_queues->next;

		free(tmpq);
	}

	return POM_OK;

}

struct timer *timer_alloc(void* priv, int (*handler) (void*, ptime)) {

	struct timer *t;
	t = malloc(sizeof(struct timer));
	if (!t) {
		pom_oom(sizeof(struct timer));
		return NULL;
	}
	memset(t, 0, sizeof(struct timer));

	t->priv = priv;
	t->handler = handler;

	registry_perf_inc(perf_timer_allocated, 1);

	return t;
}

int timer_cleanup(struct timer *t) {

	if (t->queue)
		timer_dequeue(t);

	free(t);
	
	registry_perf_dec(perf_timer_allocated, 1);

	return POM_OK;
}

int timer_queue(struct timer *t, unsigned int expiry) {

	pom_mutex_lock(&timer_main_lock);

	// Timer is still queued, dequeue it
	if (t->queue) {
		if (t->prev) {
			t->prev->next = t->next;
		} else {
			t->queue->head = t->next;
			if (t->queue->head)
				t->queue->head->prev = NULL;
		}

		if (t->next) {
			t->next->prev = t->prev;
		} else {
			t->queue->tail = t->prev;
			if (t->queue->tail)
				t->queue->tail->next = NULL;
			
		}
		t->queue = NULL;
		t->prev = NULL;
		t->next = NULL;
	} else {
		registry_perf_inc(perf_timer_queued, 1);
	}

	struct timer_queue *tq = timer_queues;

	// First find the right queue or create it
	
	if (!tq) {

		// There is no queue yet
		tq = malloc(sizeof(struct timer_queue));
		if (!tq) {
			pom_mutex_unlock(&timer_main_lock);
			pom_oom(sizeof(struct timer_queue));
			return POM_ERR;
		}
		memset(tq, 0, sizeof(struct timer_queue));
		timer_queues = tq;

		tq->expiry = expiry;

		registry_perf_inc(perf_timer_queues, 1);

	} else {

		while (tq) {
			
			if (tq->expiry == expiry) { // The right queue already exists
				
				break;

			} else if (tq->expiry > expiry) { // The right queue doesn't exists and we are too far in the list

				struct timer_queue *tmp;
				tmp = malloc(sizeof(struct timer_queue));
				if (!tmp) {
					pom_oom(sizeof(struct timer_queue));
					pom_mutex_unlock(&timer_main_lock);
					return POM_ERR;
				}
				memset(tmp, 0, sizeof(struct timer_queue));

				tmp->prev = tq->prev;
				tmp->next = tq;
				tq->prev = tmp;

				if (tmp->prev)
					tmp->prev->next = tmp;
				else
					timer_queues = tmp;


				tq = tmp;
				tq->expiry = expiry;

				registry_perf_inc(perf_timer_queues, 1);

				break;
			
			} else if (!tq->next) { // Looks like we are at the end of our list

				struct timer_queue *tmp;
				tmp = malloc(sizeof(struct timer_queue));
				if (!tmp) {
					pom_oom(sizeof(struct timer_queue));
					pom_mutex_unlock(&timer_main_lock);
					return POM_ERR;
				}
				memset(tmp, 0, sizeof(struct timer_queue));

				tmp->prev = tq;
				
				tq->next = tmp;

				tq = tmp;

				tq->expiry = expiry;

				registry_perf_inc(perf_timer_queues, 1);
				
				break;
			}

			tq = tq->next;
		}

	}

	// Now we can queue the timer
	
	if (tq->head == NULL) {
		tq->head = t;
		tq->tail = t;
	} else {
		t->prev = tq->tail;
		tq->tail = t;
		t->prev->next = t;
	}

	// Update the expiry time

	t->expires = core_get_clock();
	t->expires += expiry * 1000000UL;
	t->queue = tq;
	pom_mutex_unlock(&timer_main_lock);


	return POM_OK;
}


int timer_dequeue(struct timer *t) {

	// First let's check if it's the one at the begining of the queue

	pom_mutex_lock(&timer_main_lock);

	if (!t->queue) {
		pomlog(POMLOG_WARN "Warning, timer %p was already dequeued", t);
		pom_mutex_unlock(&timer_main_lock);
		return POM_OK;
	}

	if (t->prev) {
		t->prev->next = t->next;
	} else {
		t->queue->head = t->next;
		if (t->queue->head)
			t->queue->head->prev = NULL;
	}

	if (t->next) {
		t->next->prev = t->prev;
	} else {
		t->queue->tail = t->prev;
		if (t->queue->tail)
			t->queue->tail->next = NULL;
		
	}


	// Make sure this timer will not reference anything

	t->prev = NULL;
	t->next = NULL;
	t->queue = NULL;
	pom_mutex_unlock(&timer_main_lock);

	registry_perf_dec(perf_timer_queued, 1);

	return POM_OK;
}

