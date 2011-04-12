/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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


#if 0
#define timer_tshoot(x...) pomlog(POMLOG_TSHOOT x)
#else
#define timer_tshoot(x...)
#endif

static pthread_rwlock_t timer_main_lock = PTHREAD_RWLOCK_INITIALIZER;
static struct timer_queue *timer_queues = NULL;


int timers_process() {

	struct timeval now;
	core_get_clock(&now);

	timer_queues_lock(0);

	struct timer_queue *tq;
	tq = timer_queues;

	while (tq) {
		timer_queue_lock(tq, 0);
		while (tq->head && timercmp(&tq->head->expires, &now, <)) {
				timer_tshoot( "Timer 0x%lx reached. Starting handler ...", (unsigned long) tq->head);
				(*tq->head->handler) (tq->head->priv);
		}
		timer_queue_unlock(tq);
		tq = tq->next;

	}

	timer_queues_unlock(0);

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

		}
		pthread_rwlock_destroy(&tmpq->lock);
		timer_queues = timer_queues->next;

		free(tmpq);
	}

	pthread_rwlock_destroy(&timer_main_lock);
	return POM_OK;

}

struct timer *timer_alloc(void* priv, int (*handler) (void*)) {

	struct timer *t;
	t = malloc(sizeof(struct timer));
	if (!t) {
		pom_oom(sizeof(struct timer));
		return NULL;
	}
	memset(t, 0, sizeof(struct timer));

	t->priv = priv;
	t->handler = handler;

	return t;
}

int timer_cleanup(struct timer *t) {

	if (t->queue)
		timer_dequeue(t);

	free(t);
	
	return POM_OK;
}

int timer_queue(struct timer *t, unsigned int expiry) {

	if (t->prev || t->next) {
		pomlog(POMLOG_WARN "Error, timer not dequeued correctly");
		return POM_ERR;
	}

	timer_queues_lock(1);

	struct timer_queue *tq = timer_queues;

	// First find the right queue or create it
	
	if (!tq) {

		// There is no queue yet
		tq = malloc(sizeof(struct timer_queue));
		if (!tq) {
			timer_queues_unlock();
			pom_oom(sizeof(struct timer_queue));
			return POM_ERR;
		}
		memset(tq, 0, sizeof(struct timer_queue));
		timer_queues = tq;
		if (pthread_rwlock_init(&tq->lock, NULL)) {
			timer_queues_unlock();
			pomlog(POMLOG_ERR "Unable to initialize timer queue lock");
			free(tq);
			return POM_ERR;
		}

		tq->expiry = expiry;

	} else {

		while (tq) {
			
			if (tq->expiry == expiry) { // The right queue already exists
				
				break;

			} else if (tq->expiry > expiry) { // The right queue doesn't exists and we are too far in the list

				struct timer_queue *tmp;
				tmp = malloc(sizeof(struct timer_queue));
				if (!tmp) {
					pom_oom(sizeof(struct timer_queue));
					timer_queues_unlock();
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

				break;
			
			} else if (!tq->next) { // Looks like we are at the end of our list

				struct timer_queue *tmp;
				tmp = malloc(sizeof(struct timer_queue));
				if (!tmp) {
					pom_oom(sizeof(struct timer_queue));
					timer_queues_unlock();
					return POM_ERR;
				}
				memset(tmp, 0, sizeof(struct timer_queue));

				tmp->prev = tq;
				
				tq->next = tmp;

				tq = tmp;

				tq->expiry = expiry;
				
				break;
			}

			tq = tq->next;
		}

	}

	timer_queue_lock(tq, 1);
	timer_queues_unlock();
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

	core_get_clock(&t->expires);
	t->expires.tv_sec += expiry;
	t->queue = tq;

	timer_queue_unlock(tq);
	return POM_OK;
}


int timer_dequeue(struct timer *t) {

	// First let's check if it's the one at the begining of the queue

	if (!t->queue) {
		pomlog(POMLOG_WARN "Warning, timer 0x%p was already dequeued", t);
		return POM_OK;
	}

	timer_queue_lock(t->queue, 1);


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
	timer_queue_unlock(t->queue);
	t->queue = NULL;


	return POM_OK;
}

void timer_queues_lock(int write) {

	int res = 0;
	if (write)
		res = pthread_rwlock_wrlock(&timer_main_lock);
	else
		res = pthread_rwlock_rdlock(&timer_main_lock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking timer queues lock : %s", pom_strerror(errno));
		abort();
	}

}

void timer_queues_unlock() {

	int res = pthread_rwlock_unlock(&timer_main_lock);

	if (res) {
		pomlog(POMLOG_ERR "Error while unlocking timer queues lock : %s", pom_strerror(errno));
		abort();
	}

}

void timer_queue_lock(struct timer_queue *q, int write) {

	int res = 0;
	if (write)
		res = pthread_rwlock_wrlock(&q->lock);
	else
		res = pthread_rwlock_rdlock(&q->lock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking timer queue lock : %s", pom_strerror(errno));
		abort();
	}
}

void timer_queue_unlock(struct timer_queue *q) {

	int res = pthread_rwlock_unlock(&q->lock);

	if (res) {
		pomlog(POMLOG_ERR "Error while unlocking timer queues lock : %s", pom_strerror(errno));
		abort();
	}

}
