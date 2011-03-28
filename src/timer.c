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

static struct timer_queue *timer_queues = NULL;


int timers_process() {

	struct timeval now;
	core_get_clock(&now);

	struct timer_queue *tq;
	tq = timer_queues;

	while (tq) {
		while (tq->head && timercmp(&tq->head->expires, &now, <)) {
				timer_tshoot( "Timer 0x%lx reached. Starting handler ...", (unsigned long) tq->head);
				(*tq->head->handler) (tq->head->priv);
		}
		tq = tq->next;

	}

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
		timer_queues = timer_queues->next;

		free(tmpq);
	}

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

	if (t->next || t->prev) {
		timer_dequeue(t);
	} else { // Timer could be alone in the list
		struct timer_queue *tq;
		tq = timer_queues;
		while (tq) {
			if (tq->head == t) {
				tq->head = NULL;
				tq->tail = NULL;
			}
			tq = tq->next;
		}
	}

	free(t);
	
	return POM_OK;
}

int timer_queue(struct timer *t, unsigned int expiry) {

	struct timer_queue *tq;
	tq = timer_queues;

	if (t->prev || t->next) {
		pomlog(POMLOG_WARN "Error, timer not dequeued correctly");
		return POM_ERR;
	}

	// First find the right queue or create it
	
	if (!tq) {

		// There is no queue yet
		tq = malloc(sizeof(struct timer_queue));
		if (!tq) {
			pom_oom(sizeof(struct timer_queue));
			return POM_ERR;
		}
		memset(tq, 0, sizeof(struct timer_queue));
		timer_queues = tq;

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

	return POM_OK;
}


int timer_dequeue(struct timer *t) {

	// First let's check if it's the one at the begining of the queue

	if (t->prev) {
		t->prev->next = t->next;
	} else {
		struct timer_queue *tq;
		tq = timer_queues;
		while (tq) {
			if (tq->head == t) {
				tq->head = t->next;

				// Let's see if the queue is empty
			
				/* WE SHOULD NOT TRY TO REMOVE QUEUES FROM THE QUEUE LIST
				if (!tq->head) { // If it is, remove that queue from the queue list
					timer_tshoot( "Removing queue 0x%lx from the queue list", (unsigned long) tq);
					if (tq->prev)
						tq->prev->next = tq->next;
					else
						timer_queues = tq->next;

					if (tq->next)
						tq->next->prev = tq->prev;


					free (tq);
					return POM_OK;
				}*/
				break;
			}
			tq = tq->next;
		}
		if (!tq)
			pomlog(POMLOG_WARN "Warning, timer 0x%lx not found in timers queues heads", (unsigned long) t);
	}

	if (t->next) {
		t->next->prev = t->prev;
	} else {
		struct timer_queue *tq;
		tq = timer_queues;
		while (tq) {
			if (tq->tail == t) {
				tq->tail = t->prev;
				break;
			}
			tq = tq->next;
		}
		if (!tq) 
			pomlog(POMLOG_WARN "Warning, timer 0x%lx not found in timers queues tails", (unsigned long) t);
	}


	// Make sure this timer will not reference anything

	t->prev = NULL;
	t->next = NULL;

	return POM_OK;
}
