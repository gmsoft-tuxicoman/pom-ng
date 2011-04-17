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


#ifndef __TIMER_H__
#define __TIMER_H__

#include <pom-ng/timer.h>

struct timer_queue {

	unsigned int expiry;
	struct timer_queue *next;
	struct timer_queue *prev;
	struct timer *head;
	struct timer *tail;

};



int timers_process();
int timers_cleanup();

void timer_queue_lock(struct timer_queue *q, int write);
void timer_queue_unlock(struct timer_queue *q);


#endif
