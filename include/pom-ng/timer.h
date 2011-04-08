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


#ifndef __POM_NG_TIMER_H__
#define __POM_NG_TIMER_H__

#include <pom-ng/base.h>

#include <time.h>
#include <sys/time.h>

struct timer {

	struct timeval expires;
	void *priv;
	int (*handler) (void *);
	struct timer *next;
	struct timer *prev;

};


struct timer *timer_alloc(void* priv, int (*handler) (void*));
int timer_cleanup(struct timer *t);
int timer_queue(struct timer *t, unsigned int expiry);
int timer_dequeue(struct timer *t);


#endif
