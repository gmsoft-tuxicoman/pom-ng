/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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



#ifndef __POMLOG_H__
#define __POMLOG_H__

#include <pom-ng/pomlog.h>

/// Log entry
struct pomlog_entry {

	uint32_t id; // Only valid if level < POM_LOG_TSHOOT
	char file[64];
	char *data;
	char level;
	struct timeval ts;

	struct pomlog_entry *main_prev, *main_next;
	struct pomlog_entry *lvl_prev, *lvl_next;

};

int pomlog_cleanup();
int pomlog_set_debug_level(unsigned int debug_level);

void pomlog_rlock();
void pomlog_unlock();
struct pomlog_entry *pomlog_get_tail();
int pomlog_poll(struct timespec *timeout);

#endif
