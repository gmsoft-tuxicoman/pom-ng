/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2011 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __POM_NG_BASE_H__
#define __POM_NG_BASE_H__

// Default return values
#define POM_OK 0
#define POM_ERR -1

// Defines for packet directions
#define POM_DIR_UNK -1
#define POM_DIR_FWD 0
#define POM_DIR_REV 1
#define POM_DIR_TOT 2 // Total number of possible directions

#define POM_DIR_REVERSE(x) ((x) == POM_DIR_FWD ? POM_DIR_REV : POM_DIR_FWD)

#include <pom-ng/pomlog.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#define POM_STRERROR_BUFF_SIZE 128

// Thread safe version of strerror()
char *pom_strerror(int err);

// Out of memory handler
void pom_oom_internal(size_t size, char *file, unsigned int line);
#define pom_oom(x) pom_oom_internal(x, __FILE__, __LINE__)

// Locking handlers
#define pom_mutex_lock(x) {												\
	if (pthread_mutex_lock(x)) {											\
		pomlog(POMLOG_ERR "Error while locking mutex in %s:%u : %s", __FILE__, __LINE__, pom_strerror(errno));	\
		abort();												\
	}														\
}															

#define pom_mutex_unlock(x) {													\
	if (pthread_mutex_unlock(x)) {												\
		pomlog(POMLOG_ERR "Error while unlocking mutex in %s:%u : %s", __FILE__, __LINE__, pom_strerror(errno));	\
		abort();													\
	}															\
}															

// Wrapper for write() that writes the whole buffer
int pom_write(int fd, const void *buf, size_t count);

#endif
