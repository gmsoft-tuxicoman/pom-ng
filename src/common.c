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
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

char *pom_strerror(int err_num) {

	static __thread char buff[POM_STRERROR_BUFF_SIZE];
	memset(buff, 0, POM_STRERROR_BUFF_SIZE);
	return strerror_r(err_num, buff, POM_STRERROR_BUFF_SIZE - 1);
}


void pom_oom_internal(size_t size, char *file, unsigned int line) {
	pomlog(POMLOG_ERR "Not enough memory to allocate %u bytes at %s:%u", size, file, line);
}


int pom_open(const char *filename, int flags, mode_t mode) {

	if (strstr(filename, "..")) {
		pomlog(POMLOG_ERR "String '..' found in the filename");
		return -1;
	}

	char buffer[NAME_MAX + 1];
	buffer[NAME_MAX] = 0;
	strncpy(buffer, filename, NAME_MAX);

	char *slash = buffer;
	if (*slash == '/') // we assume that the root directory exists :)
		slash++;
	
	slash = strchr(slash, '/');
	while (slash) {
		*slash = 0;
		struct stat stats;
		if (stat(buffer, &stats)) {
			switch (errno) {
				case ENOENT:
					mkdir(buffer, 00777);
					break;
				default:
					return -1;
			}
		}
		*slash = '/';
		slash = strchr(slash + 1, '/');
	}

	return open(buffer, flags, mode);
}

int pom_write(int fd, const void *buf, size_t count) {

	size_t pos = 0;
	while (pos < count) {
		ssize_t len = write(fd, buf + pos, count - pos);
		if (len < 0) {
			pomlog(POMLOG_ERR "Write error : %s", pom_strerror(errno));
			return POM_ERR;
		}
		pos += len;
	}

	return POM_OK;
}

int pom_mutex_init_type(pthread_mutex_t *lock, int type) {

	pthread_mutexattr_t attr;
	if (pthread_mutexattr_init(&attr)) {
		pomlog(POMLOG_ERR "Error while initializing mutex attribute : %s", pom_strerror(errno));
		return POM_ERR;
	}

	if (pthread_mutexattr_settype(&attr, type)) {
		pomlog(POMLOG_ERR "Error while setting mutex attribute type : %s", pom_strerror(errno));
		pthread_mutexattr_destroy(&attr);
		return POM_ERR;
	}

	if(pthread_mutex_init(lock, &attr)) {
		pomlog(POMLOG_ERR "Error while initializing a lock : %s", pom_strerror(errno));
		pthread_mutexattr_destroy(&attr);
		return POM_ERR;
	}

	if (pthread_mutexattr_destroy(&attr)) {
		pomlog(POMLOG_WARN "Error while destroying conntrack mutex attribute : %s", pom_strerror(errno));
		pthread_mutex_destroy(lock);
		return POM_ERR;
	}

	return POM_OK;
}

ptime pom_gettimeofday() {

	struct timeval now;
	gettimeofday(&now, NULL);
	return pom_timeval_to_ptime(now);
}

