/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2015 Guy Martin <gmsoft@tuxicoman.be>
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
#include <arpa/inet.h>

char *pom_strerror(int err_num) {

	static __thread char buff[POM_STRERROR_BUFF_SIZE];
	memset(buff, 0, POM_STRERROR_BUFF_SIZE);
	return strerror_r(err_num, buff, POM_STRERROR_BUFF_SIZE - 1);
}


void pom_oom_internal(size_t size, char *file, unsigned int line) {
	pomlog(POMLOG_ERR "Not enough memory to allocate %u bytes at %s:%u", size, file, line);
}

int pom_mkdir(const char *path) {

	char buffer[NAME_MAX + 1];
	buffer[NAME_MAX] = 0;
	strncpy(buffer, path, NAME_MAX);

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
					if (mkdir(buffer, 00777)) {
						pomlog(POMLOG_ERR "Error creating directory %s : %s", buffer, pom_strerror(errno));
						return POM_ERR;
					}
					break;
				default:
					return POM_ERR;
			}
		}
		*slash = '/';
		slash = strchr(slash + 1, '/');
	}

	return POM_OK;
}

int pom_open(const char *filename, int flags, mode_t mode) {

	if (strstr(filename, "..")) {
		pomlog(POMLOG_ERR "String '..' found in the filename");
		return -1;
	}

	if (pom_mkdir(filename) != POM_OK)
		return -1;

	return open(filename, flags, mode);
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

int pom_read(int fd, void *buf, size_t count) {

	size_t pos = 0;
	while (pos < count) {
		ssize_t len = read(fd, buf + pos, count - pos);
		if (len < 0) {
			pomlog(POMLOG_ERR "Read error : %s", pom_strerror(errno));
			return POM_ERR;
		} else if (!len) {
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

#ifndef bswap64

uint64_t bswap64(uint64_t x) {

#ifdef _LP64
	/*
	 * Assume we have wide enough registers to do it without touching
	 * memory.
	 */
	return  ( (x << 56) & 0xff00000000000000UL ) |
		( (x << 40) & 0x00ff000000000000UL ) |
		( (x << 24) & 0x0000ff0000000000UL ) |
		( (x <<  8) & 0x000000ff00000000UL ) |
		( (x >>  8) & 0x00000000ff000000UL ) |
		( (x >> 24) & 0x0000000000ff0000UL ) |
		( (x >> 40) & 0x000000000000ff00UL ) |
		( (x >> 56) & 0x00000000000000ffUL );
#else
	/*
	 * Split the operation in two 32bit steps.
	 */
	uint32_t tl, th;

	th = ntohl((uint32_t)(x & 0x00000000ffffffffULL));
	tl = ntohl((uint32_t)((x >> 32) & 0x00000000ffffffffULL));
	return ((uint64_t)th << 32) | tl;
#endif
}

#endif

char *pom_strnstr(char *haystack, char *needle, size_t len) {

	size_t needle_len = strlen(needle);
	if (len < needle_len)
		return NULL;

	
	char *start = NULL;
	while (len > 0) {
		start = memchr(haystack, *needle, len - needle_len + 1);
		if (!start)
			return NULL;

		size_t pos = start - haystack;
		if (len - pos < needle_len)
			return NULL;

		if (!memcmp(start, needle, needle_len))
			return start;
		haystack = start + 1;
		len -= pos + 1;
	}
	
	return NULL;
}


char *pom_undquote(char* dquoted_str, size_t len) {
	if (!len) {
		char *ret = malloc(1);
		if (!ret) {
			pom_oom(1);
			return NULL;
		}
		*ret = 0;
		return ret;
	}

	if (dquoted_str[0] != '"' || dquoted_str[len - 1] != '"')
		return strndup(dquoted_str, len);

	dquoted_str++;
	len -= 2;

	char *ret = malloc(len + 1);
	if (!ret) {
		pom_oom(len + 1);
		return NULL;
	}
	memset(ret, 0, len + 1);

	char *bslash = dquoted_str;
	char *otmp = ret;
	char *itmp = dquoted_str;
	size_t slen = len;

	while ((bslash = memchr(bslash, '\\', slen))) {
		char *escaped = bslash + 1;
		if (*escaped != '\\'  && *escaped != '"') {
			bslash++;
			slen -= bslash - itmp;
			continue;
		}
		size_t ltmp = bslash - itmp;
		memcpy(otmp, itmp, ltmp);
		otmp += ltmp;
		*otmp = *escaped;
		len -= ltmp + 2;
		itmp = bslash + 2;
		bslash = itmp;
		slen = len;
		otmp++;
	}

	memcpy(otmp, itmp, len);

	return ret;
}
