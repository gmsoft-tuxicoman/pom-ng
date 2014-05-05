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



#include "common.h"

#include "signal.h"

#include "xmlrpccmd.h"

#include <sys/msg.h>

static struct pomlog_entry *pomlog_head = NULL, *pomlog_tail = NULL;
static struct pomlog_entry *pomlog_lvl_head[4] = { 0 }, *pomlog_lvl_tail[4] = { 0 };
static unsigned int pomlog_buffer_size[4] = { 0 };
static pthread_rwlock_t pomlog_buffer_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint32_t pomlog_buffer_entry_id = 0;
static pthread_mutex_t pomlog_poll_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pomlog_poll_cond = PTHREAD_COND_INITIALIZER;


static unsigned int pomlog_debug_level = 3; // Default to POMLOG_INFO

void pomlog_internal(const char *file, const char *format, ...) {

	unsigned int level = *POMLOG_INFO;
	if (format[0] <= *POMLOG_DEBUG) {
		level = format[0];
		format++;
	}
	
	va_list arg_list;

	char buff[POMLOG_LINE_SIZE];
	memset(buff, 0, POMLOG_LINE_SIZE);
	va_start(arg_list, format);
	vsnprintf(buff, POMLOG_LINE_SIZE - 1, format, arg_list);
	va_end(arg_list);


	char *tmp = strrchr(file, '/');
	if (tmp)
		file = tmp + 1;

	char *dot = strchr(file, '.');
	unsigned int len = strlen(file);
	// Only remove extension for C files, not lua ones
	if (dot && *(dot + 1) == 'c') {
		unsigned int new_len = dot - file;
		if (new_len < len)
			len = new_len;
	}

	if (len >= POMLOG_FILENAME_SIZE)
		len = POMLOG_FILENAME_SIZE - 1;


	char filename[POMLOG_FILENAME_SIZE];
	memset(filename, 0, POMLOG_FILENAME_SIZE);
	strncpy(filename, file, len);

	if (pomlog_debug_level >= level)
		printf("%s: %s\n", filename, buff);

	struct pomlog_entry *entry;
	entry = malloc(sizeof(struct pomlog_entry));
	if (!entry) {
		// don't use pomlog here !
		pom_oom(sizeof(struct pomlog_entry));
		return;
	}
	memset(entry, 0, sizeof(struct pomlog_entry));

	strcpy(entry->file, filename);
	entry->data = strdup(buff);

	gettimeofday(&entry->ts, NULL);

	if (!entry->data) {
		pom_oom(strlen(buff));
		free(entry);
		return;
	}

	entry->level = level;


	int result = pthread_rwlock_wrlock(&pomlog_buffer_lock);
	if (result) {
		printf("Error while locking the log lock. Aborting.\r");
		abort();
		return; // never reached
	}

	entry->id = pomlog_buffer_entry_id++;

	entry->main_prev = pomlog_tail;
	if (entry->main_prev)
		entry->main_prev->main_next = entry;
	else
		pomlog_head = entry;
	pomlog_tail = entry;

	int queue = level - 1;

	entry->lvl_prev = pomlog_lvl_tail[queue];
	if (entry->lvl_prev)
		entry->lvl_prev->lvl_next = entry;
	else
		pomlog_lvl_head[queue] = entry;
	pomlog_lvl_tail[queue] = entry;

	pomlog_buffer_size[queue]++;

	while (pomlog_buffer_size[queue] > POMLOG_BUFFER_SIZE) {
		struct pomlog_entry *tmp = pomlog_lvl_head[queue];

		pomlog_lvl_head[queue] = tmp->lvl_next;
		pomlog_lvl_head[queue]->lvl_prev = NULL;

		if (tmp->main_next)
			tmp->main_next->main_prev = tmp->main_prev;
		else
			pomlog_tail = tmp->main_prev;

		if (tmp->main_prev)
			tmp->main_prev->main_next = tmp->main_next;
		else
			pomlog_head = tmp->main_next;

		free(tmp->data);
		free(tmp);


		pomlog_buffer_size[queue]--;
	}

	if (pthread_rwlock_unlock(&pomlog_buffer_lock)) {
		printf("Error while unlocking the log lock. Aborting.\r");
		abort();
	}

	pom_mutex_lock(&pomlog_poll_lock);
	result = pthread_cond_broadcast(&pomlog_poll_cond);
	if (result) {
		printf("Error while broadcasting the pomlog poll condition : %s\r", pom_strerror(result));
		abort();
	}
	pom_mutex_unlock(&pomlog_poll_lock);
}

int pomlog_cleanup() {

	while (pomlog_head) {
		struct pomlog_entry *tmp = pomlog_head;
		pomlog_head = pomlog_head->main_next;
		free(tmp->data);
		free(tmp);

	}
	
	pomlog_tail = NULL;

	return POM_OK;
}

void pomlog_finish() {
	pom_mutex_lock(&pomlog_poll_lock);
	pthread_cond_broadcast(&pomlog_poll_cond);
	pom_mutex_unlock(&pomlog_poll_lock);
}

int pomlog_set_debug_level(unsigned int debug_level) {

	if (debug_level > (unsigned int) *POMLOG_DEBUG)
		debug_level = *POMLOG_DEBUG;

	pomlog_debug_level = debug_level;

	return POM_OK;
}

void pomlog_rlock() {

	if (pthread_rwlock_rdlock(&pomlog_buffer_lock)) {
		printf("Error while locking the log lock.");
		abort();
	}
}

void pomlog_unlock() {
	if (pthread_rwlock_unlock(&pomlog_buffer_lock)) {
		printf("Error while unlocking the log lock.");
		abort();
	}
}

struct pomlog_entry *pomlog_get_tail() {
	return pomlog_tail;
}

int pomlog_poll(struct timespec *timeout) {

	pom_mutex_lock(&pomlog_poll_lock);

	int res = pthread_cond_timedwait(&pomlog_poll_cond, &pomlog_poll_lock, timeout);
	pom_mutex_unlock(&pomlog_poll_lock);

	if (res && res != ETIMEDOUT) {
		pomlog(POMLOG_ERR "Error while waiting for poll condition : %s", pom_strerror(res));
		abort();
	}

	return res;
}

