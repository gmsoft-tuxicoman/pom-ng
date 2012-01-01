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



#include "common.h"

#include "signal.h"

#include <sys/msg.h>

static struct pomlog_entry *pomlog_head = NULL, *pomlog_tail = NULL;
static unsigned int pomlog_buffer_size = 0;
static pthread_rwlock_t pomlog_buffer_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint32_t pomlog_buffer_entry_id = 0;


static unsigned int pomlog_debug_level = 3; // Default to POMLOG_INFO

void pomlog_internal(char *file, const char *format, ...) {



	int level = *POMLOG_INFO;
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
	if (dot) {
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

	if (!pomlog_tail) {
		pomlog_head = entry;
		pomlog_tail = entry;
	} else {
		entry->prev = pomlog_tail;
		pomlog_tail->next = entry;
		pomlog_tail = entry;
	}
	pomlog_buffer_size++;

	while (pomlog_buffer_size > POMLOG_BUFFER_SIZE) {
		struct pomlog_entry *tmp = pomlog_head;
		pomlog_head = pomlog_head->next;
		pomlog_head->prev = NULL;

		free(tmp->data);
		free(tmp);


		pomlog_buffer_size--;
	}

	if (pthread_rwlock_unlock(&pomlog_buffer_lock)) {
		printf("Error while unlocking the log lock. Aborting.\r");
		abort();
	}
}

int pomlog_cleanup() {

	while (pomlog_head) {
		struct pomlog_entry *tmp = pomlog_head;
		pomlog_head = pomlog_head->next;
		free(tmp->data);
		free(tmp);

	}
	
	pomlog_tail = NULL;

	return POM_OK;
}

int pomlog_set_debug_level(unsigned int debug_level) {

	if (debug_level > *POMLOG_DEBUG)
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



