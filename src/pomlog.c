/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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
#include "ipc.h"
#include "input_ipc.h"

#include "signal.h"

#include <sys/msg.h>

static struct pomlog_entry *pomlog_head = NULL, *pomlog_tail = NULL;
static unsigned int pomlog_buffer_size = 0;
static pthread_rwlock_t pomlog_buffer_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint32_t pomlog_buffer_entry_id = 0;
static pthread_t pomlog_input_ipc_thread;


static int pomlog_debug_level = 3; // Default to POMLOG_INFO

static void *pomlog_ipc_thread_func(void *params) {

	int *queue_id = params;

	struct pomlog_ipc_msg ipcmsg;

	while (1) {
		if (ipc_read_msg(*queue_id, IPC_TYPE_LOG, &ipcmsg, sizeof(struct pomlog_ipc_msg))) {
			pomlog(POMLOG_ERR "Error while reading logs from input process");
			return NULL;
		}

		char format[] = "x<IPC> %s";
		format[0] = ipcmsg.log_level;
		pomlog_internal(ipcmsg.filename, format, ipcmsg.line);
	

	}

	return NULL;
}

int pomlog_ipc_thread_init(int *ipc_queue) {

	// Create the thread to process logs from IPC
	if (pthread_create(&pomlog_input_ipc_thread, NULL, pomlog_ipc_thread_func, (void*) ipc_queue)) {
		pomlog(POMLOG_ERR "Error while creating the input IPC log thread. Aborting");
		return POM_ERR;
	}

	return POM_OK;

}

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


	char *dot = strchr(file, '.');
	unsigned int len = strlen(file);
	if (dot) {
		unsigned int new_len = dot - file;
		if (new_len < len)
			len = new_len;
	}

	if (input_current_process()) {
		// We are running in the input process, we must send the log via IPC
		if (pomlog_ipc(level, file, buff) != POM_OK) {
			printf("<IPC LOG ERR> : %s", buff);

		}

		return;

	}

	if (len >= POMLOG_FILENAME_SIZE) {
		len = POMLOG_FILENAME_SIZE - 1;
		file[POMLOG_FILENAME_SIZE] = 0;
	}

	int result = pthread_rwlock_wrlock(&pomlog_buffer_lock);
	if (result) {
		printf("Error while locking the log lock. Aborting.\r");
		abort();
		return; // never reached
	}


	if (pomlog_debug_level >= level)
		printf("%s: %s\n", file, buff);

	struct pomlog_entry *entry;
	entry = malloc(sizeof(struct pomlog_entry));
	if (!entry) {
		// don't use pomlog here !
		printf("Not enough memory to allocate struct pomlog_entry, log entry dropped");
		return;
	}
	memset(entry, 0, sizeof(struct pomlog_entry));

	strncpy(entry->file, file, len);
	entry->data = strdup(buff);

	entry->level = level;
	entry->id = pomlog_buffer_entry_id;
	pomlog_buffer_entry_id++;

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
		return; // never reached
	}
}

int pomlog_ipc(int log_level, char *filename, char *line) {

	struct pomlog_ipc_msg ipcmsg;
	memset(&ipcmsg, 0, sizeof(struct pomlog_ipc_msg));
	ipcmsg.type = IPC_TYPE_LOG;

	ipcmsg.log_level = log_level;
	strncpy(ipcmsg.line, line, POMLOG_LINE_SIZE - 1);
	strncpy(ipcmsg.filename, filename, POMLOG_FILENAME_SIZE - 1);


	if (ipc_send_msg(input_ipc_get_queue(), &ipcmsg, sizeof(struct pomlog_ipc_msg)) == POM_ERR) {
		char *line = ipcmsg.line;
		if (*line <= *POMLOG_DEBUG)
			line++;
		pomlog(POMLOG_ERR "Error while sending log via IPC. msg : \"%s\"", line);
		return POM_ERR;
	}

	return POM_OK;

}

int pomlog_cleanup() {

	if (!input_current_process()) {

		// Stop the IPC log thread
		pomlog("Stopping input IPC log thread");
		pthread_kill(pomlog_input_ipc_thread, SIGINT);
		pthread_join(pomlog_input_ipc_thread, NULL);
	}

	pomlog("Cleaning up logs ...");
	while (pomlog_head) {
		struct pomlog_entry *tmp = pomlog_head;
		pomlog_head = pomlog_head->next;
		free(tmp->data);
		free(tmp);

	}
	
	pomlog_tail = NULL;

	return POM_OK;
}
