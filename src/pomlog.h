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



#ifndef __POMLOG_H__
#define __POMLOG_H__

#include <pom-ng/pomlog.h>

/// IPC log message
struct pomlog_ipc_msg {
	long type; // IPC_TYPE_LOG
	int log_level;
	char filename[POMLOG_FILENAME_SIZE];
	char line[POMLOG_LINE_SIZE];
};

/// Log entry

struct pomlog_entry {

	uint32_t id; // Only valid if level < POM_LOG_TSHOOT
	char file[64];
	char *data;
	char level;

	struct pomlog_entry *prev;
	struct pomlog_entry *next;

};

int pomlog_ipc(int log_level, char *filename, char *line);
int pomlog_ipc_thread_init(int *ipc_queue);
int pomlog_cleanup();

// Declared in <pom-ng/pomlog.h>
// void pomlog_internal(char *file, const char *format, ...);
// int pomlog_ipc_internal(int queue_id, char *filename, const char *format, ...);

#endif
