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




#ifndef __INPUT_IPC__
#define __INPUT_IPC__

#include "input.h"

#define INPUT_IPC_LOG_FILE_NAME_SIZE 16
#define INPUT_IPC_LOG_MSG_SIZE 64

#define INPUT_IPC_MAX_READ_TYPE 0xff

enum input_ipc_msg_type {

	// Commands to the input

	input_ipc_cmd_type_add = 1,
};

union input_ipc_cmd_msg {

	struct add {
		int type;
		char name[INPUT_NAME_MAX + 1];
	} add;

};

struct input_ipc_raw_cmd {
	long type; // IPC_TYPE_INPUT_CMD
	enum input_ipc_msg_type subtype;
	int id;
	union input_ipc_cmd_msg data;
};

struct input_ipc_raw_cmd_reply {
	long type; // IPC_TYPE_INPUT_CMD_REPLY
	int id;
	int status;
};


struct input_ipc_request {

	int id;
	pthread_mutex_t mutex;
	struct input_ipc_raw_cmd_reply reply;

	struct input_ipc_request *next;
	struct input_ipc_request *prev;

};

int input_ipc_create_queue(key_t input_ipc_key);
int input_ipc_open_queue(key_t input_ipc_key);
int input_ipc_get_queue();
int input_ipc_set_uid_gid(int queue_id, uid_t uid, gid_t gid);
void *input_ipc_log_thread_func(void *params);
int input_ipc_reply_wait(int req_id, struct input_ipc_raw_cmd_reply **msg);
int input_ipc_destroy_request(int req_id);
int input_ipc_cleanup();

int input_ipc_send_request(int queue_id, struct input_ipc_raw_cmd *msg);
int input_ipc_process_reply(int queue_id);


void input_ipc_req_mutex_lock();
void input_ipc_req_mutex_unlock();


int input_ipc_cmd_add(int input_type, char *name);


#endif

