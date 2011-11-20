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

#define INPUT_IPC_DATALINK_MAX 64

#define INPUT_IPC_LOG_FILE_NAME_SIZE 16
#define INPUT_IPC_LOG_MSG_SIZE 64
#define INPUT_IPC_MOD_FILE_NAME_SIZE 64

#define INPUT_IPC_MAX_READ_TYPE 0xff

enum input_ipc_msg_type {

	// Commands to the input
	input_ipc_cmd_type_mod_load = 1,
	input_ipc_cmd_type_mod_unload,
	input_ipc_cmd_type_add,
	input_ipc_cmd_type_get_param,
	input_ipc_cmd_type_set_param,
	input_ipc_cmd_type_remove,
	input_ipc_cmd_type_start,
	input_ipc_cmd_type_stop,
	input_ipc_cmd_type_halt,
};

union input_ipc_cmd_msg {

	struct mod_load {
		char name[INPUT_IPC_MOD_FILE_NAME_SIZE + 1];
	} mod_load;

	struct mod_unload {
		char name[INPUT_IPC_MOD_FILE_NAME_SIZE + 1];
	} mod_unload;

	struct add {
		char name[INPUT_NAME_MAX + 1];
	} add;

	struct get_param {
		int input_id;
		int param_id;
	} get_param;

	struct set_param {
		int input_id;
		int param_id;
		char value[INPUT_PARAM_VALUE_MAX + 1];
	} set_param;

	struct start {
		unsigned int id;
	} start;

	struct stop {
		unsigned int id;
	} stop;
	
	struct remove {
		unsigned int id;
	} remove;

};

struct input_ipc_raw_cmd {
	long type; // IPC_TYPE_INPUT_CMD
	enum input_ipc_msg_type subtype;
	int id;
	union input_ipc_cmd_msg data;
};

union input_ipc_cmd_reply_msg {
	struct add_reply {
		unsigned int id;
		int shm_key;
		size_t shm_buff_size;
	} add;

	struct start_reply {
		char datalink[INPUT_IPC_DATALINK_MAX + 1];
	} start_reply;

	struct get_param_reply {
		char name[INPUT_PARAM_NAME_MAX];
		char defval[INPUT_PARAM_DEFVAL_MAX];
		char description[INPUT_PARAM_DESCRIPTION_MAX];
		char type[INPUT_PARAM_TYPE_MAX];
		int flags;
		int last;
	} get_param;
};

struct input_ipc_raw_cmd_reply {
	long type; // IPC_TYPE_INPUT_CMD_REPLY
	int id;
	int status;
	union input_ipc_cmd_reply_msg data;
};


struct input_ipc_request {

	int id;
	int replied;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	struct input_ipc_raw_cmd_reply reply;

	struct input_ipc_request *next;
	struct input_ipc_request *prev;

};

struct input_ipc_processing_thread_priv {
	int *input_ipc_queue;
	int *running;
};

int input_ipc_create_queue(key_t input_ipc_key);
int input_ipc_open_queue(key_t input_ipc_key);
int input_ipc_get_queue();
int input_ipc_set_uid_gid(int queue_id, uid_t uid, gid_t gid);
void *input_ipc_log_thread_func(void *params);

int input_ipc_create_processing_thread(pthread_t *thread, int *input_ipc_queue, int *running);
void *input_ipc_processing_thread_func(void *priv);

int input_ipc_reply_wait(int req_id, struct input_ipc_raw_cmd_reply **msg);
int input_ipc_destroy_request(int req_id);
int input_ipc_server_halt();
int input_ipc_cleanup();

int input_ipc_send_request(int queue_id, struct input_ipc_raw_cmd *msg);
int input_ipc_process_reply(int queue_id);


#endif

