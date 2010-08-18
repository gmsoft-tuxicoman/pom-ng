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

//#include <sys/ipc.h>
//#include <sys/msg.h>
//#include <sys/shm.h>
#include <signal.h>

#include "mod.h"
#include "ipc.h"
#include "input_ipc.h"
#include "input_server.h"
#include "ptype.h"


static key_t input_ipc_key;
static int input_server_running = 1;
static unsigned int input_server_list_cur_id = 0;
static int input_server_current_process = 0;

static pthread_rwlock_t input_server_list_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct input_list *input_server_list_head = NULL;

static void input_server_sighandler(int signal) {

	input_server_running = 0;
	printf("Input process received signal %u. Shutting down ...\n", signal);
}

int input_server_main(key_t ipc_key, uid_t main_uid, gid_t main_gid) {

	input_server_current_process = 1;

	pomlog_cleanup(); // Cleanup log entry from previous process

	pomlog("Input process started using uid/gid %u/%u and IPC key %u", geteuid(), getegid(), ipc_key);

	input_ipc_key = ipc_key;

	// Install signal handler
	struct sigaction mysigaction;
	sigemptyset(&mysigaction.sa_mask);
	mysigaction.sa_flags = 0;
	mysigaction.sa_handler = input_server_sighandler;
	sigaction(SIGINT, &mysigaction, NULL);
	sigaction(SIGTERM, &mysigaction, NULL);


	// Check if IPC queue already exists
	int qid = input_ipc_open_queue(ipc_key);
	if (qid == -1) {
		pomlog(POMLOG_ERR "Unable to create message queue");
		return -1;
	}

	// Load relevant modules
	mod_load_all();

	// Main input process loop
	while (input_server_running) {

		struct input_ipc_raw_cmd cmd;

		if (ipc_read_msg(qid, IPC_TYPE_INPUT_CMD, &cmd, sizeof(struct input_ipc_raw_cmd)) != POM_OK) {
			if (errno == EINTR)
				continue;
			pomlog(POMLOG_ERR "Error while reading from the IPC queue for input commands");
			break;
		}

		if (cmd.type != IPC_TYPE_INPUT_CMD) {
			pomlog("Command type invalid : %u!", cmd.type);
			break;
		}


		int res = POM_ERR;

		struct input_ipc_raw_cmd_reply cmd_reply;
		memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
		cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
		cmd_reply.id = cmd.id;
		cmd_reply.status = POM_ERR;

		switch (cmd.subtype) {
			case input_ipc_cmd_type_mod_load:
				res = input_server_cmd_mod_load(&cmd);
				break;

			case input_ipc_cmd_type_add: 
				res = input_server_cmd_add(&cmd, main_uid, main_gid);
				break;

			case input_ipc_cmd_type_get_param:
				res = input_server_cmd_get_param(&cmd);
				break;

			case input_ipc_cmd_type_remove:
				res = input_server_cmd_remove(&cmd);
				break;

			case input_ipc_cmd_type_start: 
				res = input_server_cmd_start(&cmd);
				break;

			case input_ipc_cmd_type_stop: 
				res = input_server_cmd_stop(&cmd);
				break;

			default:
				break;
		}

		if (res != POM_OK) {
			pomlog(POMLOG_ERR "Error while sending reply for input command");
			break;
		}

	}

	// Cleanup input list
	input_server_list_lock(1);

	struct input_list *l;
	while (input_server_list_head) {
		l = input_server_list_head;
		input_server_list_head = l->next;

		pomlog("Cleaning up input %u (%s)", l->id, l->i->type->info->name);
		if (l->i->running)
			input_close(l->i);
		input_cleanup(l->i);
		free(l);
	}


	input_server_list_unlock();

	mod_unload_all();

	pomlog("Input process terminated cleanly");


	return 0;
}

int input_server_cmd_mod_load(struct input_ipc_raw_cmd *cmd) {

	struct input_ipc_raw_cmd_reply cmd_reply;
	memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
	cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
	cmd_reply.id = cmd->id;
	if (mod_load(cmd->data.mod_load.name))
		cmd_reply.status = POM_OK;

	return ipc_send_msg(input_ipc_get_queue(), &cmd_reply, sizeof(struct input_ipc_raw_cmd_reply));

}

int input_server_cmd_add(struct input_ipc_raw_cmd *cmd, uid_t uid, gid_t gid) {

	struct input_ipc_raw_cmd_reply cmd_reply;
	memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
	cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
	cmd_reply.id = cmd->id;
	cmd_reply.status = POM_ERR;

	struct input_list *l = malloc(sizeof(struct input_list));
	if (!l) {
		pom_oom(sizeof(struct input_list));
		goto err;
	}
	memset(l, 0, sizeof(struct input_list));
	l->i = input_alloc(cmd->data.add.name, input_ipc_key, uid, gid);
	if (!l->i) {
		pomlog("Error while allocating input %s", cmd->data.add.name);
		free(l);
		goto err;
	}

	input_server_list_lock(1);

	l->next = input_server_list_head;
	if (l->next)
		l->next->prev = l;
	input_server_list_head = l;
	input_server_list_cur_id++;
	if (input_server_list_cur_id == POM_ERR)
		input_server_list_cur_id++;
	l->id = input_server_list_cur_id;

	input_server_list_unlock();

	cmd_reply.data.add.id = l->id;
	cmd_reply.data.add.shm_key = l->i->shm_key;
	cmd_reply.data.add.shm_buff_size = l->i->shm_buff_size;
	cmd_reply.status = POM_OK;

err:

	return ipc_send_msg(input_ipc_get_queue(), &cmd_reply, sizeof(struct input_ipc_raw_cmd_reply));

}

int input_server_cmd_get_param(struct input_ipc_raw_cmd *cmd) {

	struct input_ipc_raw_cmd_reply cmd_reply;
	memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
	cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
	cmd_reply.id = cmd->id;
	cmd_reply.status = POM_ERR;


	// Find the right input
	input_server_list_lock(0);
	if (cmd->data.get_param.param_id < 0)
		goto err;
	
	struct input_list *l = input_server_list_head;
	for (; l && l->id != cmd->data.get_param.input_id; l = l->next);
	if (!l) 
		goto err;

	struct input_param *p = l->i->params;
	int i;
	for (i = 0; p && i < cmd->data.get_param.param_id; i++)
		p = p->next;

	if (!p) 
		goto err;

	memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
	cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
	cmd_reply.id = cmd->id;
	cmd_reply.status = POM_OK;

	strncpy(cmd_reply.data.get_param.name, p->name, INPUT_PARAM_NAME_MAX - 1);
	strncpy(cmd_reply.data.get_param.defval, p->default_value, INPUT_PARAM_DEFVAL_MAX - 1);
	strncpy(cmd_reply.data.get_param.description, p->description, INPUT_PARAM_DESCRIPTION_MAX - 1);
	strncpy(cmd_reply.data.get_param.type, ptype_get_name(p->value), INPUT_PARAM_TYPE_MAX - 1);
	cmd_reply.data.get_param.flags = p->flags;
	if (!p->next)
		cmd_reply.data.get_param.last = 1;


err:
	input_server_list_unlock();
	return ipc_send_msg(input_ipc_get_queue(), &cmd_reply, sizeof(struct input_ipc_raw_cmd_reply));

}


int input_server_cmd_remove(struct input_ipc_raw_cmd *cmd) {

	struct input_ipc_raw_cmd_reply cmd_reply;
	memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
	cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
	cmd_reply.id = cmd->id;
	cmd_reply.status = POM_ERR;

	input_server_list_lock(1);
	struct input_list *l;
	for (l = input_server_list_head; l && l->id != cmd->data.remove.id; l = l->next);
	if (!l) {
		pomlog(POMLOG_ERR "Input with id %u not found", cmd->data.remove.id);
		goto err;
	}
	pomlog("Cleaning up input %u", l->id);
	if (input_cleanup(l->i) != POM_OK) {
		pomlog(POMLOG_ERR "Error while cleaning up input %u", l->id);
		goto err;
	}

	if (l->prev) {
		l->prev->next = l->next;
	} else {
		input_server_list_head = l->next;
		if (input_server_list_head)
			input_server_list_head->prev = NULL;
	}
	if (l->next)
		l->next->prev = l->prev;

	free(l);
	cmd_reply.status = POM_OK;

err:
	input_server_list_unlock();
	return ipc_send_msg(input_ipc_get_queue(), &cmd_reply, sizeof(struct input_ipc_raw_cmd_reply));
}

int input_server_cmd_start(struct input_ipc_raw_cmd *cmd) {

	struct input_ipc_raw_cmd_reply cmd_reply;
	memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
	cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
	cmd_reply.id = cmd->id;
	cmd_reply.status = POM_ERR;

	input_server_list_lock(1);
	struct input_list *l;
	for (l = input_server_list_head; l && l->id != cmd->data.start.id; l = l->next);
	if (!l) {
		pomlog(POMLOG_ERR "List with id %u not found", cmd->data.start.id);
		input_server_list_unlock();
		goto err;
	}
	cmd_reply.status = input_open(l->i);

	struct input_caps ic;
	memset(&ic, 0, sizeof(struct input_caps));
	if (input_get_caps(l->i, &ic) == POM_ERR) {
		pomlog(POMLOG_ERR "Unable to get the input caps");
		input_close(l->i);
		cmd_reply.status = POM_ERR;
		goto err;
	}

	strncpy(cmd_reply.data.start_reply.datalink, ic.datalink, INPUT_IPC_DATALINK_MAX);

err:
	input_server_list_unlock();
	return ipc_send_msg(input_ipc_get_queue(), &cmd_reply, sizeof(struct input_ipc_raw_cmd_reply));
}

int input_server_cmd_stop(struct input_ipc_raw_cmd *cmd) {

	struct input_ipc_raw_cmd_reply cmd_reply;
	memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
	cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
	cmd_reply.id = cmd->id;
	cmd_reply.status = POM_ERR;

	input_server_list_lock(1);
	struct input_list *l;
	for (l = input_server_list_head; l && l->id != cmd->data.start.id; l = l->next);
	if (!l) {
		pomlog(POMLOG_ERR "List with id %u not found", cmd->data.start.id);
		input_server_list_unlock();
		goto err;
	}
	cmd_reply.status = input_close(l->i);


err:
	input_server_list_unlock();
	return ipc_send_msg(input_ipc_get_queue(), &cmd_reply, sizeof(struct input_ipc_raw_cmd_reply));
}


void input_server_list_lock(int write) {
	
	int res = 0;
	
	if (write)
		res = pthread_rwlock_wrlock(&input_server_list_rwlock);
	else
		res = pthread_rwlock_rdlock(&input_server_list_rwlock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking the input_list lock : %s", pom_strerror(errno));
		abort();
	}

}

void input_server_list_unlock() {

	if (pthread_rwlock_unlock(&input_server_list_rwlock)) {
		pomlog(POMLOG_ERR "Error while unlocking the input_list lock : %s", pom_strerror(errno));
		abort();
	}

}



int input_server_is_current_process() {
	return input_server_current_process;
}
