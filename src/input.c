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

#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>

#include "input.h"
#include "ipc.h"
#include "input_ipc.h"
#include "mod.h"

static key_t input_ipc_key;
static int running = 1;

static int input_is_current_process = 0;

static pthread_rwlock_t input_reg_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct input_reg *input_reg_head = NULL;

static void input_sighandler(int signal) {

	running = 0;

	printf("Signal received.\n");
}

int input_current_process() {
	return input_is_current_process;
}

int input_main(key_t ipc_key, uid_t main_uid, gid_t main_gid) {

	input_is_current_process = 1;
	pomlog_cleanup(); // Cleanup log entry from previous process

	pomlog("Input process started using uid/gid %u/%u and IPC key %u", geteuid(), getegid(), ipc_key);

	input_ipc_key = ipc_key;

	// Install signal handler
	struct sigaction mysigaction;
	sigemptyset(&mysigaction.sa_mask);
	mysigaction.sa_flags = 0;
	mysigaction.sa_handler = input_sighandler;
	sigaction(SIGINT, &mysigaction, NULL);
	sigaction(SIGTERM, &mysigaction, NULL);


	// Check if IPC queue already exists
	int qid = input_ipc_open_queue(ipc_key);
	if (qid == -1) {
		pomlog(POMLOG_ERR "Unable to create message queue");
		return -1;
	}

	// Main input process loop
	while (running) {

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

		struct input_ipc_raw_cmd_reply cmd_reply;
		memset(&cmd_reply, 0, sizeof(struct input_ipc_raw_cmd_reply));
		cmd_reply.type = IPC_TYPE_INPUT_CMD_REPLY;
		cmd_reply.id = cmd.id;
		cmd_reply.status = POM_OK;

		if (ipc_send_msg(qid, &cmd_reply, sizeof(struct input_ipc_raw_cmd_reply)) != POM_OK) {
			pomlog(POMLOG_ERR "Error while sending reply for input command");
			break;
		}

		sleep(1);
	}


	pomlog("Input process terminated cleanly");


	return 0;
}


int input_register(struct input_reg_info *reg_info, struct mod_reg *mod) {

	pomlog("Registering input %s", reg_info->name);

	if (reg_info->api_ver != INPUT_API_VER) {
		pomlog(POMLOG_ERR "API version of input %s does not match : expected %s got %s", reg_info->name, INPUT_API_VER, reg_info->api_ver);
		return POM_ERR;
	}

	struct input_reg *reg = malloc(sizeof(struct input_reg));
	if(!reg) {
		pomlog(POMLOG_ERR "Not enough memory to allocate struct input_reg");
		return POM_ERR;
	}

	memset(reg, 0, sizeof(struct input_reg));

	input_reg_lock(1);

	struct input_reg *tmp;
	for (tmp = input_reg_head; tmp && strcmp(tmp->info->name, reg_info->name); tmp = tmp->next);
	if (tmp) {
		pomlog(POMLOG_ERR "Input %s already registered", reg_info->name);
		free(reg);
		input_reg_unlock();
		return POM_ERR;
	}

	reg->info = reg_info;
	reg->module = mod;

	mod_refcount_inc(mod);

	reg->next = input_reg_head;
	input_reg_head = reg;
	if (reg->next)
		reg->next->prev = reg;

	input_reg_unlock();

	return POM_OK;

}

struct input* input_alloc(const char* type, char* unit) {

	input_reg_lock(1);

	struct input_reg *reg;
	for (reg = input_reg_head; reg && strcmp(reg->info->name, type); reg = reg->next);

	if (!reg) {
		input_reg_unlock();
		pomlog(POMLOG_ERR "Input of type %s not found", type);
		return NULL;
	}
	
	struct input *ret = malloc(sizeof(struct input));
	if (!ret) {
		input_reg_unlock();
		pomlog(POMLOG_ERR "Not enough memory to allocate input %s", type);
		return NULL;
	}

	memset(ret, 0, sizeof(struct input));
	ret->type = reg;
	if (reg->info->alloc) {
		if (reg->info->alloc(ret) != POM_OK) {
			input_reg_unlock();
			pomlog(POMLOG_ERR "Error while allocating input %s", type);
			free(ret);
			return NULL;
		}
	}

	reg->refcount++;
	input_reg_unlock();


	return ret;
}

int input_unregister(char *name) {


	input_reg_lock(1);
	struct input_reg *reg;

	for (reg = input_reg_head; reg && strcmp(reg->info->name, name); reg = reg->next);
	if (!reg) {
		pomlog(POMLOG_WARN "Input %s is not registered, cannot unregister it.", name);
		input_reg_unlock();
		return POM_OK; // Do not return an error so module unloading proceeds
	}

	if (reg->refcount) {
		pomlog(POMLOG_WARN "Cannot unregister input %s as it's still in use", name);
		input_reg_unlock();
		return POM_ERR;
	}

	if (reg->prev)
		reg->prev->next = reg->next;
	else
		input_reg_head = reg->next;
	
	if (reg->next)
		reg->next->prev = reg->prev;

	reg->next = NULL;
	reg->prev = NULL;

	mod_refcount_dec(reg->module);

	input_reg_unlock();

	return POM_OK;
}


void input_reg_lock(int write) {
	
	int res = 0;
	
	if (write)
		res = pthread_rwlock_wrlock(&input_reg_rwlock);
	else
		res = pthread_rwlock_rdlock(&input_reg_rwlock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking the input_reg lock");
		abort();
	}

}

void input_reg_unlock() {

	if (pthread_rwlock_unlock(&input_reg_rwlock)) {
		pomlog(POMLOG_ERR "Error while unlocking the input_reg lock");
		abort();
	}

}
