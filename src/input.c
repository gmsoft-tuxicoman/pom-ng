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

static key_t input_ipc_key;
static int running = 1;

static int input_is_current_process = 0;

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
