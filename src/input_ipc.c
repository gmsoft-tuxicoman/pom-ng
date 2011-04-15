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
#include "input.h"
#include "ipc.h"
#include "input_ipc.h"

#include <pthread.h>

static unsigned int input_ipc_req_cur_id = 0;
static struct input_ipc_request *input_ipc_reqs = NULL;
static pthread_mutex_t input_ipc_req_mutex = PTHREAD_MUTEX_INITIALIZER;

static int input_ipc_queue = -1;

int input_ipc_create_queue(key_t input_ipc_key) {

	input_ipc_queue = msgget(input_ipc_key, IPC_CREAT | 0600);
	if (input_ipc_queue == -1)
		return POM_ERR;

	return input_ipc_queue;
}

int input_ipc_open_queue(key_t input_ipc_key) {

	if (input_ipc_key == -1) {

		// Wait for the IPC queue to be created
		do {
			input_ipc_queue = (msgget(input_ipc_key, 0));
			if (input_ipc_queue == -1) {
				switch (errno) {
					case EIDRM:
						pomlog(POMLOG_WARN "Current IPC queue is marked for deletion, waiting ...");
						break;
					case ENOENT:
						pomlog(POMLOG_WARN "Input IPC queue doesn't not exists yet, waiting ...");
						break;
					case EPERM:
						pomlog(POMLOG_ERR "Permission denied on the input IPC queue. Aborting !");
						return -1;
					default:
						pomlog(POMLOG_ERR "Error while trying to get the IPC queue. Aborting !");
						return -1;
				}

			}
			sleep(1);

		} while (input_ipc_queue == -1);
	}

	return input_ipc_queue;

}
int input_ipc_get_queue() {
	return input_ipc_queue;
}

int input_ipc_set_uid_gid(int queue_id, uid_t uid, gid_t gid) {

	struct msqid_ds data;
	if (msgctl(queue_id, IPC_STAT, &data)) {
		pomlog(POMLOG_ERR "Error while getting input queue data");
		return POM_ERR;
	}

	data.msg_perm.uid = uid;
	data.msg_perm.gid = gid;

	if (msgctl(queue_id, IPC_SET, &data)) {
		pomlog(POMLOG_ERR "Error while setting permissions on the input queue");
		return POM_ERR;
	}

	return POM_OK;
}



int input_ipc_send_request(int queue_id, struct input_ipc_raw_cmd *msg) {

	msg->type = IPC_TYPE_INPUT_CMD; // Make sure the type is ok	
	struct input_ipc_request *req = malloc(sizeof(struct input_ipc_request));
	if (!req) {
		pomlog(POMLOG_ERR "Not enough memory to allocate struct input_ipc_request");
		return POM_ERR;
	}

	memset(req, 0, sizeof(struct input_ipc_request));
	pthread_mutex_init(&req->mutex, NULL);
	pthread_cond_init(&req->cond, NULL);

	pom_mutex_lock(&input_ipc_req_mutex);

	req->id = input_ipc_req_cur_id;
	msg->id = input_ipc_req_cur_id;
	input_ipc_req_cur_id++;
	if (input_ipc_req_cur_id < 0)
		input_ipc_req_cur_id = 0;

	if (ipc_send_msg(queue_id, msg, sizeof(struct input_ipc_raw_cmd)) != POM_OK) {
		pomlog(POMLOG_ERR "Failed to send IPC message");
		free(req);
		pom_mutex_unlock(&input_ipc_req_mutex);
		return POM_ERR;
	}

	if (input_ipc_reqs)
		input_ipc_reqs->prev = req;
	
	req->next = input_ipc_reqs;
	if (req->next)
		req->next->prev = req;
	input_ipc_reqs = req;

	pom_mutex_unlock(&input_ipc_req_mutex);

	pomlog(POMLOG_DEBUG "Sent input IPC request %u", req->id);

	return req->id;
}

int input_ipc_process_reply(int queue_id) {

	struct input_ipc_raw_cmd_reply msg;

	while (ipc_read_msg(queue_id, IPC_TYPE_INPUT_CMD_REPLY, &msg, sizeof(struct input_ipc_raw_cmd_reply)) == POM_OK) {

		// Find that request in the request backlog
		
		pom_mutex_lock(&input_ipc_req_mutex);
		struct input_ipc_request *req = input_ipc_reqs;
		for (; req && req->id != msg.id; req = req->next);
		
		if (!req) {
			pomlog(POMLOG_ERR "IPC request %u not found in the queue !", msg.id);
			pom_mutex_unlock(&input_ipc_req_mutex);
			return POM_OK;
		}

		pom_mutex_lock(&req->mutex);
		pom_mutex_unlock(&input_ipc_req_mutex);


		memcpy(&req->reply, &msg, sizeof(struct input_ipc_raw_cmd_reply));

		req->replied = 1;

		pomlog(POMLOG_DEBUG "Processing request %u", req->id);
		pthread_cond_broadcast(&req->cond);
		pom_mutex_unlock(&req->mutex);

	

	}

	return POM_OK;

}

int input_ipc_reply_wait(int req_id, struct input_ipc_raw_cmd_reply **msg) {

	pom_mutex_lock(&input_ipc_req_mutex);

	struct input_ipc_request *req = input_ipc_reqs;

	for (; req && req->id != req_id; req = req->next);

	if (!req) {
		pomlog(POMLOG_ERR "IPC request %u not found in the queue !");
		pom_mutex_unlock(&input_ipc_req_mutex);
		return POM_OK;
	}

	pom_mutex_lock(&req->mutex);
	pom_mutex_unlock(&input_ipc_req_mutex);

	if (req->replied) {
		*msg = &req->reply;
		pom_mutex_unlock(&req->mutex);
		return POM_OK;
	}


	// Wait for the reply to be processed by the main process
	pomlog(POMLOG_DEBUG "Waiting for reply %u", req_id);

	if (pthread_cond_wait(&req->cond, &req->mutex)) {
		pomlog(POMLOG_ERR "Error while waiting for request condition : %s", pom_strerror(errno));
		return POM_ERR;
	}

	pom_mutex_unlock(&req->mutex);

	*msg = &req->reply;

	return POM_OK;
}

int input_ipc_destroy_request(int req_id) {

	pom_mutex_lock(&input_ipc_req_mutex);

	struct input_ipc_request *req = input_ipc_reqs;
	for (; req && req->id != req_id; req = req->next);


	if (!req) {
		pomlog(POMLOG_ERR "IPC request %u not found in the queue !");
		pom_mutex_unlock(&input_ipc_req_mutex);
		return POM_OK;
	}
	
	if (req->prev)
		req->prev->next = req->next;
	else
		input_ipc_reqs = req->next;

	if (req->next)
		req->next->prev = req->prev;

	pom_mutex_unlock(&input_ipc_req_mutex);

	pthread_mutex_destroy(&req->mutex);
	pthread_cond_destroy(&req->cond);
	free(req);

	return POM_OK;
}

int input_ipc_cleanup() {

	pom_mutex_lock(&input_ipc_req_mutex);
	struct input_ipc_request *req = input_ipc_reqs;

	// Free the lock on all the requests
	while (req) {
		req->reply.status = POM_ERR;
		pthread_cond_broadcast(&req->cond);
		req = req->next;
	}

	pom_mutex_unlock(&input_ipc_req_mutex);
	// Wait for all the requests to be cleaned up
	
	while (input_ipc_reqs) {
		pomlog(POMLOG_DEBUG "Waiting for requests to be processed ...");
		sleep(1);
	}

	return POM_OK;
}


