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
#include <sys/shm.h>
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

static pthread_rwlock_t input_list_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct input_list *input_list_head = NULL;
static unsigned int input_list_cur_id = 0;

static void input_sighandler(int signal) {

	running = 0;

	printf("Signal %u received.\n", signal);
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

	// Load relevant modules
	mod_load_all();

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
		cmd_reply.status = POM_ERR;

		switch (cmd.subtype) {
			case input_ipc_cmd_type_mod_load:
				if (mod_load(cmd.data.mod_load.name))
					cmd_reply.status = POM_OK;
				break;

			case input_ipc_cmd_type_add: {
				struct input_list *l = malloc(sizeof(struct input_list));
				if (!l) {
					pomlog(POMLOG_ERR "Not enough memory to allocate struct input_list");
					break;
				}
				memset(l, 0, sizeof(struct input_list));
				l->i = input_alloc(cmd.data.add.name, input_ipc_key);
				if (!l->i) {
					pomlog("Error while allocating input %s", cmd.data.add.name);
					break;
				}

				input_list_lock(1);
				l->next = input_list_head;
				if (l->next)
					l->next->prev = l;
				input_list_head = l;
				input_list_cur_id++;
				if (input_list_cur_id == POM_ERR)
					input_list_cur_id++;
				l->id = input_list_cur_id;
				input_list_unlock();

				cmd_reply.data.add.id = l->id;
				cmd_reply.status = POM_OK;

				break;
			}

			case input_ipc_cmd_type_remove: {
				input_list_lock(1);
				struct input_list *l;
				for (l = input_list_head; l && l->id != cmd.data.remove.id; l = l->next);
				if (!l) {
					pomlog(POMLOG_ERR "Input with id %u not found", cmd.data.remove.id);
					input_list_unlock();
					break;
				}
				pomlog("Cleaning up input %u", l->id);
				if (input_cleanup(l->i) != POM_OK) {
					pomlog(POMLOG_ERR "Error while cleaning up input %u", l->id);
					input_list_unlock();
					break;
				}

				if (l->prev) {
					l->prev->next = l->next;
				} else {
					input_list_head = l->next;
					if (input_list_head)
						input_list_head->prev = NULL;
				}
				if (l->next)
					l->next->prev = l->prev;

				free(l);

				input_list_unlock();

				cmd_reply.status = POM_OK;
				break;
			}

			case input_ipc_cmd_type_start: {
				input_list_lock(1);
				struct input_list *l;
				for (l = input_list_head; l && l->id != cmd.data.start.id; l = l->next);
				if (!l) {
					pomlog(POMLOG_ERR "List with id %u not found", cmd.data.start.id);
					input_list_unlock();
					break;
				}
				cmd_reply.status = input_open(l->i);
				input_list_unlock();
				break;
			}

			case input_ipc_cmd_type_stop: {
				input_list_lock(1);
				struct input_list *l;
				for (l = input_list_head; l && l->id != cmd.data.stop.id; l = l->next);
				if (!l) {
					pomlog(POMLOG_ERR "List with id %u not found", cmd.data.stop.id);
					input_list_unlock();
					break;
				}
				cmd_reply.status = input_close(l->i);
				input_list_unlock();
				break;
			}

			default:
				break;
		}

		pomlog(POMLOG_DEBUG "Sending reply with status %d", cmd_reply.status);
		if (ipc_send_msg(qid, &cmd_reply, sizeof(struct input_ipc_raw_cmd_reply)) != POM_OK) {
			pomlog(POMLOG_ERR "Error while sending reply for input command");
			break;
		}

	}

	input_list_cleanup();

	mod_unload_all();

	pomlog("Input process terminated cleanly");


	return 0;
}


int input_register(struct input_reg_info *reg_info, struct mod_reg *mod) {

	if (!input_current_process()) {
		pomlog(POMLOG_DEBUG "Not loading input in another process than the input process");
		return POM_ERR;
	}

	pomlog(POMLOG_DEBUG "Registering input %s", reg_info->name);

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

struct input* input_alloc(const char* type, int input_ipc_key) {

	input_reg_lock(1);

	struct input_reg *reg;
	for (reg = input_reg_head; reg && strcmp(reg->info->name, type); reg = reg->next);

	if (!reg) {
		input_reg_unlock();
		pomlog(POMLOG_ERR "Input of type %s not found", type);
		return NULL;
	}

	reg->refcount++;
	input_reg_unlock();

	// Try to allocate IPC shared memory
	void *shm_buff = NULL;
	int shm_id = -1;
	size_t shm_buff_size = 0;
	while (!shm_buff) {
		// Create the new id
		input_ipc_key++;
		shm_id = shmget(input_ipc_key, INPUT_SHM_BUFF_SIZE, IPC_CREAT | IPC_EXCL);
		if (shm_id == -1) {
			if (errno == ENOMEM) {
				pomlog(POMLOG_ERR "Not enough memory to allocate IPC shared memory of %u bytes", INPUT_SHM_BUFF_SIZE);
				goto err;
			}
			continue;
		}

		// Get the exact allocated size
		struct shmid_ds info;
		if (shmctl(shm_id, IPC_STAT, &info) == -1) {
			shmctl(shm_id, IPC_RMID, 0);
			shm_id = -1;
			continue;
		}

		shm_buff_size = info.shm_segsz;

		pomlog("Requested %u bytes, got %u", INPUT_SHM_BUFF_SIZE, shm_buff_size);

		// Attach the memory segment in our address space
		shm_buff = shmat(shm_id, NULL, 0);
		if (shm_buff == (void*)-1) {
			shmctl(shm_id, IPC_RMID, 0);
			if (errno == ENOMEM) {
				pomlog(POMLOG_ERR "Not enough memory to attach the IPC shared memory");
				goto err;
			}
			shm_buff = NULL;
			shm_id = -1;
		}

	}
	
	struct input *ret = malloc(sizeof(struct input));
	if (!ret) {
		pomlog(POMLOG_ERR "Not enough memory to allocate input %s", type);
		goto err;
	}
	memset(ret, 0, sizeof(struct input));

	ret->shm_key = input_ipc_key;
	ret->shm_id = shm_id;
	ret->shm_buff = shm_buff;
	ret->shm_buff_size = shm_buff_size;
	if (pthread_rwlock_init(&ret->op_lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing the input op lock");
		free(ret);
		goto err;
	}

	ret->type = reg;
	if (reg->info->alloc) {
		if (reg->info->alloc(ret) != POM_OK) {
			pomlog(POMLOG_ERR "Error while allocating input %s", type);
			pthread_rwlock_destroy(&ret->op_lock);
			free(ret);
			goto err;
		}
	}
	

	return ret;

err:

	if (shm_buff)
		shmdt(shm_buff);
	if (shm_id != -1)
		shmctl(shm_id, IPC_RMID, 0);

	input_reg_lock(1);
	reg->refcount++;
	input_reg_unlock();

	return NULL;
}

int input_open(struct input *i) {

	if (!i)
		return POM_ERR;

	input_instance_lock(i, 1);

	if (i->running) {
		input_instance_unlock(i);
		return POM_ERR;
	}

	int res = POM_ERR;
	if (i->type->info->open) {
		res = i->type->info->open(i);
		if (res == POM_ERR) {
			input_instance_unlock(i);
			return POM_ERR;
		}
	}

	i->running = 1;

	if (pthread_create(&i->thread, NULL, input_process_thread, (void *) i)) {
		pomlog(POMLOG_ERR "Unable to spawn a new thread for the input");
		input_instance_unlock(i);
		return POM_ERR;

	}

	input_instance_unlock(i);
	return res;
}


int input_add_processed_packet(struct input *i, size_t pkt_size, unsigned char *pkt_data, struct timeval *ts) {

	struct input_buff *buff = i->shm_buff;

	void *start = (void*)i->shm_buff + sizeof(struct input_buff);
	void *end = (void*)i->shm_buff + i->shm_buff_size;

	// Find some space where to store the packet in the shared mem
	
	struct input_packet *pkt = NULL;

	size_t buff_pkt_len = sizeof(struct input_packet) + pkt_size;

	// Check for that size right after tail

	if (!buff->tail) { // buffer is empty
		pkt = start;
	} else {
		// Something is in the buffer, see if it fits 
		void *next = (void*)buff->tail + sizeof(struct input_packet) + buff->tail->len;

		// Check if packet fits after last one
		if (next + buff_pkt_len >= end) {
			// Ok packet won't fit, let's see if we can put it at the begining
			next = start;
			while (buff->head && ((void*)buff->head <= next + buff_pkt_len)) {
				// Ok it doesn't fit at the begining, let's drop a packet then ...
				buff->head = buff->head->next;
			}
		}

		if (buff->tail < buff->head || next < (void*)buff->head) {
			while (buff->head && (next + buff_pkt_len >= (void*)buff->head)) {
				// Buffer is full, next packet will overwrite the packet that needs to be read, drop it then
				buff->head = buff->head->next;
			}

		}

		pkt = next;
	}
	memset(pkt, 0, sizeof(struct input_packet));	
	memcpy(&pkt->ts, ts, sizeof(struct timeval));
	pkt->len = pkt_size;
	memcpy((void*)pkt + sizeof(struct input_packet), pkt_data, pkt_size);

	if (!buff->head) {
		buff->head = pkt;
		buff->tail = pkt;
	} else {
		buff->tail->next = pkt;
		buff->tail = pkt;
	}

	return POM_OK;
}


int input_close(struct input *i) {

	if (!i)
		return POM_ERR;

	input_instance_lock(i, 1);

	if (!i->running) {
		input_instance_unlock(i);
		return POM_ERR;
	}

	if (i->type->info->close) {
		int res = i->type->info->close(i);
		if (res == POM_ERR) {
			input_instance_unlock(i);
			return POM_ERR;
		}
	}

	i->running = 0;
	input_instance_unlock(i);

	if (!pthread_equal(pthread_self(), i->thread)) {
		// Try to join the thread only if it's not ourself
		if (pthread_join(i->thread, NULL))
			pomlog(POMLOG_ERR "Error while waiting for the input thread to finish : %s", pom_strerror(errno));
	}


	return POM_OK;
}

int input_cleanup(struct input *i) {

	if (!i)
		return POM_ERR;
	
	input_instance_lock(i, 1);
	if (i->running) {
		input_instance_unlock(i);
		return POM_ERR;
	}

	if (i->type->info->cleanup)
		i->type->info->cleanup(i);

	// Free shm stuff
	if (i->shm_buff && shmdt(i->shm_buff))
		pomlog(POMLOG_WARN "Error while detaching shared memory : %s", pom_strerror(errno));
	
	if (i->shm_id != -1 && shmctl(i->shm_id, IPC_RMID, 0) == -1)
		pomlog(POMLOG_WARN "Error while removing the IPC id %u : %s", i->shm_id, pom_strerror(errno));

	input_reg_lock(1);
	i->type->refcount--;
	input_reg_unlock();

	param_list_cleanup(&i->param);
	input_instance_unlock(i);
	pthread_rwlock_destroy(&i->op_lock);
	free(i);

	return POM_OK;
}

int input_list_cleanup() {

	input_list_lock(1);

	struct input_list *l;
	while (input_list_head) {
		l = input_list_head;
		input_list_head = l->next;

		pomlog("Cleaning up input %u (%s)", l->id, l->i->type->info->name);
		if (l->i->running)
			input_close(l->i);
		param_list_cleanup(&l->i->param);
		input_cleanup(l->i);
		free(l);
	}


	input_list_unlock();

	return POM_OK;
}

int input_unregister(char *name) {


	input_reg_lock(1);
	struct input_reg *reg;

	for (reg = input_reg_head; reg && strcmp(reg->info->name, name); reg = reg->next);
	if (!reg) {
		pomlog(POMLOG_DEBUG "Input %s is not registered, cannot unregister it.", name);
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

	free(reg);

	return POM_OK;
}

void *input_process_thread(void *param) {

	struct input *i = param;

	pomlog("New input thread running");

	while (i->type->info->read(i) == POM_OK) {
		input_instance_lock(i, 0);
		if (!i->running) {
			input_instance_unlock(i);
			break;
		}
		input_instance_unlock(i);
	}

	pomlog("Input thread finished");

	return NULL;
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

void input_list_lock(int write) {
	
	int res = 0;
	
	if (write)
		res = pthread_rwlock_wrlock(&input_list_rwlock);
	else
		res = pthread_rwlock_rdlock(&input_list_rwlock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking the input_list locki : %s", pom_strerror(errno));
		abort();
	}

}

void input_list_unlock() {

	if (pthread_rwlock_unlock(&input_list_rwlock)) {
		pomlog(POMLOG_ERR "Error while unlocking the input_list lock : %s", pom_strerror(errno));
		abort();
	}

}


void input_instance_lock(struct input *i, int write) {
	
	int res = 0;

	if (write)
		res = pthread_rwlock_wrlock(&i->op_lock);
	else
		res = pthread_rwlock_rdlock(&i->op_lock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking the input instance op lock : %s", pom_strerror(errno));
		abort();
	}
}

void input_instance_unlock(struct input *i) {

	if (pthread_rwlock_unlock(&i->op_lock)) {
		pomlog(POMLOG_ERR "Error while unlocking the input instance op lock : %s", pom_strerror(errno));
		abort();
	}
}
