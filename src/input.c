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
#include "input_server.h"
#include "mod.h"
#include <ptype.h>

static pthread_rwlock_t input_reg_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct input_reg *input_reg_head = NULL;

int input_register(struct input_reg_info *reg_info, struct mod_reg *mod) {

	if (!input_server_is_current_process()) {
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
		pom_oom(sizeof(struct input_reg));
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

struct input* input_alloc(const char* type, int input_ipc_key, uid_t uid, gid_t gid) {

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
	size_t shm_buff_size = INPUT_SHM_BUFF_SIZE;
	while (!shm_buff) {
		// Create the new id
		input_ipc_key++;
		shm_id = shmget(input_ipc_key, shm_buff_size, IPC_CREAT | IPC_EXCL);
		if (shm_id == -1) {
			if (errno == ENOMEM) {
				pomlog(POMLOG_ERR "Not enough memory to allocate IPC shared memory of %u bytes", INPUT_SHM_BUFF_SIZE);
				goto err;
			}
			continue;
		}

		// we should round up the size to a multiple of PAGE_SIZE // sysconf(_SC_PAGESIZE);

		// Attach the memory segment in our address space
		shm_buff = shmat(shm_id, NULL, 0);
		if (shm_buff == (void*)-1) {
			pomlog(POMLOG_ERR "Error while attaching the IPC shared memory segment : %s", pom_strerror(errno));
			shm_buff = NULL;
			shmctl(shm_id, IPC_RMID, 0);
			goto err;
		}

		struct shmid_ds data;
		if (shmctl(shm_id, IPC_STAT, &data)) {
			pomlog(POMLOG_ERR "Error while getting shared memory data : %s", pom_strerror(errno));
			goto err;
		}

		data.shm_perm.uid = uid;
		data.shm_perm.gid = gid;
		data.shm_perm.mode = 0600;

		if (shmctl(shm_id, IPC_SET, &data)) {
			pomlog(POMLOG_ERR "Error while setting the correct permissions on the IPC shared memory : %s", pom_strerror(errno));
			goto err;
		}

	}
	
	struct input *ret = malloc(sizeof(struct input));
	if (!ret) {
		pom_oom(sizeof(struct input));
		goto err;
	}
	memset(ret, 0, sizeof(struct input));

	if (pthread_rwlock_init(&ret->op_lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing the input op lock");
		goto err_ret;
	}

	ret->shm_key = input_ipc_key;
	ret->shm_id = shm_id;
	ret->shm_buff = shm_buff;
	ret->shm_buff_size = shm_buff_size;

	// Setup the buffer
	struct input_buff *buff = ret->shm_buff;
	memset(buff, 0, sizeof(struct input_buff));

	buff->buff_start_offset = sizeof(struct input_buff);
	buff->buff_end_offset = ret->shm_buff_size;

	buff->inpkt_head_offset = -1;
	buff->inpkt_process_head_offset = -1;
	buff->inpkt_tail_offset = -1;

	// Setup the buffer lock
	pthread_mutexattr_t attr;
	pthread_condattr_t condattr;

	if (pthread_mutexattr_init(&attr)) {
		pomlog(POMLOG_ERR "Error while initializing the mutex attributes");
		goto err_oplock;
	}

	if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
		pomlog(POMLOG_ERR "Error while setting the pshared attribute");
		goto err_mutexattr;
	}

	if (pthread_mutex_init(&buff->lock, &attr)) {
		pomlog(POMLOG_ERR "Error while initializing the mutex on the shared memory");
		goto err_mutexattr;
	}

	if (pthread_condattr_init(&condattr)) {
		pomlog(POMLOG_ERR "Error while initializing the mutex condition attributes");
		goto err_mutex;
	}

	if (pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED)) {
		pomlog(POMLOG_ERR "Error while setting the pshared condition attribute");
		goto err_condattr;
	}

	if (pthread_cond_init(&buff->underrun_cond, &condattr)) {
		pomlog(POMLOG_ERR "Error while initializing the underrun condition");
		goto err_condattr;
	}

	if (pthread_cond_init(&buff->overrun_cond, &condattr)) {
		pomlog(POMLOG_ERR "Error while initializing the overrun condition");
		goto err_underrun_cond;
	}

	if (pthread_condattr_destroy(&condattr)) {
		pomlog(POMLOG_WARN "Error while destroying the mutex cond attributes");
	}

	if (pthread_mutexattr_destroy(&attr)) {
		pomlog(POMLOG_WARN "Error while destroying the mutex attributes");
	}

	ret->type = reg;
	if (reg->info->alloc) {
		if (reg->info->alloc(ret) != POM_OK) {
			pomlog(POMLOG_ERR "Error while allocating input %s", type);
			pthread_cond_destroy(&buff->underrun_cond);
			pthread_cond_destroy(&buff->underrun_cond);
			goto err_mutex;
		}
	}
	

	return ret;

err_underrun_cond:
	pthread_cond_destroy(&buff->underrun_cond);
err_condattr:
	pthread_condattr_destroy(&condattr);
err_mutex:
	pthread_mutex_destroy(&buff->lock);
err_mutexattr:
	pthread_mutexattr_destroy(&attr);
err_oplock:
	pthread_rwlock_destroy(&ret->op_lock);
err_ret:
	free(ret);
err:

	if (shm_buff)
		shmdt(shm_buff);
	if (shm_id != -1)
		shmctl(shm_id, IPC_RMID, 0);

	input_reg_lock(1);
	reg->refcount--;
	input_reg_unlock();

	return NULL;
}

int input_register_param(struct input *i, char *name, struct ptype *value, char *default_value, char *description, unsigned int flags) {

	// Create the input_param structure

	struct input_param *p = malloc(sizeof(struct input_param));
	if (!p) {
		pom_oom(sizeof(struct input_param));
		return POM_ERR;
	}
	memset(p, 0, sizeof(struct input_param));

	p->name = strdup(name);
	if (!p->name) {
		pom_oom(strlen(name));
		goto err_name;
	}

	p->default_value = strdup(default_value);
	if (!p->default_value) {
		pom_oom(strlen(default_value));
		goto err_defval;
	}

	p->description = strdup(description);
	if (!p->description) {
		pom_oom(strlen(description));
		goto err_description;
	}

	p->value = value;

	if (ptype_parse_val(p->value, default_value) != POM_OK) {
		pomlog(POMLOG_ERR "Unable to parse default value \"%s\" for input parameter %s", default_value, name);
		goto err;
	}

	p->flags = flags;


	p->next = i->params;
	i->params = p;

	return POM_OK;

err:
	free(p->description);
err_description:
	free(p->default_value);
err_defval:
	free(p->name);
err_name:
	free(p);

	return POM_ERR;
}


int input_open(struct input *i, struct input_caps *ic) {

	if (!i || !ic)
		return POM_ERR;

	input_instance_lock(i, 1);

	if (i->running || !i->type->info->get_caps) {
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

	if (i->type->info->get_caps(i, ic) == POM_ERR) {
		input_instance_unlock(i);
		pomlog(POMLOG_ERR "Unable to get input capabilities");
		input_close(i);
		return POM_ERR;
	}


	i->running = 1;

	if (pthread_create(&i->thread, NULL, input_process_thread, (void *) i)) {
		input_instance_unlock(i);
		pomlog(POMLOG_ERR "Unable to spawn a new thread for the input");
		input_close(i);
		return POM_ERR;

	}

	input_instance_unlock(i);
	return res;
}


int input_add_processed_packet(struct input *i, size_t pkt_size, unsigned char *pkt_data, struct timeval *ts, unsigned int drop_if_full) {


	if (!i || !pkt_size || !pkt_data || !ts)
		return POM_ERR;

	struct input_buff *buff = i->shm_buff;

	// Find some space where to store the packet in the shared mem
	
	struct input_packet *pkt = NULL;

	size_t buff_pkt_len = sizeof(struct input_packet) + pkt_size;
	void *buff_start = (buff->buff_start_offset ? (void*)buff + buff->buff_start_offset : NULL);
	void *buff_end = (buff->buff_end_offset ? (void*)buff + buff->buff_end_offset : NULL);
	struct input_packet *buff_head = (struct input_packet *)(buff->inpkt_head_offset >= 0 ? (void*)buff + buff->inpkt_head_offset : NULL);
	struct input_packet *buff_tail = (struct input_packet *)(buff->inpkt_tail_offset >= 0 ? (void*)buff + buff->inpkt_tail_offset : NULL);

	// Check for that size right after tail

	pom_mutex_lock(&buff->lock);

retry:

	if (!buff_tail) { // buffer is empty
		pkt = buff_start;
	} else {
		// Something is in the buffer, see if it fits 
		void *next = buff_tail + sizeof(struct input_packet) + buff_tail->len;


		if (buff_tail >= buff_head) {
			// Check if packet fits after last one
			if (next + buff_pkt_len > buff_end) {
				// Ok packet won't fit, let's see if we can put it at the begining
				next = buff_start;
				if ((void *) buff_head < next + buff_pkt_len) {
					// Ok it doesn't fit at the begining, buffer is full
					next = NULL;
				}
			}
		} else {
			if ((void*)buff_head < next + buff_pkt_len) {
				// Ok it doesn't fit at the begining, buffer is full
				next = NULL;
			}
		}

		if (!next) { // Buffer overflow

			if (drop_if_full) {
				pomlog(POMLOG_DEBUG "Packet dropped (%ub) ...", pkt_size);
				goto end;
			} else {
				pomlog(POMLOG_DEBUG "Buffer overflow, waiting ....");
				if (pthread_cond_wait(&buff->overrun_cond, &buff->lock)) {
					pom_mutex_unlock(&buff->lock);
					pomlog(POMLOG_ERR "Error while waiting for overrun condition : %s", pom_strerror(errno));
					return POM_ERR;
				}

				goto retry;
			}
		}

		pkt = next;
	}

	// The copy of the packet is done unlocked
	pom_mutex_unlock(&buff->lock);
	memset(pkt, 0, sizeof(struct input_packet));
	memcpy(&pkt->ts, ts, sizeof(struct timeval));
	pkt->inpkt_prev_offset = -1;
	pkt->inpkt_next_offset = -1;

	pkt->len = pkt_size;
	void *pkt_buff = (unsigned char *)pkt + sizeof(struct input_packet);
	memcpy(pkt_buff, pkt_data, pkt_size);
	pkt->buff_offset = pkt_buff - (void*)buff;
	pom_mutex_lock(&buff->lock);

	// Refecth the variables after relocking
	buff_head = (struct input_packet*)(buff->inpkt_head_offset >= 0 ? (void*)buff + buff->inpkt_head_offset : NULL);
	buff_tail = (struct input_packet*)(buff->inpkt_tail_offset >= 0 ? (void*)buff + buff->inpkt_tail_offset : NULL);
	if (!buff_head) {
		buff->inpkt_head_offset = (void*)pkt - (void*)buff;
		buff->inpkt_tail_offset = (void*)pkt - (void*)buff;


		pom_mutex_unlock(&buff->lock);

		if (pthread_cond_signal(&buff->underrun_cond)) {
			pomlog(POMLOG_ERR "Could not signal the underrun condition : %s", pom_strerror(errno));
			return POM_ERR;
		}

		return POM_OK;
	} else {
		// Connect the new packet to the last one in the buffer
		pkt->inpkt_prev_offset = buff->inpkt_tail_offset;
		// Update the last one to point to the next one
		buff_tail->inpkt_next_offset = (void*)pkt - (void*)buff;
		// Update tail of packets
		buff->inpkt_tail_offset = (void*)pkt - (void*)buff;
	}

end:
	pom_mutex_unlock(&buff->lock);

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

	i->running = 0;
	input_instance_unlock(i);

	if (!pthread_equal(pthread_self(), i->thread)) {
		// Try to join the thread only if it's not ourself
		if (pthread_join(i->thread, NULL))
			pomlog(POMLOG_ERR "Error while waiting for the input thread to finish : %s", pom_strerror(errno));
	}

	if (i->type->info->close) {
		int res = i->type->info->close(i);
		if (res == POM_ERR) {
			input_instance_unlock(i);
			return POM_ERR;
		}
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
	if (i->shm_buff) {
		int attached = 1;
		while (1) {
			pomlog(POMLOG_DEBUG "Waiting for the other process to detach the buffer ...");
			pom_mutex_lock(&i->shm_buff->lock);
			attached = i->shm_buff->attached;
			pom_mutex_unlock(&i->shm_buff->lock);
			if (!attached)
				break;
			sleep(1);
		}

		if (shmdt(i->shm_buff))
			pomlog(POMLOG_WARN "Error while detaching shared memory : %s", pom_strerror(errno));
	}
	
	if (i->shm_id != -1 && shmctl(i->shm_id, IPC_RMID, 0) == -1)
		pomlog(POMLOG_WARN "Error while removing the IPC id %u : %s", i->shm_id, pom_strerror(errno));

	input_reg_lock(1);
	i->type->refcount--;
	input_reg_unlock();

	input_instance_unlock(i);
	pthread_rwlock_destroy(&i->op_lock);

	while (i->params) {
		struct input_param *p = i->params;
		free(p->name);
		free(p->default_value);
		free(p->description);

		i->params = p->next;
		free(p);
	}

	free(i);

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
