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
#include "registry.h"
#include "input_client.h"
#include "core.h"
#include "packet.h"
#include "mod.h"

#include <sys/shm.h>

#include <pom-ng/ptype_string.h>

static struct input_client_entry *input_client_head = NULL;
static struct registry_class *input_registry_class = NULL;
static unsigned int input_cur_running = 0;
static pthread_mutex_t input_lock = PTHREAD_MUTEX_INITIALIZER;
static struct input_client_registered_list *input_client_registered_input = NULL;

int input_client_init() {


	input_registry_class = registry_add_class(INPUT_CLIENT_REGISTRY);
	if (!input_registry_class)
		return POM_ERR;

	input_registry_class->instance_add = input_client_cmd_add;
	input_registry_class->instance_remove = input_client_cmd_remove;

	return POM_OK;
}

int input_client_cleanup(int emergency_cleanup) {

	if (!emergency_cleanup)
		core_wait_state(core_state_idle);

	while (input_client_head) {
		struct input_client_entry *i = input_client_head;
		input_client_head = i->next;

		if (i->thread) {
			if (emergency_cleanup)
				pthread_cancel(i->thread->thread);
		}

		if (i->shm_buff) {
			pom_mutex_lock(&i->shm_buff->lock);
			i->shm_buff->flags &= ~INPUT_FLAG_ATTACHED;
			pom_mutex_unlock(&i->shm_buff->lock);
			if (shmdt(i->shm_buff))
				pomlog(POMLOG_WARN "Warning, error while detaching IPC shared memory segment : %s", pom_strerror(errno));
			i->shm_buff = NULL;
		}

		while (i->params) {
			struct input_client_param *p = i->params;
			i->params = p->next;
			ptype_cleanup(p->value);
			free(p);
		}

		if (i->datalink_dep)
			proto_remove_dependency(i->datalink_dep);
		free(i->type);

		if (i->next)
			i->next->prev = i->prev;
		if (i->prev)
			i->prev->next = i->next;
		else
			input_client_head = i->next;
		free(i);

	}

	if (input_registry_class)
		registry_remove_class(input_registry_class);
	input_registry_class = NULL;

	return POM_OK;
}

int input_client_register_input(struct input_reg_info *reg_info, struct mod_reg *mod) {

	struct input_client_registered_list *lst;
	pom_mutex_lock(&input_lock);
	// Check if the input is already registered
	for (lst = input_client_registered_input; lst && strcmp(lst->input_name, reg_info->name); lst = lst->next);
	if (lst) {
		pomlog(POMLOG_ERR "Input %s already registered at client", reg_info->name);
		pom_mutex_unlock(&input_lock);
		return POM_ERR;
	}

	// Check if the corresponding module is already loaded
	int module_loaded = 0;
	for (lst = input_client_registered_input; lst && (lst->mod != mod); lst = lst->next);
	if (!lst) {
		if (input_client_cmd_mod_load(mod->name) != POM_OK) {
			pomlog(POMLOG_ERR "Could not load the right module on the server side");
			goto err;
		}
		module_loaded = 1;
	}


	lst = malloc(sizeof(struct input_client_registered_list));
	if (!lst) {
		pom_oom(sizeof(struct input_client_registered_list));
		goto err;

	}
	memset(lst, 0, sizeof(struct input_client_registered_list));
	lst->input_name = reg_info->name;
	lst->mod = mod;

	if (registry_add_instance_type(input_registry_class, reg_info->name) != POM_OK) {
		free(lst);
		goto err;
	}

	mod_refcount_inc(mod);

	lst->next = input_client_registered_input;
	if (lst->next)
		lst->next->prev = lst;

	input_client_registered_input = lst;
	
	pom_mutex_unlock(&input_lock);
	return POM_OK;

err:
	pom_mutex_unlock(&input_lock);
	if (module_loaded)
		input_client_cmd_mod_unload(mod->name);
	return POM_ERR;

}

int input_client_unregister_input(char *name) {

	pom_mutex_lock(&input_lock);

	struct input_client_registered_list *lst;

	for (lst = input_client_registered_input; lst && strcmp(lst->input_name, name); lst = lst->next);
	if (!lst) {
		pom_mutex_unlock(&input_lock);
		pomlog(POMLOG_ERR "Input %s is not registered", name);
		return POM_ERR;
	}

	// Check if the input is still in use
	struct input_client_entry *entry;
	for (entry = input_client_head; entry && strcmp(entry->type, name); entry = entry->next);
	if (entry) {
		pom_mutex_unlock(&input_lock);
		pomlog(POMLOG_ERR "Input %s is still in use, cannot unregister it", name);
		return POM_ERR;
	}

	if (registry_remove_instance_type(input_registry_class, name) != POM_OK) {
		pom_mutex_unlock(&input_lock);
		return POM_ERR;
	}

	// Check if the module used by the input is used somewhere else
	struct input_client_registered_list *tmp;
	for (tmp = input_client_registered_input; tmp && (lst->mod != tmp->mod || tmp == lst); tmp = tmp->next);
	if (!tmp) {
		if (input_client_cmd_mod_unload(lst->mod->name) != POM_OK) {
			// Re-add the type
			registry_add_instance_type(input_registry_class, name);
			pom_mutex_unlock(&input_lock);
			return POM_ERR;
		}
	}

	mod_refcount_dec(lst->mod);


	if (lst->next)
		lst->next->prev = lst->prev;
	
	if (lst->prev)
		lst->prev->next = lst->next;
	else
		input_client_registered_input = lst->next;

	free(lst);
	pom_mutex_unlock(&input_lock);

	return POM_OK;
}

void *input_client_reader_thread_func(void *thread) {

	struct input_client_reader_thread *t = thread;

	pomlog("New thread for input \"%s\" started", t->input->reg_instance->name);
	
	pom_mutex_lock(&input_lock);
	input_cur_running++;
	if (input_cur_running == 1)
		core_set_state(core_state_running);
	pom_mutex_unlock(&input_lock);

	while (1) {

		struct packet *p = packet_pool_get();
		if (!p) {
			pomlog(POMLOG_ERR "Error while getting a packet from the packet pool for input \"%s\"", t->input->reg_instance->name);
			break;
		}
		
		if (input_client_get_packet(t->input, p) != POM_OK) {
			pomlog(POMLOG_ERR "Error while fetching packets from input \"%s\"", t->input->reg_instance->name);
			break;
		}

		if (!p->buff) {
			// EOF
			pomlog("Input \"%s\" stopped", t->input->reg_instance->name);
			packet_pool_release(p);
			break;
		}

		p->datalink = t->input->datalink_dep->proto;

		if (core_queue_packet(p, t->input) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while queueing a packet from input \"%s\"", t->input->reg_instance->name);
			break;
		}

	}

	pom_mutex_lock(&input_lock);
	if (t->input->thread) {
		pthread_detach(t->input->thread->thread);
		t->input->thread = NULL;
	}

	// Do the cleanup
	
	proto_remove_dependency(t->input->datalink_dep);
	t->input->datalink_dep = NULL;

	free(t);

	input_cur_running--;
	if (!input_cur_running)
		core_set_state(core_state_finishing);
	pom_mutex_unlock(&input_lock);
	return NULL;
}

int input_client_get_packet(struct input_client_entry *input, struct packet *p) {


	if (!p || !input)
		return POM_ERR;

	struct input_buff *buff = input->shm_buff;

	pom_mutex_lock(&buff->lock);

	while (buff->inpkt_process_head_offset < 0) {

		if (buff->flags & INPUT_FLAG_EOF) {
			
			// Clear the EOF flag so the input will be allowed to start again
			buff->flags &= ~INPUT_FLAG_EOF;

			// EOF
			pom_mutex_unlock(&buff->lock);
			p->buff = NULL;
			p->len = 0;
			return POM_OK;
		}

		// Wait for a packet
		//pomlog(POMLOG_DEBUG "Buffer underrun");
		if (pthread_cond_wait(&buff->underrun_cond, &buff->lock)) {
			pomlog(POMLOG_ERR "Error while waiting for underrun condition : %s", pom_strerror(errno));
			pom_mutex_unlock(&buff->lock);
			return POM_ERR;
		}
	}


	struct input_packet *buff_head = (struct input_packet *)(buff->inpkt_process_head_offset >= 0 ? (void*)buff + buff->inpkt_process_head_offset : NULL);
	unsigned char *inpkt_buff = (unsigned char *)buff + buff_head->buff_offset;

	buff->inpkt_process_head_offset = buff_head->inpkt_next_offset;

	// Signal that we removed a packet
	if (pthread_cond_signal(&buff->overrun_cond)) {
		pomlog(POMLOG_ERR "Unable to signal overrun condition : %s", pom_strerror(errno));
		pom_mutex_unlock(&buff->lock);
		return POM_ERR;
	}

	pom_mutex_unlock(&buff->lock);

	p->buff = inpkt_buff;
	p->len = buff_head->len;
	p->input = input;
	p->input_pkt = buff_head;
	p->id = input->last_pkt_id++;
	memcpy(&p->ts, &buff_head->ts, sizeof(struct timeval));

	return POM_OK;
}

int input_client_release_packet(struct input_client_entry *i, struct input_packet *pkt) {

	struct input_buff *buff = i->shm_buff;

	pom_mutex_lock(&buff->lock);

	if (pkt->inpkt_prev_offset >= 0) {
		struct input_packet *prev = (void*)buff + pkt->inpkt_prev_offset;
		prev->inpkt_next_offset = pkt->inpkt_next_offset;
	} else {
		buff->inpkt_head_offset = pkt->inpkt_next_offset;
	}
	
	if (pkt->inpkt_next_offset >= 0) {
		struct input_packet *next = (void*) buff + pkt->inpkt_next_offset;
		next->inpkt_prev_offset = pkt->inpkt_prev_offset;
	} else {
		buff->inpkt_tail_offset = pkt->inpkt_prev_offset;
	}

	if (pthread_cond_signal(&buff->overrun_cond)) { // A packet has been taken out
		pomlog(POMLOG_ERR "Error while signaling overrun condition : %s", pom_strerror(errno));
		pom_mutex_unlock(&buff->lock);
		return POM_ERR;
	}

	pom_mutex_unlock(&buff->lock);

	return POM_OK;
}


int input_client_cmd_mod_load(char *mod_name) {
	
	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_mod_load;
	strncpy(msg.data.mod_load.name, mod_name, INPUT_IPC_MOD_FILE_NAME_SIZE);

	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);
	if (id == POM_ERR)
		return POM_ERR;
	
	struct input_ipc_raw_cmd_reply *reply;
	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;

	int status = reply->status;
	
	input_ipc_destroy_request(id);
	return status;

}

int input_client_cmd_mod_unload(char *mod_name) {
	
	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_mod_unload;
	strncpy(msg.data.mod_unload.name, mod_name, INPUT_IPC_MOD_FILE_NAME_SIZE);

	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);
	if (id == POM_ERR)
		return POM_ERR;
	
	struct input_ipc_raw_cmd_reply *reply;
	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;

	int status = reply->status;
	
	input_ipc_destroy_request(id);
	return status;

}

int input_client_cmd_add(char *type, char *name) {
	
	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_add;
	strncpy(msg.data.add.name, type, INPUT_NAME_MAX);

	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);

	if (id == POM_ERR)
		return POM_ERR;

	struct input_ipc_raw_cmd_reply *reply;

	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;

	int status = reply->status;
	int input_id = reply->data.add.id;
	int shm_key = reply->data.add.shm_key;
	size_t shm_buff_size = reply->data.add.shm_buff_size;
	
	input_ipc_destroy_request(id);

	if (status == POM_ERR || input_id == POM_ERR)
		return POM_ERR;

	struct input_client_entry *entry = NULL;
	struct input_buff *buff = NULL;

	// Get the shm_id
	int shm_id = shmget(shm_key, shm_buff_size, 0);
	if (shm_id == -1) {
		pomlog(POMLOG_ERR "Cannot get SHM id : %s", pom_strerror(errno));
		goto err;
	}

	// Try to attach the shared memory
	buff = shmat(shm_id, NULL, 0);
	if (buff == (void*)-1) {
		pomlog(POMLOG_ERR "Error while attaching the IPC shared memory segment : %s", pom_strerror(errno));
		buff = NULL;
		goto err;
	}

	pom_mutex_lock(&buff->lock);
	buff->flags |= INPUT_FLAG_ATTACHED;
	pom_mutex_unlock(&buff->lock);

	entry = malloc(sizeof(struct input_client_entry));
	if (!entry) {
		pom_oom(sizeof(struct input_client_entry));
		goto err;
	}
	memset(entry, 0, sizeof(struct input_client_entry));

	entry->id = input_id;
	entry->shm_id = shm_id;
	entry->shm_buff = buff;

	entry->type = strdup(type);
	if (!entry->type) {
		pom_oom(sizeof(strlen(type) + 1));
		goto err;
	}

	entry->next = input_client_head;
	input_client_head = entry;
	if (entry->next)
		entry->next->prev = entry;

	// Add the input in the registry
	
	entry->reg_instance = registry_add_instance(input_registry_class, name);
	if (!entry->reg_instance)
		goto err;

	entry->reg_instance->priv = entry;

	if (registry_instance_add_function(entry->reg_instance, "start", input_client_cmd_start , "Start the input") != POM_OK ||
		registry_instance_add_function(entry->reg_instance, "stop", input_client_cmd_stop, "Stop the input") != POM_OK)
		goto err;

	// Add the type as a parameter
	struct ptype *input_type = ptype_alloc("string");
	if (!input_type)
		goto err;
	
	struct registry_param *type_param = registry_new_param("type", entry->type, input_type, "Type of the input", REGISTRY_PARAM_FLAG_CLEANUP_VAL | REGISTRY_PARAM_FLAG_IMMUTABLE);
	if (!type_param) {
		ptype_cleanup(input_type);
		goto err;
	}

	if (registry_instance_add_param(entry->reg_instance, type_param) != POM_OK) {
		ptype_cleanup(input_type);
		goto err;
	}
	if (registry_uid_create(entry->reg_instance) != POM_OK)
		goto err;
		

	// Fetch the input parameters

	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_get_param;
	msg.data.get_param.param_id = 0;
	int last = 0;
	do {
		msg.data.get_param.input_id = input_id;
		id = input_ipc_send_request(input_ipc_get_queue(), &msg);
		
		int res = input_ipc_reply_wait(id, &reply);
		if (res == POM_ERR || reply->status != POM_OK) {
			pomlog(POMLOG_ERR "Error while retreiving input parameters, please re-add the input");
			input_ipc_destroy_request(id);
			goto err;
		}

		pomlog(POMLOG_DEBUG "Got param %s of type %s, with defval %s", reply->data.get_param.name, reply->data.get_param.type, reply->data.get_param.defval);

		struct input_client_param *p = malloc(sizeof(struct input_client_param));
		if (!p) {
			pom_oom(sizeof(struct input_client_param));
			input_ipc_destroy_request(id);
			goto err;
		}
		memset(p, 0, sizeof(struct input_client_param));

		p->value = ptype_alloc(reply->data.get_param.type);
		if (!p->value) {
			free(p);
			input_ipc_destroy_request(id);
			goto err;
		}

		struct registry_param *reg_p = registry_new_param(	reply->data.get_param.name,
									reply->data.get_param.defval,
									p->value,
									reply->data.get_param.description,
									reply->data.get_param.flags);
		if (!reg_p) {
			ptype_cleanup(p->value);
			free(p);
			input_ipc_destroy_request(id);
			goto err;
		}

		registry_param_set_check_callbacks(reg_p, p, NULL, input_client_registry_param_apply);

		registry_instance_add_param(entry->reg_instance, reg_p);
		
		last = reply->data.get_param.last;
		input_ipc_destroy_request(id);

		p->id = msg.data.get_param.param_id;
		p->input = entry;
		p->next = entry->params;
		entry->params = p;

		msg.data.get_param.param_id++;

	} while (!last);

	return POM_OK;

err:


	// Make sure the buffer is not attached
	if (buff) {
		pom_mutex_lock(&buff->lock);
		buff->flags &= ~INPUT_FLAG_ATTACHED;
		pom_mutex_unlock(&buff->lock);
		shmdt(buff);
	}

	// Remove the input on the other side
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_remove;
	msg.data.remove.id = input_id;

	id = input_ipc_send_request(input_ipc_get_queue(), &msg);
	if (id == POM_ERR)
		return POM_ERR;
	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;
	input_ipc_destroy_request(id);

	if (entry) {

		// Remove the entry from the list
		if (entry->next)
			entry->next->prev = entry->prev;
		if (entry->prev)
			entry->prev->next = entry->next;
		else
			input_client_head = entry->next;

		// Remove it from the registry
		if (entry->reg_instance)
			registry_remove_instance(entry->reg_instance);

		// Cleanup various stuff
		if (entry->type)
			free(entry->type);

		// Cleanup params
		while (entry->params) {
			struct input_client_param *p = entry->params;
			entry->params = p->next;
			ptype_cleanup(p->value);
			free(p);
		}

		free(entry);

	}

	return POM_ERR;
}

int input_client_cmd_remove(struct registry_instance *ri) {
	
	struct input_client_entry *i = ri->priv;

	if (i->thread) {
		pomlog(POMLOG_WARN "Cannot remove input %u as it's running");
		return POM_ERR;
	}

	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_remove;
	msg.data.remove.id = i->id;

	int status = POM_ERR;
	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);

	if (id == POM_ERR)
		goto err;

	struct input_ipc_raw_cmd_reply *reply;

	if (i->shm_buff) {
		pom_mutex_lock(&i->shm_buff->lock);
		i->shm_buff->flags &= ~INPUT_FLAG_ATTACHED;
		pom_mutex_unlock(&i->shm_buff->lock);
		if (shmdt(i->shm_buff))
			pomlog(POMLOG_WARN "Warning, error while detaching IPC shared memory segment : %s", pom_strerror(errno));
		i->shm_buff = NULL;
	}

	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		goto err;

	registry_remove_instance(i->reg_instance);

	while (i->params) {
		struct input_client_param *p = i->params;
		i->params = p->next;
		ptype_cleanup(p->value);
		free(p);
	}

	if (i->datalink_dep)
		proto_remove_dependency(i->datalink_dep);

	if (i->type)
		free(i->type);

	if (i->next)
		i->next->prev = i->prev;
	if (i->prev)
		i->prev->next = i->next;
	else
		input_client_head = i->next;
	free(i);

	status = reply->status;

err:
	input_ipc_destroy_request(id);

	return status;
}

int input_client_cmd_start(struct registry_instance *ri) {

	enum core_state state = core_get_state();
	if (state != core_state_idle && state != core_state_running) {
		pomlog(POMLOG_WARN "Cannot start input, core is not ready");
		return POM_ERR;
	}

	struct input_client_entry *i = ri->priv;

	pom_mutex_lock(&i->shm_buff->lock);
	int running = i->shm_buff->flags & INPUT_FLAG_RUNNING;
	pom_mutex_unlock(&i->shm_buff->lock);

	if (running) {
		pomlog(POMLOG_ERR "Input is already running");
		return POM_ERR;
	}

	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_start;
	msg.data.start.id = i->id; 

	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);

	if (id == POM_ERR)
		return POM_ERR;

	struct input_ipc_raw_cmd_reply *reply;

	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;

	if (reply->status != POM_OK) {
		input_ipc_destroy_request(id);
		return POM_ERR;
	}

	i->datalink_dep = proto_add_dependency(reply->data.start_reply.datalink);
	if (!i->datalink_dep)
		return POM_ERR;
	
	input_ipc_destroy_request(id);

	// Start the reader thread
	struct input_client_reader_thread *t = malloc(sizeof(struct input_client_reader_thread));
	if (!t) {
		pom_oom(sizeof(struct input_client_reader_thread));
		return POM_ERR;
	}
	memset(t, 0, sizeof(struct input_client_reader_thread));

	t->input = i;
	i->thread = t;

	if (pthread_create(&t->thread, NULL, input_client_reader_thread_func, t)) {
		pomlog(POMLOG_ERR "Error while creating the reader thread : %s", pom_strerror(errno));
		free(t);
		return POM_ERR;
	}

	return POM_OK;
}

int input_client_cmd_stop(struct registry_instance *ri) {
	
	struct input_client_entry *i = ri->priv;

	pom_mutex_lock(&i->shm_buff->lock);
	int running = i->shm_buff->flags & INPUT_FLAG_RUNNING;
	pom_mutex_unlock(&i->shm_buff->lock);

	if (!running) {
		pomlog(POMLOG_ERR "Input is already stopped");
		return POM_ERR;
	}
	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_stop;
	msg.data.stop.id = i->id;

	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);

	if (id == POM_ERR)
		return POM_ERR;

	struct input_ipc_raw_cmd_reply *reply;

	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;

	int status = reply->status;
	
	input_ipc_destroy_request(id);

	pthread_t thread = 0;
	pom_mutex_lock(&input_lock);
	if (i->thread) {
		thread = i->thread->thread;
		i->thread = NULL;
	}
	pom_mutex_unlock(&input_lock);

	if (thread)
		pthread_join(thread, NULL);

	proto_remove_dependency(i->datalink_dep);
	i->datalink_dep = NULL;


	return status;
}

int input_client_registry_param_apply(void *priv, struct ptype *value) {

	struct input_client_param *p = priv;

	struct input_client_entry *i = p->input;

	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_set_param;
	msg.data.set_param.input_id = i->id;
	msg.data.set_param.param_id = p->id;
	
	if (ptype_serialize(value, msg.data.set_param.value, INPUT_PARAM_VALUE_MAX) == POM_ERR)
		return POM_ERR;

	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);

	if (id == POM_ERR)
		return POM_ERR;

	struct input_ipc_raw_cmd_reply *reply;

	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;

	int status = reply->status;
	
	input_ipc_destroy_request(id);

	return status;

}
