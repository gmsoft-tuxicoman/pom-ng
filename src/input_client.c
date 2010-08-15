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

#include <sys/shm.h>

#include <pom-ng/ptype_string.h>

static struct input_client_entry *input_client_head;
static struct packet_info_owner *input_client_packet_info_owner;

int input_client_init() {

	const int packet_input_info_max = 1;
	struct packet_info_reg infos[packet_input_info_max + 1];
	memset(infos, 0, sizeof(struct packet_info_reg) * (packet_input_info_max + 1));
	infos[0].name = "type";
	infos[0].value_template = ptype_alloc("string");
	if (!infos[0].value_template) {
		pomlog(POMLOG_ERR "Error while allocating ptype string");
		return POM_ERR;
	}

	input_client_packet_info_owner = packet_register_info_owner("input", infos);
	if (!input_client_packet_info_owner)
		return POM_ERR;
	return registry_add_branch("root", "input");
}

int input_client_cleanup() {

	while (input_client_head) {
		struct input_client_entry *i = input_client_head;
		input_client_head = i->next;

		if (i->thread)
			core_destroy_thread(i->thread);

		if (i->shm_buff && shmdt(i->shm_buff))
			pomlog(POMLOG_WARN "Warning, error while detaching IPC shared memory segment : %s", pom_strerror(errno));

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

	return POM_OK;
}

int input_client_wait_for_empty_buff(struct input_client_entry *input) {

	struct input_buff *buff = input->shm_buff;

	int empty = 0;
	do {

		if (pthread_mutex_lock(&buff->lock)) {
			pomlog(POMLOG_ERR "Error while trying to lock the input buffer : %s", pom_strerror(errno));
			return POM_ERR;
		}

		if (!buff->inpkt_head_offset)
			empty = 1;

		if (pthread_mutex_unlock(&buff->lock)) {
			pomlog(POMLOG_ERR "Error while trying to unlock the input buffer : %s", pom_strerror(errno));
			return POM_ERR;
		}

		sleep(1);

	} while (!empty);

	if (pthread_cond_broadcast(&buff->underrun_cond)) {
		pomlog(POMLOG_ERR "Could not signal the underrun condition");
		return POM_ERR;
	}

	return POM_OK;
}

int input_client_get_packet(struct input_client_entry *input, struct packet *p) {
	
	struct input_buff *buff = input->shm_buff;

	if (pthread_mutex_lock(&buff->lock)) {
		pomlog(POMLOG_ERR "Error while trying to lock the input buffer : %s", pom_strerror(errno));
		return POM_ERR;
	}

	while (!buff->inpkt_head_offset) {
		// Wait for a packet
		if (pthread_cond_wait(&buff->underrun_cond, &buff->lock)) {
			pomlog(POMLOG_ERR "Error while waiting for underrun condition : %s", pom_strerror(errno));
			return POM_ERR;
		}

		if (!buff->inpkt_head_offset) {
			// EOF
			p->len = 0;
			return POM_OK;
		}
	}

	struct input_packet *buff_head = (struct input_packet *)(buff->inpkt_head_offset ? (void*)buff + buff->inpkt_head_offset : NULL);
	unsigned char *inpkt_buff = (unsigned char *)buff + buff_head->buff_offset;


	if (p->bufflen < buff_head->len) {
		p->buff = realloc(p->buff, buff_head->len);
		if (!p->buff) {
			pom_oom(buff_head->len);
			return POM_ERR;
		}
		p->bufflen = buff_head->len;
	}

	memcpy(&p->ts, &buff_head->ts, sizeof(struct timeval));
	p->len = buff_head->len;
	memcpy(p->buff, inpkt_buff, buff_head->len);

	buff->inpkt_head_offset = buff_head->inpkt_next_offset;
	if (!buff->inpkt_head_offset)
		buff->inpkt_tail_offset = 0;

	if (pthread_mutex_unlock(&buff->lock)) {
		pomlog(POMLOG_ERR "Error while trying to unlock the input buffer : %s", pom_strerror(errno));
		return POM_ERR;
	}

	struct packet_info_list *info = packet_add_infos(p, input_client_packet_info_owner);
	if (!info)
		return POM_ERR;

	PTYPE_STRING_SETVAL(info->values[0].value, input->type);


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

int input_client_cmd_add(char *name) {
	
	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_add;
	strncpy(msg.data.add.name, name, INPUT_NAME_MAX);

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

	// Get the shm_id
	int shm_id = shmget(shm_key, shm_buff_size, 0);
	if (shm_id == -1) {
		pomlog(POMLOG_ERR "Cannot get SHM id : %s", pom_strerror(errno));
		return POM_ERR;
	}

	// Try to attach the shared memory
	void *buff = NULL;
	buff = shmat(shm_id, NULL, 0);
	if (buff == (void*)-1) {
		pomlog(POMLOG_ERR "Error while attaching the IPC shared memory segment : %s", pom_strerror(errno));
		abort();
		goto err;
	}

	struct input_client_entry *entry = malloc(sizeof(struct input_client_entry));
	if (!entry) {
		pom_oom(sizeof(struct input_client_entry));
		goto err;
	}

	memset(entry, 0, sizeof(struct input_client_entry));

	entry->type = strdup(name);
	if (!entry->type) {
		pom_oom(sizeof(struct packet));
		goto err;
	}

	entry->id = input_id;
	entry->shm_id = shm_id;
	entry->shm_buff = buff;

	entry->next = input_client_head;
	input_client_head = entry;
	if (entry->next)
		entry->next->prev = entry;

	// Add the input in the registry
	
	char num[16];
	memset(num, 0, sizeof(num));
	snprintf(num, sizeof(num), "%u", input_id);
	if (registry_add_branch(REGISTRY_ROOT "." INPUT_CLIENT_REGISTRY, num) != POM_OK)
		goto err;
	char branch[strlen(REGISTRY_ROOT "." INPUT_CLIENT_REGISTRY ".") + sizeof(num) + 1];
	strcpy(branch, REGISTRY_ROOT "." INPUT_CLIENT_REGISTRY ".");
	strcat(branch, num);

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

		pomlog("Got param %s of type %s, with defval %s", reply->data.get_param.name, reply->data.get_param.type, reply->data.get_param.defval);

		struct ptype *value = ptype_alloc(reply->data.get_param.type);
		if (!value) {
			input_ipc_destroy_request(id);
			goto err;
		}

		if (registry_add_param(	branch,
					reply->data.get_param.name,
					reply->data.get_param.defval,
					value,
					reply->data.get_param.description,
					reply->data.get_param.flags | REGISTRY_FLAG_CLEANUP_VAL
					) != POM_OK) {
			ptype_cleanup(value);
			input_ipc_destroy_request(id);
			goto err;
		}
		
		last = reply->data.get_param.last;
		input_ipc_destroy_request(id);

		msg.data.get_param.param_id++;

	} while (!last);

	return input_id;

err:

	if (entry) {
		if (entry->type)
			free(entry->type);
		free(entry);
	}

	if (buff) 
		shmdt(buff);
	
	// Remove the input on the other side
	input_client_cmd_remove(input_id);

	// TODO remove registry branch

	return POM_ERR;


}

int input_client_cmd_remove(unsigned int input_id) {
	
	struct input_client_entry *i;
	for (i = input_client_head; i && i->id != input_id; i = i->next);
	if (!i) {
		pomlog(POMLOG_ERR "Input with id %u does not exists", input_id);
		return POM_ERR;
	}

	if (i->thread) {
		pomlog(POMLOG_WARN "Cannot remove input %u as it's running");
		return POM_ERR;
	}

	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_remove;
	msg.data.remove.id = input_id;

	int status = POM_ERR;
	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);

	if (id == POM_ERR)
		goto err;

	struct input_ipc_raw_cmd_reply *reply;

	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		goto err;

	if (i->shm_buff && shmdt(i->shm_buff))
		pomlog(POMLOG_WARN "Warning, error while detaching IPC shared memory segment : %s", pom_strerror(errno));

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

	status = reply->status;

err:
	input_ipc_destroy_request(id);

	return status;
}

int input_client_cmd_start(unsigned int input_id) {
	
	
	struct input_client_entry *i;
	for (i = input_client_head; i && i->id != input_id; i = i->next);
	if (!i) {
		pomlog(POMLOG_ERR "Input with id %u does not exists", input_id);
		return POM_ERR;
	}

	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_start;
	msg.data.start.id = input_id;

	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);

	if (id == POM_ERR)
		return POM_ERR;

	struct input_ipc_raw_cmd_reply *reply;

	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;

	int status = reply->status;

	i->datalink_dep = proto_add_dependency(reply->data.start_reply.datalink);
	if (!i->datalink_dep) {
		input_ipc_destroy_request(id);
		return POM_ERR;
	}
	
	input_ipc_destroy_request(id);

	i->thread = core_spawn_thread(i);
	if (!i->thread)
		return POM_ERR;

	return status;
}

int input_client_cmd_stop(unsigned int input_id) {
	
	struct input_client_entry *i;
	for (i = input_client_head; i && i->id != input_id; i = i->next);
	if (!i) {
		pomlog(POMLOG_ERR "Input with id %u does not exists", input_id);
		return POM_ERR;
	}

	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_stop;
	msg.data.stop.id = input_id;

	uint32_t id = input_ipc_send_request(input_ipc_get_queue(), &msg);

	if (id == POM_ERR)
		return POM_ERR;

	struct input_ipc_raw_cmd_reply *reply;

	if (input_ipc_reply_wait(id, &reply) == POM_ERR)
		return POM_ERR;

	int status = reply->status;
	
	input_ipc_destroy_request(id);

	if (core_destroy_thread(i->thread))
		return POM_ERR;
	i->thread = NULL;

	proto_remove_dependency(i->datalink_dep);
	i->datalink_dep = NULL;

	return status;
}
