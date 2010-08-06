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

int input_client_init() {
	
	return registry_add_branch("root", "input");

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
	
	input_ipc_destroy_request(id);

	if (status == POM_ERR || input_id == POM_ERR)
		return POM_ERR;

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

	// Remove the input on the other side
	input_client_cmd_remove(input_id);

	// TODO remove registry branch

	return POM_ERR;


}

int input_client_cmd_remove(unsigned int input_id) {
	
	struct input_ipc_raw_cmd msg;
	memset(&msg, 0, sizeof(struct input_ipc_raw_cmd));
	msg.subtype = input_ipc_cmd_type_remove;
	msg.data.remove.id = input_id;

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

int input_client_cmd_start(unsigned int input_id) {
	
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
	
	input_ipc_destroy_request(id);

	return status;
}

int input_client_cmd_stop(unsigned int input_id) {
	
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

	return status;
}
