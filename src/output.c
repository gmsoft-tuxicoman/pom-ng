/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#include "output.h"
#include "input_server.h"
#include "registry.h"
#include "mod.h"

static struct output_reg *output_reg_head = NULL;
static struct output *output_head = NULL;
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;

static struct registry_class *output_registry_class = NULL;

int output_init() {
	
	output_registry_class = registry_add_class(OUTPUT_REGISTRY);
	if (!output_registry_class)
		return POM_ERR;

	output_registry_class->instance_add = output_instance_add;

	return POM_OK;
}

int output_cleanup() {
	
	pom_mutex_lock(&output_lock);

	while (output_head) {
		struct output *o = output_head;
		output_head = output_head->next;
		if (o->running && o->info->reg_info->close && o->info->reg_info->close(o) != POM_OK)
			pomlog(POMLOG_WARN "Error while closing the output");

		o->running = 0;

		if (o->info->reg_info->cleanup && o->info->reg_info->cleanup(o) != POM_OK)
			pomlog(POMLOG_WARN "Error while cleaning up output");

		free(o->name);
		free(o);
	}

	while (output_reg_head) {

		struct output_reg *tmp = output_reg_head;
		output_reg_head = tmp->next;

		mod_refcount_dec(tmp->reg_info->mod);

		free(tmp);
	}

	pom_mutex_unlock(&output_lock);

	if (output_registry_class)
		registry_remove_class(output_registry_class);
	output_registry_class = NULL;
	return POM_OK;

}

int output_register(struct output_reg_info *reg_info) {

	if (reg_info->api_ver != OUTPUT_API_VER) {
		pomlog(POMLOG_ERR "Cannot register output as API version differ : expected %u got %u", OUTPUT_API_VER, reg_info->api_ver);
		return POM_ERR;
	}

	if (input_server_is_current_process()) {
		pomlog(POMLOG_DEBUG "Not loading output %s in the input process", reg_info->name);
		return POM_OK;

	}

	pom_mutex_lock(&output_lock);
	struct output_reg *output = malloc(sizeof(struct output_reg));
	if (!output) {
		pom_mutex_unlock(&output_lock);
		pom_oom(sizeof(struct output_reg));
		return POM_ERR;
	}
	memset(output, 0, sizeof(struct output_reg));
	output->reg_info = reg_info;

	if (registry_add_instance_type(output_registry_class, reg_info->name) != POM_OK) {
		pom_mutex_unlock(&output_lock);
		free(output);
		return POM_ERR;
	}

	output->next = output_reg_head;
	if (output->next)
		output->next->prev = output;
	output_reg_head = output;
	pom_mutex_unlock(&output_lock);

	mod_refcount_inc(reg_info->mod);

	return POM_OK;
}

int output_instance_add(char *type, char *name) {

	struct output_reg *reg;
	for (reg = output_reg_head; reg && strcmp(reg->reg_info->name, type); reg = reg->next);

	if (!reg) {
		pomlog(POMLOG_ERR "Output type %s does not exists", type);
		return POM_ERR;
	}

	struct output *res = malloc(sizeof(struct output));
	if (!res) {
		pom_oom(sizeof(struct output));
		return POM_ERR;
	}
	memset(res, 0, sizeof(struct output));
	res->info = reg;
	res->name = strdup(name);
	if (!res->name) {
		pom_oom(strlen(name) + 1);
		return POM_ERR;
	}

	res->reg_instance = registry_add_instance(output_registry_class, name);
	if (!res->reg_instance)
		goto err;

	if (registry_instance_add_function(res->reg_instance, "start", output_instance_start, "Start the output") != POM_OK ||
		registry_instance_add_function(res->reg_instance, "stop", output_instance_stop, "Stop the output") != POM_OK)
		goto err;

	struct ptype *output_type = ptype_alloc("string");
	if (!output_type)
		goto err;

	struct registry_param *type_param = registry_new_param("type", type, output_type, "Type of the output", REGISTRY_PARAM_FLAG_CLEANUP_VAL | REGISTRY_PARAM_FLAG_IMMUTABLE);
	if (!type_param) {
		ptype_cleanup(output_type);
		goto err;
	}

	if (registry_instance_add_param(res->reg_instance, type_param) != POM_OK) {
		ptype_cleanup(output_type);
		goto err;
	}

	if (registry_uid_create(res->reg_instance) != POM_OK)
		goto err;

	res->reg_instance->priv = res;

	if (reg->reg_info->init) {
		if (reg->reg_info->init(res) != POM_OK) {
			pomlog(POMLOG_ERR "Error while initializing the output %s", name);
			goto err;
		}
	}

	res->next = output_head;
	if (res->next)
		res->next->prev = res;
	output_head = res;

	return POM_OK;

err:
	if (res->name)
		free(res->name);

	if (res->reg_instance)
		registry_remove_instance(res->reg_instance);

	free(res);

	return POM_ERR;
}

int output_instance_remove(struct registry_instance *ri) {

	struct output *o = ri->priv;

	if (o->running && output_instance_stop(ri))
		return POM_ERR;

	if (o->info->reg_info->cleanup) {
		if (o->info->reg_info->cleanup(o) != POM_OK) {
			pomlog(POMLOG_ERR "Error while cleaning up output");
			return POM_ERR;
		}
	}

	free(o->name);

	if (o->prev)
		o->prev->next = o->next;
	else
		output_head = o->next;

	if (o->next)
		o->next->prev = o->prev;

	free(o);

	return POM_OK;
}

int output_instance_start(struct registry_instance *ri) {
	
	struct output *o = ri->priv;

	if (o->running) {
		pomlog(POMLOG_ERR "Error, output already opened");
		return POM_ERR;
	}

	if (o->info->reg_info->open) {
		if (o->info->reg_info->open(o) != POM_OK) {
			pomlog(POMLOG_ERR "Error while opening the output");
			return POM_ERR;
		}
	}
	o->running = 1;

	return POM_OK;
}

int output_instance_stop(struct registry_instance *ri) {

	struct output *o = ri->priv;
	if (!o->running) {
		pomlog(POMLOG_ERR "Error, output already closed");
		return POM_ERR;
	}

	if (o->info->reg_info->close) {
		if (o->info->reg_info->close(o) != POM_OK) {
			pomlog(POMLOG_ERR "Error while closing the output");
			return POM_ERR;
		}
	}
	o->running = 0;

	return POM_OK;
}

int output_unregister(char *name) {

	pom_mutex_lock(&output_lock);
	struct output_reg *tmp;
	for (tmp = output_reg_head; tmp && strcmp(tmp->reg_info->name, name); tmp = tmp->next);

	if (!tmp) {
		pom_mutex_unlock(&output_lock);
		pomlog(POMLOG_DEBUG "Output %s is not registered, cannot unregister it", name);
		return POM_OK;
	}

	registry_remove_instance_type(output_registry_class, name);

	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		output_reg_head = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	mod_refcount_dec(tmp->reg_info->mod);

	free(tmp);

	pom_mutex_unlock(&output_lock);

	return POM_OK;
}

