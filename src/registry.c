/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include "registry.h"
#include "core.h"
#include "xmlrpccmd.h"
#include "datastore.h"
#include "main.h"
#include <pom-ng/ptype.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_timestamp.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/ptype_uint64.h>

static struct datavalue_template registry_config_list_dataset_template[] = {

	{ .name = "name", .type = "string" },
	{ .name = "timestamp", .type = "timestamp" },

	{ 0 }

};

static struct datavalue_template registry_config_dataset_template[] = {
	{ .name = "config_id", .type = "uint64" },
	{ .name = "entry", .type = "string" },
	{ .name = "value", .type = "string" },
	{ .name = "type", .type = "uint8" },

	{ 0 }
};

static pthread_mutex_t registry_global_lock;
static struct registry_class *registry_head = NULL;

static uint32_t *registry_uid_table = NULL;
static size_t registry_uid_table_size = 0;
static unsigned int registry_uid_seedp = 0;
static uint32_t registry_serial = 0, registry_classes_serial = 0, registry_config_serial = 0;

int registry_init() {

	if (pom_mutex_init_type(&registry_global_lock, PTHREAD_MUTEX_RECURSIVE) != POM_OK)
		return POM_ERR;


	// Init random numbers for UIDs
	registry_uid_seedp = (unsigned int) time(NULL) + (unsigned int) pthread_self();
		

	return POM_OK;
}

int registry_cleanup() {

	while (registry_head) {
		if (registry_remove_class(registry_head) != POM_OK)
			return POM_ERR;
	}

	pthread_mutex_destroy(&registry_global_lock);

	free(registry_uid_table);
	
	return POM_OK;
}

void registry_lock() {
	pom_mutex_lock(&registry_global_lock);
}

void registry_unlock() {
	pom_mutex_unlock(&registry_global_lock);
}

struct registry_class *registry_get() {
	return registry_head;
}

struct registry_class* registry_add_class(char *name) {

	if (!name)
		return NULL;

	registry_lock();

	struct registry_class *c = registry_head;
	for (;c && strcmp(c->name, name); c = c->next);
	if (c) {
		pomlog(POMLOG_WARN "Cannot add class %s as it already exists", name);
		registry_unlock();
		return NULL;
	}

	c = malloc(sizeof(struct registry_class));
	if (!c) {
		pom_oom(sizeof(struct registry_class));
		registry_unlock();
		return NULL;
	}

	memset(c, 0, sizeof(struct registry_class));

	c->name = strdup(name);
	if (!c->name) {
		registry_unlock();
		free(c);
		pom_oom(strlen(name));
		return NULL;
	}

	c->next = registry_head;
	if (c->next)
		registry_head->prev = c;
	registry_head = c;
	registry_unlock();

	return c;
}

int registry_remove_class(struct registry_class *c) {

	if (!c)
		return POM_OK;

	registry_lock();

	if (c->prev)
		c->prev->next = c->next;
	else
		registry_head = c->next;
	
	if (c->next)
		c->next->prev = c->prev;

	while (c->types) {
		struct registry_instance_type *t = c->types;
		c->types = c->types->next;
		free(t->name);
		free(t);
	}


	while (c->instances) {
		if (registry_remove_instance(c->instances) != POM_OK) {
			pomlog(POMLOG_WARN "Some error occured while removing an instance");
			break;
		}
	}

	registry_unlock();

	while (c->global_params) {
		struct registry_param *p = c->global_params;
		c->global_params = p->next;

		free(p->name);
		if (p->default_value)
			free(p->default_value);
		free(p->description);

		if (p->flags & REGISTRY_PARAM_FLAG_CLEANUP_VAL)
			ptype_cleanup(p->value);

		free(p);
	}

	while (c->perfs) {
		struct registry_perf *p = c->perfs;
		c->perfs = p->next;

		if (p->update_hook) {
			int res = pthread_mutex_destroy(&p->hook_lock);
			if (res) {
				pomlog(POMLOG_ERR "Error while destroying perf hook lock : %s", pom_strerror(errno));
				abort();
			}
		}

		free(p->name);
		free(p->description);
		free(p->unit);
		free(p);
	}

	free(c->name);

	free(c);

	return POM_OK;
}

int registry_add_instance_type(struct registry_class *c, char *name) {

	struct registry_instance_type *type = malloc(sizeof(struct registry_instance_type));
	if (!type) {
		pom_oom(sizeof(struct registry_instance_type));
		return POM_ERR;
	}
	memset(type, 0, sizeof(struct registry_instance_type));
	
	type->name = strdup(name);
	if (!type->name) {
		free(type);
		pom_oom(strlen(name) + 1);
		return POM_ERR;
	}

	registry_lock();

	type->next = c->types;
	if (type->next)
		type->next->prev = type;
	c->types = type;

	registry_unlock();

	return POM_OK;
}

int registry_remove_instance_type(struct registry_class *c, char *name) {

	struct registry_instance_type *type;

	registry_lock();

	for (type = c->types; type && strcmp(type->name, name); type = type->next);

	if (!type) {
		registry_unlock();
		pomlog(POMLOG_ERR "Registry instance type %s not found in class %s", name, c->name);
		return POM_ERR;
	}

	if (type->next)
		type->next->prev = type->prev;
	
	if (type->prev)
		type->prev->next = type->next;
	else
		c->types = type->next;

	registry_unlock();

	free(type->name);
	free(type);

	return POM_OK;
}

struct registry_instance *registry_add_instance(struct registry_class *c, char *name) {

	if (!name || !c)
		return NULL;

	struct registry_instance *i = malloc(sizeof(struct registry_instance));
	if (!i) {
		pom_oom(sizeof(struct registry_instance));
		return NULL;
	}

	memset(i, 0, sizeof(struct registry_instance));

	
	i->name = strdup(name);
	if (!i->name) {
		free(i);
		pom_oom(strlen(name));
		return NULL;
	}


	i->parent = c;

	registry_lock();

	i->next = c->instances;
	if (i->next)
		i->next->prev = i;
	c->instances = i;
	
	i->parent->serial++;
	registry_classes_serial_inc();

	registry_unlock();


	return i;

}

int registry_remove_instance(struct registry_instance *i) {

	if (!i)
		return POM_ERR;


	registry_lock();

	struct registry_class *c = i->parent;

	if (c->instance_remove && c->instance_remove(i) != POM_OK) {
		pomlog(POMLOG_ERR "Error while removing the instance %s from class %s", i->name, c->name);
		registry_unlock();
		return POM_ERR;

	}

	free(i->name);
	
	while (i->params) {
		struct registry_param *p = i->params;
		i->params = p->next;

		free(p->name);
		if (p->default_value)
			free(p->default_value);
		free(p->description);

		if (p->flags & REGISTRY_PARAM_FLAG_CLEANUP_VAL)
			ptype_cleanup(p->value);

		free(p);
	}

	while (i->funcs) {
		struct registry_function *f = i->funcs;
		i->funcs = f->next;
		free(f->name);
		free(f->description);
		free(f);
	}

	while (i->perfs) {
		struct registry_perf *p = i->perfs;
		i->perfs = p->next;

		if (p->update_hook) {
			int res = pthread_mutex_destroy(&p->hook_lock);
			if (res) {
				pomlog(POMLOG_ERR "Error while destroying perf hook lock : %s", pom_strerror(errno));
				abort();
			}
		}

		free(p->name);
		free(p->description);
		free(p->unit);
		free(p);
	}

	if (i->prev)
		i->prev->next = i->next;
	else 
		c->instances = i->next;

	if (i->next)
		i->next->prev = i->prev;

	c->serial++;
	registry_classes_serial_inc();

	registry_unlock();

	free(i);

	return POM_OK;
}

struct registry_param* registry_new_param(char *name, char *default_value, struct ptype *value, char *description, int flags) {

	if (!name || !value || !description)
		return NULL;

	struct registry_param *p = malloc(sizeof(struct registry_param));
	if (!p) {
		pom_oom(sizeof(struct registry_param));
		return NULL;
	}

	memset(p, 0, sizeof(struct registry_param));

	p->name = strdup(name);
	if (!p->name) {
		pom_oom(strlen(name));
		goto err;
	}

	if (default_value) {
		p->default_value = strdup(default_value);
		if (!p->default_value) {
			pom_oom(strlen(default_value));
			goto err;
		}

		if (ptype_parse_val(value, default_value) != POM_OK) {
			pomlog(POMLOG_ERR "Error while parsing default parameter \"%s\" of type \"%s\"", default_value, value->type);
			goto err;
		}
	} else if (! (flags & REGISTRY_PARAM_FLAG_IMMUTABLE) ) {
		pomlog(POMLOG_ERR "default value is required when adding non immutable parameter");
		goto err;
	}

	p->description = strdup(description);
	if (!p->description) {
		pom_oom(strlen(description));
		goto err;
	}
	
	p->flags = flags;
	p->value = value;

	return p;

err:
	if (p->default_value)
		free(p->default_value);
	
	if (p->name)
		free(p->name);
	free(p);


	return NULL;
}

int registry_cleanup_param(struct registry_param *p) {

	if (!p)
		return POM_ERR;
	
	if (p->name)
		free(p->name);

	if (p->default_value)
		free(p->default_value);
	
	if (p->description)
		free(p->description);

	free(p);
	
	return POM_OK;
}


int registry_param_set_callbacks(struct registry_param *p, void *priv, int (*pre_callback) (void *priv, char *value), int (*post_callback) (void *priv, struct ptype* value)) {
	
	p->callback_priv = priv;
	p->set_pre_callback = pre_callback;
	p->set_post_callback = post_callback;

	return POM_OK;
}

int registry_class_add_param(struct registry_class *c, struct registry_param *p) {

	if (!c || !p)
		return POM_ERR;

	registry_lock();

	if (c->global_params) {
		// Add at the end
		struct registry_param *tmp = c->global_params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = p;
		p->prev = tmp;
	} else {
		c->global_params = p;
		p->prev = NULL;
	}
	p->next = NULL;

	registry_unlock();

	return POM_OK;
}

int registry_instance_add_param(struct registry_instance *i, struct registry_param *p) {

	if (!i || !p)
		return POM_ERR;

	registry_lock();

	if (i->params) {
		// Add at the end
		struct registry_param *tmp = i->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = p;
		p->prev = tmp;
	} else {
		i->params = p;
		p->prev = NULL;
	}
	p->next = NULL;

	registry_unlock();

	return POM_OK;
}

int registry_instance_add_function(struct registry_instance *i, char *name, int (*handler) (struct registry_instance *), char *description) {

	if (!i || !name || !handler || !description)
		return POM_ERR;

	struct registry_function *f = malloc(sizeof(struct registry_function));
	if (!f) {
		pom_oom(sizeof(struct registry_function));
		return POM_ERR;
	}

	memset(f, 0, sizeof(struct registry_function));

	f->name = strdup(name);
	if (!f->name) {
		pom_oom(strlen(name));
		goto err;
	}

	f->description = strdup(description);
	if (!f->description) {
		pom_oom(strlen(description));
		goto err;
	}

	f->handler = handler;

	registry_lock();

	f->next = i->funcs;
	i->funcs = f;


	registry_unlock();

	return POM_OK;

err:
	if (f->name)
		free(name);
	if (f->description)
		free(f->description);
	
	free(f);

	return POM_ERR;
}

int registry_set_param(struct registry_instance *i, char *param, char* value) {

	registry_lock();
	
	struct registry_param *p;
	for (p = i->params; p && strcmp(p->name, param); p = p->next);
	
	if (!p) {
		registry_unlock();
		pomlog(POMLOG_ERR "Parameter %s doesn't exists for registry instance %s", param, i->name);
		return POM_ERR;
	}

	if (p->flags & REGISTRY_PARAM_FLAG_IMMUTABLE) {
		registry_unlock();
		pomlog(POMLOG_ERR "Cannot change parameter %s for instance %s as it's marked immutable", param, i->name);
		return POM_ERR;
	}

	if (registry_set_param_value(p, value) != POM_OK) {
		registry_unlock();
		return POM_ERR;
	}

	i->serial++;
	i->parent->serial++;
	registry_classes_serial_inc();

	registry_unlock();

	return POM_OK;
}

int registry_set_param_value(struct registry_param *p, char *value) {

	if (!p || !value)
		return POM_ERR;

	if (p->flags & REGISTRY_PARAM_FLAG_IMMUTABLE)
		return POM_ERR;
	
	if (p->set_pre_callback && p->set_pre_callback(p->callback_priv, value) != POM_OK) {
		return POM_ERR;
	}

	core_pause_processing();

	struct ptype *old_value = ptype_alloc_from(p->value);

	if (ptype_parse_val(p->value, value) != POM_OK) {
		core_resume_processing();
		ptype_cleanup(old_value);
		return POM_ERR;
	}

	if (p->set_post_callback && p->set_post_callback(p->callback_priv, p->value) != POM_OK) {
		// Revert the old value
		ptype_copy(p->value, old_value);
		core_resume_processing();
		ptype_cleanup(old_value);
		return POM_ERR;
	}

	core_resume_processing();

	ptype_cleanup(old_value);
	
	return POM_OK;

}


struct registry_class *registry_find_class(char *cls) {

//	registry_lock();	

	struct registry_class *res = registry_head;
	for (; res && strcmp(res->name, cls); res = res->next);

//	registry_unlock();

	return res;
}

struct registry_instance *registry_find_instance(char *cls, char *instance) {

	struct registry_instance *res = NULL;
	struct registry_class *c = registry_head;

//	registry_lock();

	for (; c && strcmp(c->name, cls); c = c->next);
	if (!c) {
//		registry_unlock();
		return NULL;
	}

	for (res = c->instances; res && strcmp(res->name, instance); res = res->next);

//	registry_unlock();

	return res;
}

static int registry_uid_check(uint32_t uid) {

	if (!uid) // 0 is not allowed
		return POM_ERR;

	size_t i;
	for (i = 0; i < registry_uid_table_size; i++) {
		if (registry_uid_table[i] == uid)
			return POM_ERR;
	}

	return POM_OK;

}

static int registry_uid_add(struct registry_instance *instance, uint32_t uid) {

	// Add the uid to the instance
	struct ptype *uid_ptype = ptype_alloc("uint32");
	if (!uid_ptype) 
		return POM_ERR;

	PTYPE_UINT32_SETVAL(uid_ptype, uid);
	struct registry_param* uid_param = registry_new_param("uid", NULL, uid_ptype, "Unique ID", REGISTRY_PARAM_FLAG_CLEANUP_VAL | REGISTRY_PARAM_FLAG_IMMUTABLE);

	if (!uid_param) {
		ptype_cleanup(uid_ptype);
		return POM_ERR;
	}

	// Add the new uid to the table

	registry_uid_table_size++;
	uint32_t *new_uid_table = realloc(registry_uid_table, sizeof(uint32_t) * registry_uid_table_size);
	if (!new_uid_table) {
		pom_oom(sizeof(uint32_t) * registry_uid_table_size);
		ptype_cleanup(uid_ptype);
		return POM_ERR;
	}
	registry_uid_table = new_uid_table;
	registry_uid_table[registry_uid_table_size - 1] = uid;


	if (registry_instance_add_param(instance, uid_param) != POM_OK) {
		registry_cleanup_param(uid_param);
		ptype_cleanup(uid_ptype);
		registry_uid_table_size--;
		return POM_ERR;
	}

	return POM_OK;

}

int registry_uid_create(struct registry_instance *instance) {


	registry_lock();

	// Find a good uid
	uint32_t new_uid;
	do {
		new_uid = rand_r(&registry_uid_seedp);
			
	} while (registry_uid_check(new_uid));

	if (registry_uid_add(instance, new_uid) != POM_OK) {
		registry_unlock();
		return POM_ERR;
	}

	registry_unlock();

	return POM_OK;

}

int registry_uid_assign(struct registry_instance *instance, char* uid) {


	registry_lock();
	
	struct registry_param *p;
	for (p = instance->params; p && strcmp(p->name, "uid"); p = p->next);
	
	if (!p) {
		pomlog(POMLOG_ERR "Could not find the uid parameter");
		registry_unlock();
		return POM_ERR;
	}

	uint32_t old_uid = *PTYPE_UINT32_GETVAL(p->value);

	if (ptype_parse_val(p->value, uid) != POM_OK) {
		pomlog(POMLOG_ERR "Could not parse the new uid");
		registry_unlock();
		return POM_ERR;
	}

	uint32_t new_uid = *PTYPE_UINT32_GETVAL(p->value);

	size_t i;
	for (i = 0; registry_uid_table[i] != old_uid && i < registry_uid_table_size; i++);
	if (i < registry_uid_table_size) {
		registry_uid_table[i] = new_uid;
	}


	registry_unlock();

	return POM_OK;
}


void registry_classes_serial_inc() {
	registry_classes_serial++;
	registry_serial++;
	xmlrcpcmd_serial_inc();
}


uint32_t registry_serial_get() {
	return registry_serial;
}

uint32_t registry_classes_serial_get() {
	return registry_classes_serial;
}

uint32_t registry_config_serial_get() {
	return registry_config_serial;
}


struct registry_config_entry* registry_config_list() {

	struct dataset_query *dsq_config_list = NULL;

	struct registry_config_entry *list = NULL;
	ssize_t list_size = 0;

	struct datastore *sys_dstore = system_datastore();
	if (!sys_dstore)
		return NULL;

	struct datastore_connection *dc = datastore_connection_new(sys_dstore);
	if (!dc)
		return NULL;

	dsq_config_list = datastore_dataset_query_open(sys_dstore, REGISTRY_CONFIG_LIST, registry_config_list_dataset_template, dc);
	if (!dsq_config_list)
		goto err;

	int res;

	while ((res = datastore_dataset_read(dsq_config_list)) != DATASET_QUERY_OK) {
		if (res < 0)
			goto err;

		if (dsq_config_list->values[0].is_null || dsq_config_list->values[1].is_null) {
			pomlog(POMLOG_ERR "Got NULL values while they were not supposed to be !");
			goto err;
		}

		
		struct registry_config_entry *new_list = realloc(list, sizeof(struct registry_config_entry) * (list_size + 2));
		if (!new_list) {
			pom_oom(sizeof(struct registry_config_entry) * (list_size + 2));
			goto err;
		}
		list = new_list;
		memset(&list[list_size], 0, sizeof(struct registry_config_entry) * 2);

		char *name = PTYPE_STRING_GETVAL(dsq_config_list->values[0].value);
		strncpy(list[list_size].name, name, REGISTRY_CONFIG_NAME_MAX - 1);
		list[list_size].ts = *PTYPE_TIMESTAMP_GETVAL(dsq_config_list->values[1].value);

		list_size++;
	}

	datastore_dataset_query_cleanup(dsq_config_list);

	datastore_connection_release(dc);

	return list;
err:
	if (dsq_config_list)
		datastore_dataset_query_cleanup(dsq_config_list);

	if (dc)
		datastore_connection_release(dc);

	if (list)
		free(list);

	return NULL;
}

int registry_config_save(char *config_name) {

	if (strlen(config_name) >= REGISTRY_CONFIG_NAME_MAX) {
		pomlog(POMLOG_ERR "Configuration name too long, max %u characters.", REGISTRY_CONFIG_NAME_MAX);
		return POM_ERR;
	}

	struct dataset_query *dsq_config_list = NULL, *dsq_config = NULL;
	
	struct datastore *sys_dstore = system_datastore();
	if (!sys_dstore)
		return POM_ERR;

	struct datastore_connection *dc = datastore_connection_new(sys_dstore);
	if (!dc)
		return POM_ERR;

	dsq_config_list = datastore_dataset_query_open(sys_dstore, REGISTRY_CONFIG_LIST, registry_config_list_dataset_template, dc);
	if (!dsq_config_list)
		goto err;

	if (datastore_dataset_query_set_string_condition(dsq_config_list, 0, PTYPE_OP_EQ, config_name) != POM_OK)
		goto err;

	dsq_config = datastore_dataset_query_open(sys_dstore, REGISTRY_CONFIG, registry_config_dataset_template, dc);
	if (!dsq_config)
		goto err;

	if (datastore_transaction_begin(dc) != POM_OK)
		goto err;

	// Find out if we already have a config by that name
	int res = datastore_dataset_read_single(dsq_config_list);
	if (res == DATASET_QUERY_MORE) {

		// Delete existing stuff about this config
		if (datastore_dataset_query_set_uint64_condition(dsq_config, 0, PTYPE_OP_EQ, dsq_config_list->data_id) != POM_OK)
			goto err;

		if (datastore_dataset_delete(dsq_config_list) != DATASET_QUERY_OK)
			goto err;

		if (datastore_dataset_delete(dsq_config) != DATASET_QUERY_OK)
			goto err;
	}

	if (res < 0)
		goto err;

	// Add the config to the config list
	PTYPE_STRING_SETVAL(dsq_config_list->values[0].value, config_name);
	PTYPE_TIMESTAMP_SETVAL(dsq_config_list->values[1].value, pom_gettimeofday());

	if (datastore_dataset_write(dsq_config_list) != DATASET_QUERY_OK)
		goto err;



	PTYPE_UINT64_SETVAL(dsq_config->values[0].value, dsq_config_list->data_id);

	registry_lock();
	struct registry_class *cls;

	// Browse each class
	for (cls = registry_head; cls; cls = cls->next) {

		// Browse each instance of the class
		struct registry_instance *inst;
		for (inst = cls->instances; inst; inst = inst->next) {
			
			// Don't add the instance if it's not added by the user
			
			if (cls->instance_add) {

				// The system datastore will always exist
				if (inst == sys_dstore->reg_instance)
					continue;

				char *buff = malloc(strlen(cls->name) + 1 + strlen(inst->name) + 1);
				if (!buff) {
					pom_oom(strlen(cls->name) + 1 + strlen(inst->name) + 1);
					goto err_locked;
				}

				strcpy(buff, cls->name);
				strcat(buff, ".");
				strcat(buff, inst->name);
				PTYPE_STRING_SETVAL_P(dsq_config->values[1].value, buff);

				struct registry_param *p;
				for (p = inst->params; p && strcmp(p->name, "type"); p = p->next);

				if (p) {
					dsq_config->values[2].is_null = 0;
					char *type = PTYPE_STRING_GETVAL(p->value);
					PTYPE_STRING_SETVAL(dsq_config->values[2].value, type);
				} else {
					dsq_config->values[2].is_null = 1;
				}

				PTYPE_UINT8_SETVAL(dsq_config->values[3].value, registry_config_instance);

				if (datastore_dataset_write(dsq_config) != DATASET_QUERY_OK)
					goto err_locked;

			}

			// Browse the parametrers and add the non default ones

			struct registry_param *param;
			for (param = inst->params; param; param = param->next) {

				// Check if the parameter value is not the default one anymore
				if (param->default_value) {
					struct ptype *defval = ptype_alloc_from(param->value);
					if (!defval)
						goto err_locked;

					if (ptype_parse_val(defval, param->default_value) != POM_OK) {
						pomlog(POMLOG_ERR "Unable to parse default value !");
						ptype_cleanup(defval);
						goto err_locked;
					}

					if (ptype_compare_val(PTYPE_OP_EQ, param->value, defval)) {
						// Param still has the default value, do nothing
						ptype_cleanup(defval);
						continue;
					}

					ptype_cleanup(defval);
				}

				char *buff = malloc(strlen(cls->name) + 1 + strlen(inst->name) + 1 + strlen(param->name) + 1);
				if (!buff) {
					pom_oom(strlen(cls->name) + 1 + strlen(inst->name) + 1 + strlen(param->name) + 1);
					goto err_locked;
				}
				strcpy(buff, cls->name);
				strcat(buff, ".");
				strcat(buff, inst->name);
				strcat(buff, ".");
				strcat(buff, param->name);
				PTYPE_STRING_SETVAL_P(dsq_config->values[1].value, buff);

				char *value = ptype_print_val_alloc(param->value, NULL);
				if (!value)
					goto err_locked;
				
				dsq_config->values[2].is_null = 0;
				PTYPE_STRING_SETVAL_P(dsq_config->values[2].value, value);

				PTYPE_UINT8_SETVAL(dsq_config->values[3].value, registry_config_instance_param);

				if (datastore_dataset_write(dsq_config) != DATASET_QUERY_OK)
					goto err_locked;
			}
		
		}

	}

	registry_config_serial++;
	registry_serial++;
	xmlrcpcmd_serial_inc();

	registry_unlock();

	if (datastore_transaction_commit(dc) != POM_OK)
		goto err;

	datastore_dataset_query_cleanup(dsq_config_list);
	datastore_dataset_query_cleanup(dsq_config);
	
	datastore_connection_release(dc);

	pomlog("Registry configuration saved as \"%s\"", config_name);

	return POM_OK;

err_locked:
	registry_unlock();

err:
	if (dsq_config_list)
		datastore_dataset_query_cleanup(dsq_config_list);

	if (dsq_config)
		datastore_dataset_query_cleanup(dsq_config);

	if (dc) {
		datastore_transaction_rollback(dc);
		datastore_connection_release(dc);
	}

	return POM_ERR;

}

int registry_config_reset() {
	
	registry_lock();

	// Reset the UID table
	size_t old_uid_table_size = registry_uid_table_size;
	registry_uid_table_size = 0;

	struct datastore *sys_dstore = system_datastore();
	int restore_sys_dstore = 0;

	struct registry_class *cls;

	for (cls = registry_head; cls; cls = cls->next) {

		/* TODO : registry parameters */
		
		if (cls->instance_remove) {
		
			// If we can, remove the instances
			while (cls->instances) {
				
				// Do not remove the system datastore !
				if (cls->instances == sys_dstore->reg_instance) {
					cls->instances = cls->instances->next;
					if (cls->instances)
						cls->instances->prev = NULL;
					restore_sys_dstore = 1;
					continue;
				}

				if (registry_remove_instance(cls->instances) != POM_OK) {
					// cls->instances might be invalid at this point so don't reference it
					pomlog(POMLOG_ERR "Unable to remove an instance from class %s", cls->name);
					if (restore_sys_dstore) {
						cls->instances = sys_dstore->reg_instance;
						cls->instances->prev = NULL;
						cls->instances->next = NULL;
						restore_sys_dstore = 0;
					}
					goto err;
				}
			}

			if (restore_sys_dstore) {
				cls->instances = sys_dstore->reg_instance;
				cls->instances->prev = NULL;
				cls->instances->next = NULL;
				restore_sys_dstore = 0;
			}

		} else {
			// Else reset all the parameters of each instance
			struct registry_instance *inst;
			for (inst = cls->instances; inst; inst = inst->next) {
				struct registry_param *param;
				for (param = inst->params; param; param = param->next) {
					if (registry_set_param_value(param, param->default_value) != POM_OK) {
						pomlog(POMLOG_ERR "Unable to reset the default value of parameter %s.%s.%s", cls->name, inst->name, param->name);
						goto err;
					}
				}
			}

		}
	}

	registry_classes_serial_inc();
	registry_unlock();

	return POM_OK;

err:

	registry_uid_table_size = old_uid_table_size;
	return POM_ERR;


}

int registry_config_load(char *config_name) {

	struct dataset_query *dsq_config_list = NULL, *dsq_config = NULL;
	
	struct datastore *sys_dstore = system_datastore();
	if (!sys_dstore)
		return POM_ERR;


	// Find what is the id corresponding to the name given if any
	dsq_config_list = datastore_dataset_query_open(sys_dstore, REGISTRY_CONFIG_LIST, registry_config_list_dataset_template, NULL);
	if (!dsq_config_list)
		goto err;

	if (datastore_dataset_query_set_string_condition(dsq_config_list, 0, PTYPE_OP_EQ, config_name) != POM_OK)
		goto err;

	int res = datastore_dataset_read_single(dsq_config_list);

	if (res < 0)
		goto err;

	if (res == DATASET_QUERY_OK) {
		pomlog(POMLOG_ERR "Configuration \"%s\" not found in the database", config_name);
		goto err;
	}

	uint64_t config_id = dsq_config_list->data_id;

	datastore_dataset_query_cleanup(dsq_config_list);
	dsq_config_list = NULL;

	// Fetch the config
	dsq_config = datastore_dataset_query_open(sys_dstore, REGISTRY_CONFIG, registry_config_dataset_template, NULL);
	if (!dsq_config)
		goto err;

	if (datastore_dataset_query_set_uint64_condition(dsq_config, 0, PTYPE_OP_EQ, config_id) != POM_OK)
		goto err;

	// Fetch the config in a convenient way
	if (datastore_dataset_query_set_order(dsq_config, 3, DATASET_READ_ORDER_ASC) != POM_OK)
		goto err;

	registry_lock();

	// Reset the registry
	if (registry_config_reset() != POM_OK)
		goto err_locked;


	while ((res = datastore_dataset_read(dsq_config)) != DATASET_QUERY_OK) {
		if (res < 0)
			goto err_locked;

		if (dsq_config->values[1].is_null || dsq_config->values[3].is_null) {
			pomlog(POMLOG_ERR "Got NULL values while they were not supposed to be !");
			goto err_locked;
		}
		enum registry_config_entry_types type = *PTYPE_UINT8_GETVAL(dsq_config->values[3].value);
		char *entry = PTYPE_STRING_GETVAL(dsq_config->values[1].value);
		char *value = NULL;
		if (!dsq_config->values[2].is_null)
			value = PTYPE_STRING_GETVAL(dsq_config->values[2].value);

		// Parse the entry
		char *name1 = strdup(entry);
		if (!name1) {
			pom_oom(strlen(entry) + 1);
			goto err_locked;
		}
		char *name2 = strchr(name1, '.');
		if (!name2) {
			pomlog(POMLOG_ERR "Unparseable entry name \"%s\"", entry);
			free(name1);
			goto err_locked;
		}
		*name2 = 0;
		name2++;

		char *name3 = strchr(name2, '.');
		if (name3) {
			*name3 = 0;
			name3++;
		}

		switch (type) {

			case registry_config_instance: {

				if (!value) {
					pomlog(POMLOG_WARN "Instance type not provided for entry %s, skipping", entry);
					break;
				}

				struct registry_class *cls = registry_find_class(name1);
				if (!cls) {
					pomlog(POMLOG_WARN "Cannot add instance %s to class %s as this class doesn't exists. skipping", name2, name1);
					break;
				}

				struct registry_instance *inst;
				for (inst = cls->instances; inst && strcmp(inst->name, name2); inst = inst->next);
				if (inst) {
					pomlog(POMLOG_WARN "Cannot add instance %s as it's already in the registry, skipping", entry);
					break;
				}

				if (!cls->instance_add) {
					pomlog(POMLOG_WARN "Cannot add instances to class %s as it doesn't support it. skipping", name1);
					break;
				}

				if (cls->instance_add(value, name2) != POM_OK) {
					pomlog(POMLOG_WARN "Unable to add instance %s of type %s, skipping", entry, value);
					break;
				}

				break;

			}

			case registry_config_instance_param: {

				if (!value) {
					pomlog(POMLOG_WARN "Parameter value not provided for entry %s, skipping", entry);
					break;
				}

				if (!name3) {
					pomlog(POMLOG_WARN "Parameter name not provided for entry %s, skipping", entry);
					break;
				}

				struct registry_instance *inst = registry_find_instance(name1, name2);
				if (!inst) {
					pomlog(POMLOG_WARN "Cannot find instance %s.%s to set parameter, skipping", name1, name2);
					break;
				}


				if (!strcmp(name3, "uid")) {
					// Special handling for uids
					if (registry_uid_assign(inst, value) != POM_OK) {
						pomlog(POMLOG_WARN "Error while setting the uid, skipping");
						break;
					}

				} else if (!strcmp(name3, "running")) {
					// For now don't do anything for running

				} else {
					registry_set_param(inst, name3, value);
				}

				break;
			}
				
			
			default:
				pomlog(POMLOG_WARN "Unhandled configuration entry type %u for item %s", entry);

		}

		free(name1);
		

	}

	registry_classes_serial_inc();
	registry_unlock();

	datastore_dataset_query_cleanup(dsq_config);

	pomlog("Registry configuration \"%s\" loaded", config_name);

	return POM_OK;

err_locked:
	registry_unlock();
err:

	if (dsq_config_list)
		datastore_dataset_query_cleanup(dsq_config_list);

	if (dsq_config)
		datastore_dataset_query_cleanup(dsq_config);

	return POM_ERR;
}

int registry_config_delete(char *config_name) {

	struct dataset_query *dsq_config_list = NULL, *dsq_config = NULL;
	
	struct datastore *sys_dstore = system_datastore();
	if (!sys_dstore)
		return POM_ERR;

	registry_lock();

	// Find what is the id corresponding to the name given if any
	dsq_config_list = datastore_dataset_query_open(sys_dstore, REGISTRY_CONFIG_LIST, registry_config_list_dataset_template, NULL);
	if (!dsq_config_list)
		goto err;

	if (datastore_dataset_query_set_string_condition(dsq_config_list, 0, PTYPE_OP_EQ, config_name) != POM_OK)
		goto err;

	int res = datastore_dataset_read_single(dsq_config_list);

	if (res < 0)
		goto err;

	if (res == DATASET_QUERY_OK) {
		pomlog(POMLOG_ERR "Configuration \"%s\" not found in the database", config_name);
		goto err;
	}

	// Get the id of the list
	uint64_t config_id = dsq_config_list->data_id;

	// Fetch the config
	dsq_config = datastore_dataset_query_open(sys_dstore, REGISTRY_CONFIG, registry_config_dataset_template, NULL);
	if (!dsq_config)
		goto err;

	if (datastore_dataset_query_set_uint64_condition(dsq_config, 0, PTYPE_OP_EQ, config_id) != POM_OK)
		goto err;

	// Delete the config
	if (datastore_dataset_delete(dsq_config) != POM_OK)
		goto err;
	datastore_dataset_query_cleanup(dsq_config);

	// Delete the config in the list
	datastore_dataset_delete(dsq_config_list);
	datastore_dataset_query_cleanup(dsq_config_list);

	registry_config_serial++;
	registry_serial++;
	xmlrcpcmd_serial_inc();
	registry_unlock();

	return POM_OK;

err:
	registry_unlock();

	if (dsq_config_list)
		datastore_dataset_query_cleanup(dsq_config_list);
	if (dsq_config)
		datastore_dataset_query_cleanup(dsq_config);

	return POM_ERR;
}

struct registry_perf *registry_perf_alloc(const char *name, enum registry_perf_type type, const char *description, const char *unit) {

	struct registry_perf *perf = malloc(sizeof(struct registry_perf));
	if (!perf) {
		pom_oom(sizeof(struct registry_perf));
		return NULL;
	}
	memset(perf, 0, sizeof(struct registry_perf));

	perf->name = strdup(name);
	if (!perf->name) {
		free(perf);
		pom_oom(strlen(name) + 1);
		return NULL;
	}

	perf->description = strdup(description);
	if (!perf->description) {
		free(perf->name);
		free(perf);
		pom_oom(strlen(description) + 1);
		return NULL;
	}

	if (type == registry_perf_type_timeticks)
		unit = "usec";

	perf->unit = strdup(unit);
	if (!perf->unit) {
		free(perf->name);
		free(perf->description);
		free(perf);
		pom_oom(strlen(unit) + 1);
		return NULL;
	}

	perf->type = type;

	return perf;
}

struct registry_perf *registry_class_add_perf(struct registry_class *c, const char *name, enum registry_perf_type type, const char *description, const char *unit) {
	
	struct registry_perf *p = registry_perf_alloc(name, type, description, unit);
	if (!p)
		return NULL;

	registry_lock();
	p->next = c->perfs;
	c->perfs = p;
	registry_unlock();
	
	return p;
}

struct registry_perf *registry_instance_add_perf(struct registry_instance *i, const char *name, enum registry_perf_type type, const char *description, const char *unit) {

	struct registry_perf *p = registry_perf_alloc(name, type, description, unit);
	if (!p)
		return NULL;

	registry_lock();
	p->next = i->perfs;
	i->perfs = p;
	registry_unlock();
	
	return p;
}

void registry_perf_set_update_hook(struct registry_perf *p, int (*update_hook) (uint64_t *cur_val, void *priv), void *hook_priv) {

	if (p->type == registry_perf_type_timeticks) {
		pomlog(POMLOG_ERR "Trying to set an update hook on a timeticks perf");
		return;
	}

	if (!update_hook) {
		if (p->update_hook) {
			int res = pthread_mutex_destroy(&p->hook_lock);
			if (res) {
				pomlog(POMLOG_ERR "Error while destroying the perf hook lock : %s", pom_strerror(res));
				abort();
			}
		}
		p->update_hook = NULL;
		p->hook_priv = NULL;
		return;
	}

	if (!p->update_hook) {
		int res = pthread_mutex_init(&p->hook_lock, NULL);
		if (res) {
			pomlog(POMLOG_ERR "Error while initializing the perf hook lock : %s", pom_strerror(res));
			abort();
		}
	}

	p->update_hook = update_hook;
	p->hook_priv = hook_priv;

}

void registry_perf_inc(struct registry_perf *p, uint64_t val) {

	if (p->type == registry_perf_type_timeticks) {
		pomlog(POMLOG_ERR "Trying to increase a perf item of type timeticks");
		return;
	} else if (p->update_hook) {
		pomlog(POMLOG_ERR "Trying to increase a perf item with an update hook");
		return;
	}

	__sync_fetch_and_add(&p->value, val);
}

void registry_perf_dec(struct registry_perf *p, uint64_t val) {

	if (p->type != registry_perf_type_gauge) {
		pomlog(POMLOG_ERR "Trying to decrease a perf item which is not of type gauge");
		return;
	} else if (p->update_hook) {
		pomlog(POMLOG_ERR "Trying to decrease a perf item with an update hook");
		return;
	}

	__sync_fetch_and_sub(&p->value, val);
}

void registry_perf_timeticks_stop(struct registry_perf *p) {

	if (p->type != registry_perf_type_timeticks) {
		pomlog(POMLOG_ERR "Trying to stop a non timetick performance");
		return;
	}

	if (!(p->value & REGISTRY_PERF_TIMETICKS_STARTED)) {
		pomlog(POMLOG_ERR "Timeticks performance already stopped");
		return;
	}

	ptime now = pom_gettimeofday();

	// value currently holds the absolute start time expressed in usec
	// Not sure if the below is correct ...
	volatile uint64_t new_val = (now + REGISTRY_PERF_TIMETICKS_STARTED) - p->value;
	p->value = new_val;
}

void registry_perf_timeticks_restart(struct registry_perf *p) {

	if (p->type != registry_perf_type_timeticks) {
		pomlog(POMLOG_ERR "Trying to restart a non timetick performance");
		return;
	}

	if (p->value & REGISTRY_PERF_TIMETICKS_STARTED) {
		pomlog(POMLOG_ERR "Timeticks performance already started");
		return;
	}

	ptime now = pom_gettimeofday();

	// value currently holds the runtime in usec
	volatile uint64_t new_val = (now + REGISTRY_PERF_TIMETICKS_STARTED) - p->value;
	p->value = new_val;
}

uint64_t registry_perf_getval(struct registry_perf *p) {

	// Since we have memory barrier for updating the value
	// I don't think there is the need for one for simply reading it
	if (p->type != registry_perf_type_timeticks) {

		if (p->update_hook) {
			pom_mutex_lock(&p->hook_lock);
			if (p->update_hook((uint64_t*)&p->value, p->hook_priv) != POM_OK)
				pomlog(POMLOG_WARN "Warning: update of performance %s value failed.", p->name);
			pom_mutex_unlock(&p->hook_lock);
		}

		return p->value;

	}

	// It's a timeticks and it's not started
	uint64_t value = p->value;
	if (!(value & REGISTRY_PERF_TIMETICKS_STARTED))
		return value;

	// Handle the case when it's started
	return pom_gettimeofday() - (value - REGISTRY_PERF_TIMETICKS_STARTED);
}

void registry_perf_reset(struct registry_perf *p) {

	if (p->type == registry_perf_type_gauge)
		return;

	if (p->update_hook) {
		pom_mutex_lock(&p->hook_lock);
		p->value = 0;
		pom_mutex_unlock(&p->hook_lock);
	} if (p->type == registry_perf_type_timeticks) {
		uint64_t running = p->value & REGISTRY_PERF_TIMETICKS_STARTED;
		if (running) {
			p->value = pom_gettimeofday() + REGISTRY_PERF_TIMETICKS_STARTED;
		} else {
			p->value = 0;
		}

	}else {
		p->value = 0;
	}
}

void registry_perf_reset_all() {
	registry_lock();

	struct registry_class *ctmp;
	for (ctmp = registry_head; ctmp; ctmp = ctmp->next) {
		
		struct registry_perf *p;
		for (p = ctmp->perfs; p; p = p->next) {
			if (p->type == registry_perf_type_counter)
				registry_perf_reset(p);
		}

		struct registry_instance *inst;
		for (inst = ctmp->instances; inst; inst = inst->next) {
			for (p = inst->perfs; p; p = p->next) {
				if (p->type == registry_perf_type_counter)
					registry_perf_reset(p);
			}
		}
	}
	registry_unlock();
}
