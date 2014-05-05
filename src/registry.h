/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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



#ifndef __REGISTRY_H__
#define __REGISTRY_H__

#include <pom-ng/registry.h>

#define REGISTRY_CONFIG_LIST		"config_list"
#define REGISTRY_CONFIG			"config"
#define REGISTRY_CONFIG_NAME_MAX	256

// Use the msb for started/stopped flag
#define REGISTRY_PERF_TIMETICKS_STARTED (1LLU << 63)

struct registry_perf {

	char *name;
	char *description;
	char *unit;
	enum registry_perf_type type;
	volatile uint64_t value;
	struct registry_perf *next;

	int (*update_hook) (uint64_t *cur_val, void *priv);
	void *hook_priv;
	pthread_mutex_t hook_lock;
};

struct registry_param {
	char *name;
	char *default_value;
	struct ptype *value;
	char *description;
	unsigned int flags;

	void *callback_priv;
	int (*set_pre_callback) (void *priv, char *value);
	int (*set_post_callback) (void *priv, struct ptype *value);

	struct registry_param *next, *prev;
};

struct registry_instance {
	char *name;
	struct registry_param *params;
	struct registry_function *funcs;
	uint32_t serial;
	void *priv;
	struct registry_instance *next, *prev;
	struct registry_class *parent;

	struct registry_perf *perfs;
};

enum registry_config_entry_types {
	registry_config_class_param,
	registry_config_instance,
	registry_config_instance_param,
};

struct registry_function {
	
	char *name;
	int (*handler) (struct registry_instance *instance);
	char *description;
	struct registry_function *next;

};

// Available types for instances
struct registry_instance_type {
	char *name;
	char *description;
	struct registry_instance_type *prev, *next;
	
};

struct registry_class {
	char *name;
	struct registry_instance *instances;
	struct registry_instance_type *types;
	struct registry_param *global_params;
	struct registry_perf *perfs;
	uint32_t serial;
	int (*instance_add) (char *type, char *name);
	int (*instance_remove) (struct registry_instance *i);
	struct registry_class *next, *prev;
};

struct registry_config_entry {
	char name[REGISTRY_CONFIG_NAME_MAX];
	ptime ts;
};

int registry_init();
int registry_cleanup();
void registry_finish();

void registry_lock();
void registry_unlock();

struct registry_class *registry_get();

struct registry_class* registry_add_class(char *name);
int registry_remove_class(struct registry_class *c);

struct registry_perf *registry_class_add_perf(struct registry_class *c, const char *name, enum registry_perf_type type, const char *description, const char *unit);

int registry_add_instance_type(struct registry_class *c, char *name, char *description);
int registry_remove_instance_type(struct registry_class *c, char *name);

struct registry_instance *registry_add_instance(struct registry_class *c, char *name);
int registry_remove_instance(struct registry_instance *i);

int registry_class_add_param(struct registry_class *c, struct registry_param *p);
int registry_set_param(struct registry_instance *i, char *param, char* value);
int registry_set_param_value(struct registry_param *p, char *value);

struct registry_class *registry_find_class(char *cls);
struct registry_instance *registry_find_instance(char *cls, char *instance);

int registry_uid_assign(struct registry_instance *instance, char *uid);
void registry_classes_serial_inc();
uint32_t registry_serial_get();
uint32_t registry_classes_serial_get();
uint32_t registry_config_serial_get();

struct registry_config_entry* registry_config_list();
int registry_config_save(char *config_name);
int registry_config_reset();
int registry_config_load(char *config_name);
int registry_config_delete(char *config_name);

void registry_perf_reset_all();

uint32_t registry_serial_poll(uint32_t last_serial, struct timespec *timeout);

#endif
