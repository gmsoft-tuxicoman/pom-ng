/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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

#define REGISTRY_CONFIG_LIST	"config_list"
#define REGISTRY_CONFIG		"config"

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
	struct registry_instance_type *prev, *next;
	
};

struct registry_class {
	char *name;
	struct registry_instance *instances;
	struct registry_instance_type *types;
	struct registry_param *global_params;
	uint32_t serial;
	int (*instance_add) (char *type, char *name);
	int (*instance_remove) (struct registry_instance *i);
	struct registry_class *next, *prev;
};

int registry_init();
int registry_cleanup();

void registry_lock();
void registry_unlock();

struct registry_class *registry_get();

struct registry_class* registry_add_class(char *name);
int registry_remove_class(struct registry_class *c);

int registry_add_instance_type(struct registry_class *c, char *name);
int registry_remove_instance_type(struct registry_class *c, char *name);

struct registry_instance *registry_add_instance(struct registry_class *c, char *name);
int registry_remove_instance(struct registry_instance *i);

int registry_class_add_param(struct registry_class *c, struct registry_param *p);
int registry_set_param(struct registry_instance *i, char *param, char* value);
int registry_set_param_value(struct registry_param *p, char *value);

struct registry_class *registry_find_class(char *cls);
struct registry_instance *registry_find_instance(char *cls, char *instance);

int registry_uid_assign(struct registry_instance *instance, char *uid);
void registry_serial_inc();
uint32_t registry_serial_get();

int registry_save(char *config_name);
int registry_reset();
int registry_load(char *config_name);

#endif
