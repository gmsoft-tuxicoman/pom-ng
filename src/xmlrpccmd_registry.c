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

#include "common.h"
#include "xmlrpcsrv.h"
#include "xmlrpccmd_registry.h"
#include <pom-ng/ptype.h>

#include "registry.h"

#define XMLRPCCMD_REGISTRY_NUM 10
static struct xmlrpcsrv_command xmlrpccmd_registry_commands[XMLRPCCMD_REGISTRY_NUM] = {

	{
		.name = "registry.list",
		.callback_func = xmlrpccmd_registry_list,
		.signature = "S:",
		.help = "List all the classes and their instances",
	},

	{
		.name = "registry.addInstance",
		.callback_func = xmlrpccmd_registry_add_instance,
		.signature = "i:sss",
		.help = "Add an instance of a certain class. Arguments are : class, instance_name, instance_type",
	},

	{
		.name = "registry.removeInstance",
		.callback_func = xmlrpccmd_registry_remove_instance,
		.signature = "i:ss",
		.help = "Remove an instance from a certain class, Arguments are : class, instance",
	},

	{
		.name = "registry.getInstance",
		.callback_func = xmlrpccmd_registry_get_instance,
		.signature = "A:ss",
		.help = "Get the details of an instance. Arguments are : class, instance",
	},

	{
		.name = "registry.setInstanceParam",
		.callback_func = xmlrpccmd_registry_set_instance_param,
		.signature = "i:ssss",
		.help = "Set the value of an instance parameter. Arguments are : class, instance, parameter, value",
	},

	{
		.name = "registry.instanceFunction",
		.callback_func = xmlrpccmd_registry_instance_function,
		.signature = "i:sss",
		.help = "Execute an instance function. Arguments are : class, instance, function",
	},

	{
		.name = "registry.save",
		.callback_func = xmlrpccmd_registry_save,
		.signature = "i:s",
		.help = "Save the registry configuration in the system datastore",

	},

	{
		.name = "registry.reset",
		.callback_func = xmlrpccmd_registry_reset,
		.signature = "i:",
		.help = "Reset the registry to it's initial state",
	},

	{
		.name = "registry.load",
		.callback_func = xmlrpccmd_registry_load,
		.signature = "i:s",
		.help = "Load a saved configuration",
	},

	{
		.name = "registry.delete_config",
		.callback_func = xmlrpccmd_registry_delete,
		.signature = "i:s",
		.help = "Delete a saved configuration",
	}
};

int xmlrpccmd_registry_register_all() {

	int i;

	for (i = 0; i < XMLRPCCMD_REGISTRY_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpccmd_registry_commands[i]) == POM_ERR)
			return POM_ERR;
	}

	return POM_OK;

}


xmlrpc_value *xmlrpccmd_registry_list(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *classes = xmlrpc_array_new(envP);
	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_class *c;

	for (c = registry_get(); c; c = c->next) {

		xmlrpc_value *types = xmlrpc_array_new(envP);
		struct registry_instance_type *t;
		for (t = c->types; t; t = t->next) {
			xmlrpc_value *type = xmlrpc_build_value(envP, "{s:s}",
								"name", t->name);
			xmlrpc_array_append_item(envP, types, type);
			xmlrpc_DECREF(type);

		}

		xmlrpc_value *instances = xmlrpc_array_new(envP);
		
		struct registry_instance *i;
		for (i = c->instances; i; i = i->next) {
			xmlrpc_value *inst = xmlrpc_build_value(envP, "{s:s,s:i}",
								"name", i->name,
								"serial", i->serial);
			xmlrpc_array_append_item(envP, instances, inst);
			xmlrpc_DECREF(inst);
		}

		xmlrpc_value *cls = xmlrpc_build_value(envP, "{s:s,s:i,s:A,s:A}",
							"name", c->name,
							"serial", c->serial,
							"available_types", types,
							"instances", instances);

		xmlrpc_DECREF(types);
		xmlrpc_DECREF(instances);
		xmlrpc_array_append_item(envP, classes, cls);
		xmlrpc_DECREF(cls);

	}

	xmlrpc_value *configs = xmlrpc_array_new(envP);

	struct registry_config_entry *config_list = registry_config_list();
	if (config_list) {
		ssize_t i;

		for (i = 0; *config_list[i].name; i++) {
			xmlrpc_value *entry = xmlrpc_build_value(envP, "{s:s,s:t}",
								"name", config_list[i].name,
								"timestamp", (time_t)config_list[i].ts.tv_sec);
			xmlrpc_array_append_item(envP, configs, entry);
			xmlrpc_DECREF(entry);
		}

		free(config_list);
	}


	xmlrpc_value *res = xmlrpc_build_value(envP, "{s:i,s:A,s:i,s:A}",
					"classes_serial", registry_classes_serial_get(),
					"classes", classes,
					"configs_serial", registry_config_serial_get(),
					"configs", configs);
	xmlrpc_DECREF(classes);
	xmlrpc_DECREF(configs);
	registry_unlock();

	return res;

}


xmlrpc_value *xmlrpccmd_registry_add_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *type = NULL, *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &name, &type);

	if (envP->fault_occurred)
		goto err_decompose;

	registry_lock();

	if (registry_find_instance(cls, name)) {
		xmlrpc_faultf(envP, "Instance already exists");
		goto err;
	}

	struct registry_class *c = registry_find_class(cls);
	if (!c) {
		xmlrpc_faultf(envP, "Class not found");
		goto err;
	}
	free(cls);
	cls = NULL;
	
	if (!c->instance_add) {
		xmlrpc_faultf(envP, "This class doesn't support adding instances");
		goto err;
	}

	if (c->instance_add(type, name) != POM_OK) {
		xmlrpc_faultf(envP, "Error while adding the instance");
		goto err;
	}

	registry_unlock();

	free(type);
	free(name);

	return xmlrpc_int_new(envP, 0);

err:
	registry_unlock();
err_decompose:

	if (cls)
		free(cls);
	free(type);
	free(name);

	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_remove_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &cls, &instance);

	if (envP->fault_occurred)
		goto err;

	registry_lock();

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		registry_unlock();
		xmlrpc_faultf(envP, "Class or instance not found");
		goto err;
	}
	free(cls);
	free(instance);
	
	if (!i->parent->instance_remove) {
		registry_unlock();
		xmlrpc_faultf(envP, "This class doesn't support removing instances");
		return NULL;
	}

	if (registry_remove_instance(i) != POM_OK) {
		registry_unlock();
		xmlrpc_faultf(envP, "Error while removing the instance");
		return NULL;
	}
	
	registry_unlock();

	return xmlrpc_int_new(envP, 0);

err:
	free(cls);
	free(instance);

	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_get_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &cls, &instance);

	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		xmlrpc_faultf(envP, "Class or instance not found");
		free(cls);
		free(instance);
		goto err;
	}

	free(cls);
	free(instance);

	xmlrpc_value *params = xmlrpc_array_new(envP);

	struct registry_param *p;
	for (p = i->params; p; p = p->next) {
		char *value = ptype_print_val_alloc(p->value);
		if (!value) {
			xmlrpc_faultf(envP, "Error while getting parameter value of parameter %s", p->name);
			goto err;
		}
		xmlrpc_value *param = NULL;
		
		if (p->flags & REGISTRY_PARAM_FLAG_IMMUTABLE) {
			// Don't provide a default value for immutable parameters
			param = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s}",
							"name", p->name,
							"value", value,
							"type", ptype_get_name(p->value),
							"description", p->description);
		} else {
			param = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s,s:s}",
							"name", p->name,
							"value", value,
							"type", ptype_get_name(p->value),
							"default_value", p->default_value,
							"description", p->description);
		}
		free(value);

		xmlrpc_array_append_item(envP, params, param);
		xmlrpc_DECREF(param);

	}

	xmlrpc_value *funcs = xmlrpc_array_new(envP);

	struct registry_function *f;
	for (f = i->funcs; f; f = f->next) {
		xmlrpc_value *func = xmlrpc_build_value(envP, "{s:s,s:s}",
						"name", f->name,
						"description", f->description);
		xmlrpc_array_append_item(envP, funcs, func);
		xmlrpc_DECREF(func);

	}

	registry_unlock();

	xmlrpc_value *res = xmlrpc_build_value(envP, "{s:s,s:i,s:A,s:A}",
				"name", i->name,
				"serial", i->serial,
				"parameters", params,
				"functions", funcs);

	xmlrpc_DECREF(params);
	xmlrpc_DECREF(funcs);

	return res;

err:
	registry_unlock();

	return NULL;


}

xmlrpc_value *xmlrpccmd_registry_set_instance_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL, *param = NULL, *value = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ssss)", &cls, &instance, &param, &value);

	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		xmlrpc_faultf(envP, "Class or instance not found");
		goto err;
	}

	struct registry_param *p = i->params;
	for (; p && strcmp(p->name, param); p = p->next);

	if (!p) {
		xmlrpc_faultf(envP, "Parameter %s not found", param);
		goto err;
	}

	free(cls);
	free(instance);
	free(param);

	if (p->flags & REGISTRY_PARAM_FLAG_IMMUTABLE) {
		registry_unlock();
		free(value);
		xmlrpc_faultf(envP, "Parameter %s cannot be modified as it is immutable", p->name);
		return NULL;
	}


	if (registry_set_param_value(p, value) != POM_OK) {
		registry_unlock();
		xmlrpc_faultf(envP, "Unable to set parameter value to \"%s\"", value);
		free(value);
		return NULL;
	}
	free(value);
	
	i->serial++;
	i->parent->serial++;
	registry_classes_serial_inc();
	
	registry_unlock();

	return xmlrpc_int_new(envP, 0);

err:
	registry_unlock();

	free(cls);
	free(instance);
	free(param);
	free(value);
	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_instance_function(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL, *function = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &instance, &function);

	if (envP->fault_occurred)
		goto err;

	registry_lock();
	struct registry_instance *i = registry_find_instance(cls, instance);

	if (!i) {
		xmlrpc_faultf(envP, "Class or instance doesn't exists");
		goto err;
	}

	free(cls);
	cls = NULL;
	free(instance);
	instance = NULL;

	struct registry_function *f = i->funcs;

	for (; f && strcmp(f->name, function); f = f->next);

	if (!f) {
		xmlrpc_faultf(envP, "Function not found");
		goto err;
	}

	if (f->handler(i) != POM_OK) {
		xmlrpc_faultf(envP, "An error occurred");
		goto err;
	}

	i->serial++;
	i->parent->serial++;
	registry_classes_serial_inc();

	registry_unlock();

	free(function);

	return xmlrpc_int_new(envP, 0);

err:
	
	registry_unlock();

	if (cls)
		free(cls);
	if (instance)
		free(instance);
	free(function);

	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_save(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	if (registry_config_save(name) != POM_OK) {
		free(name);
		xmlrpc_faultf(envP, "Error while saving the registry");
		return NULL;
	}
	
	free(name);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_reset(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	if (registry_config_reset() != POM_OK) {
		xmlrpc_faultf(envP, "Error while resetting the registry");
		return NULL;
	}

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_load(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	if (registry_config_load(name) != POM_OK) {
		free(name);
		xmlrpc_faultf(envP, "Error while loading the registry");
		return NULL;
	}
	
	free(name);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_delete(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	if (registry_config_delete(name) != POM_OK) {
		free(name);
		xmlrpc_faultf(envP, "Error while deleting the registry config");
		return NULL;
	}
	
	free(name);

	return xmlrpc_int_new(envP, 0);
}
