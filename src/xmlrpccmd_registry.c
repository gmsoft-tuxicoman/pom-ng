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
#include "xmlrpcsrv.h"
#include "xmlrpccmd_registry.h"
#include <pom-ng/ptype.h>

#include "registry.h"

#define XMLRPCCMD_REGISTRY_NUM 7
static struct xmlrpcsrv_command xmlrpccmd_registry_commands[XMLRPCCMD_REGISTRY_NUM] = {

	{
		.name = "registry.listClass",
		.callback_func = xmlrpccmd_registry_list_class,
		.signature = "A:",
		.help = "List all the classes",
	},

	{
		.name = "registry.listInstance",
		.callback_func = xmlrpccmd_registry_list_instance,
		.signature = "A:s",
		.help = "List the instances of a class",
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


};

int xmlrpccmd_registry_register_all() {

	int i;

	for (i = 0; i < XMLRPCCMD_REGISTRY_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpccmd_registry_commands[i]) == POM_ERR)
			return POM_ERR;
	}

	return POM_OK;

}


xmlrpc_value *xmlrpccmd_registry_list_class(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *res = xmlrpc_array_new(envP);
	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_class *r;

	for (r = registry_get(); r; r = r->next) {
		xmlrpc_value *cls = xmlrpc_build_value(envP, "{s:s}",
							"name", r->name);
		xmlrpc_array_append_item(envP, res, cls);
		xmlrpc_DECREF(cls);

	}

	
	registry_unlock();

	return res;
}

xmlrpc_value *xmlrpccmd_registry_list_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &cls);

	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_class *c = registry_find_class(cls);
	if (!c) {
		xmlrpc_faultf(envP, "Class not found");
		goto err;
	}

	xmlrpc_value *res = xmlrpc_array_new(envP);
	if (envP->fault_occurred)
		goto err;

	struct registry_instance *i;

	for (i = c->instances; i; i = i->next) {
		xmlrpc_value *inst = xmlrpc_build_value(envP, "{s:s}",
							"name", i->name);
		xmlrpc_array_append_item(envP, res, inst);
		xmlrpc_DECREF(inst);
	}

	registry_unlock();

	free(cls);

	return res;

err:
	registry_unlock();

	free(cls);
	return NULL;

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

	if (i->parent->instance_remove(i) != POM_OK) {
		registry_unlock();
		xmlrpc_faultf(envP, "Error while adding the instance");
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
			param = xmlrpc_build_value(envP, "{s:s,s:s}",
							"name", p->name,
							"value", value);
		} else {
			param = xmlrpc_build_value(envP, "{s:s,s:s,s:s}",
							"name", p->name,
							"value", value,
							"default_value", p->default_value);
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

	xmlrpc_value *res = xmlrpc_build_value(envP, "{s:A,s:A}",
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
		xmlrpc_faultf(envP, "Parameter %s cannot be modified as it is immutable");
		return NULL;
	}


	if (registry_set_param_value(p, value) != POM_OK) {
		registry_unlock();
		free(value);
		xmlrpc_faultf(envP, "Unable to set parameter value to \"%s\"", value);
		return NULL;
	}
	free(value);
	
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

