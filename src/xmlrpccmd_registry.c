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

#define XMLRPCCMD_REGISTRY_NUM 5
static struct xmlrpcsrv_command xmlrpccmd_registry_commands[XMLRPCCMD_REGISTRY_NUM] = {

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
		.name = "registry.getInstanceParam",
		.callback_func = xmlrpccmd_registry_get_instance_param,
		.signature = "i:sss",
		.help = "Get the details of an instance parameter. Arguments are : class, instance, parameter",
	},

	{
		.name = "registry.setInstanceParam",
		.callback_func = xmlrpccmd_registry_set_instance_param,
		.signature = "i:ssss",
		.help = "Set the value of an instance parameter. Arguments are : class, instance, parameter, value",
	},

	{
		.name = "registry.instanceAction",
		.callback_func = xmlrpccmd_registry_instance_action,
		.signature = "i:sss",
		.help = "Execute an instance action. Arguments are : class, instance, action",
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

xmlrpc_value *xmlrpccmd_registry_add_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *type = NULL, *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &name, &type);

	if (envP->fault_occurred)
		goto err;

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

	free(type);
	free(name);

	return xmlrpc_int_new(envP, 0);

err:
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

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		xmlrpc_faultf(envP, "Class or instance not found");
		goto err;
	}
	free(cls);
	free(instance);
	
	if (!i->parent->instance_remove) {
		xmlrpc_faultf(envP, "This class doesn't support removing instances");
		return NULL;
	}

	if (i->parent->instance_remove(i) != POM_OK) {
		xmlrpc_faultf(envP, "Error while adding the instance");
		return NULL;
	}


	return xmlrpc_int_new(envP, 0);

err:
	free(cls);
	free(instance);

	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_get_instance_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL, *param = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &instance, &param);

	if (envP->fault_occurred)
		return NULL;

	xmlrpc_value *result = NULL;

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		xmlrpc_faultf(envP, "Class or instance not found");
		goto err;
	}

	pom_mutex_lock(&i->lock);

	struct registry_param *p = i->params;
	for (; p && strcmp(p->name, param); p = p->next);

	if (!p) {
		pom_mutex_unlock(&i->lock);
		xmlrpc_faultf(envP, "Parameter %s not found", param);
		goto err;
	}
	pom_mutex_unlock(&i->lock);
	
	pom_mutex_lock(&p->lock);

	char *value = ptype_print_val_alloc(p->value);
	pom_mutex_unlock(&p->lock);
	if (!value) {
		xmlrpc_faultf(envP, "Error while getting the parameter value of parameter %s", param);
		goto err;
	}

	result = xmlrpc_build_value(envP, "{s:s,s:s}",
					"name", p->name,
					"value", value);
err:
	free(cls);
	free(instance);
	free(param);

	return result;


}

xmlrpc_value *xmlrpccmd_registry_set_instance_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL, *param = NULL, *value = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ssss)", &cls, &instance, &param, &value);

	if (envP->fault_occurred)
		return NULL;

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		xmlrpc_faultf(envP, "Class or instance not found");
		goto err;
	}

	pom_mutex_lock(&i->lock);

	struct registry_param *p = i->params;
	for (; p && strcmp(p->name, param); p = p->next);

	if (!p) {
		pom_mutex_unlock(&i->lock);
		xmlrpc_faultf(envP, "Parameter %s not found", param);
		goto err;
	}
	pom_mutex_unlock(&i->lock);
	
	pom_mutex_lock(&p->lock);


	free(cls);
	free(instance);
	free(param);


	if (registry_set_param_value(p, value) != POM_OK) {
		pom_mutex_unlock(&p->lock);
		free(value);
		xmlrpc_faultf(envP, "Unable set parameter value to \"%s\"", value);
		return NULL;
	}
	pom_mutex_unlock(&p->lock);
	free(value);

	return xmlrpc_int_new(envP, 0);

err:

	free(cls);
	free(instance);
	free(param);
	free(value);
	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_instance_action(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL, *action = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &instance, &action);

	if (envP->fault_occurred)
		goto err;

	struct registry_instance *i = registry_find_instance(cls, instance);

	if (!i) {
		xmlrpc_faultf(envP, "Class or instance doesn't exists");
		goto err;
	}

	free(cls);
	cls = NULL;
	free(instance);
	instance = NULL;

	pom_mutex_lock(&i->lock);

	struct registry_function *f = i->funcs;

	for (; f && strcmp(f->name, action); f = f->next);

	if (!f) {
		pom_mutex_unlock(&i->lock);
		xmlrpc_faultf(envP, "Action not found");
		goto err;
	}

	if (f->handler(i) != POM_OK) {
		pom_mutex_unlock(&i->lock);
		xmlrpc_faultf(envP, "An error occurred");
		goto err;
	}

	pom_mutex_unlock(&i->lock);

	free(action);

	return xmlrpc_int_new(envP, 0);

err:
	if (cls)
		free(cls);
	if (instance)
		free(instance);
	free(action);

	return NULL;
}

