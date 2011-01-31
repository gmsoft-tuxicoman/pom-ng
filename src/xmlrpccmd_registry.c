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

#define XMLRPCCMD_REGISTRY_NUM 2
static struct xmlrpcsrv_command xmlrpccmd_registry_commands[XMLRPCCMD_REGISTRY_NUM] = {

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


};

int xmlrpccmd_registry_register_all() {

	int i;

	for (i = 0; i < XMLRPCCMD_REGISTRY_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpccmd_registry_commands[i]) == POM_ERR)
			return POM_ERR;
	}

	return POM_OK;

}

xmlrpc_value *xmlrpccmd_registry_get_instance_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL, *param = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &instance, &param);

	if (envP->fault_occurred)
		return NULL;

	xmlrpc_value *result = NULL;

	struct registry_class *c = registry_get_head();

	for (;c && strcmp(c->name, cls); c = c->next);
	if (!c) {
		xmlrpc_faultf(envP, "Class %s not found", cls);
		goto err;
	}

	struct registry_instance *i = c->instances;
	for (; i && strcmp(i->name, instance); i = i->next);
	if (!i) {
		xmlrpc_faultf(envP, "Instance %s not found", instance);
		goto err;
	}

	struct registry_param *p = i->params;
	for (; p && strcmp(p->name, param); p = p->next);

	if (!p) {
		xmlrpc_faultf(envP, "Parameter %s not found", param);
		goto err;
	}
	

	char *value = ptype_print_val_alloc(p->value);
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


	struct registry_class *c = registry_get_head();
	struct registry_param *p = NULL;

	for (;c && strcmp(c->name, cls); c = c->next);
	if (c) {
		struct registry_instance *i = c->instances;
		for (; i && strcmp(i->name, instance); i = i->next);
		if (i) {
			p = i->params;
			for (; p && strcmp(p->name, param); p = p->next);
		}
	}

	free(cls);
	free(instance);
	free(param);

	if (!p) {
		xmlrpc_faultf(envP, "Parameter not found");
		free(value);
		return NULL;
	}

	if (registry_set_param_value(p, value) != POM_OK) {
		xmlrpc_faultf(envP, "Unable set parameter value to \"%s\"", value);
		free(value);
		return NULL;
	}
	free(value);

	return xmlrpc_int_new(envP, 0);

}

