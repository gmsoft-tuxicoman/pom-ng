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
		.name = "registry.getParam",
		.callback_func = xmlrpccmd_registry_get_param,
		.signature = "i:s",
		.help = "Get the details of a parameter",
	},

	{
		.name = "registry.setParam",
		.callback_func = xmlrpccmd_registry_set_param,
		.signature = "i:ss",
		.help = "Add an input",
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

xmlrpc_value *xmlrpccmd_registry_get_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	char *param = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &param);

	if (envP->fault_occurred)
		return NULL;

	struct registry_param *p = registry_find_param(param);

	if (!p) {
		xmlrpc_faultf(envP, "Parameter %s not found", param);
		free(param);
		return NULL;
	}

	free(param);


	char *value = ptype_print_val_alloc(p->value);
	if (!value) {
		xmlrpc_faultf(envP, "Error while getting the parameter value");
		return NULL;
	}

	xmlrpc_value *result = xmlrpc_build_value(envP, "{s:s}",
					"name", p->name,
					"value", value);
	free(value);

	return result;

}

xmlrpc_value *xmlrpccmd_registry_set_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *param = NULL, *value = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &param, &value);

	if (envP->fault_occurred)
		return NULL;

	struct registry_param *p = registry_find_param(param);

	if (!p) {
		xmlrpc_faultf(envP, "Parameter %s not found", param);
		free(param);
		free(value);
		return NULL;
	}
	free(param);

	if (ptype_parse_val(p->value, value) != POM_OK) {
		xmlrpc_faultf(envP, "Unable to parse \"%s\"", value);
		free(value);
		return NULL;
	}
	free(value);

	return xmlrpc_int_new(envP, 0);

}

