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
#include "xmlrpccmd_input.h"
#include "httpd.h"

#include "input_ipc.h"

#define XMLRPCCMD_INPUT_NUM 1
static struct xmlrpcsrv_command xmlrpccmd_input_commands[XMLRPCCMD_INPUT_NUM] = {

	{
		.name = "input.add",
		.callback_func = xmlrpccmd_input_add,
		.signature = "i:is",
		.help = "Get " PACKAGE_NAME " version",
	}

};

int xmlrpccmd_input_register_all() {

	int i;

	for (i = 0; i < XMLRPCCMD_INPUT_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpccmd_input_commands[i]) == POM_ERR)
			return POM_ERR;
	}

	return POM_OK;

}


xmlrpc_value *xmlrpccmd_input_add(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	int type = 0;
	char *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(is)", &type, &name);

	if (envP->fault_occurred)
		return NULL;

	if (input_ipc_cmd_add(type, name) != POM_OK) {
		xmlrpc_faultf(envP, "Unable to add input");
		return NULL;
	}
	return xmlrpc_int_new(envP, 0);

}
