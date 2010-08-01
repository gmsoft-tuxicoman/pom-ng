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
#include "xmlrpccmd.h"

#include <libxml/parser.h>


static xmlrpc_registry *xmlrpcsrv_registry = NULL;

int xmlrpcsrv_init() {


	// Init the XMLRPC-C library
	
	xmlrpc_env env;
	xmlrpc_env_init(&env);
	xmlrpcsrv_registry = xmlrpc_registry_new(&env);

	if (env.fault_occurred) {
		xmlrpc_env_clean(&env);
		return POM_ERR;
	}

	xmlrpc_env_clean(&env);

	xmlrpccmd_register_all();

	return POM_OK;
}

int xmlrpcsrv_process(char *data, size_t size, char **response, size_t *reslen) {
	
	xmlrpc_env env;
	xmlrpc_env_init(&env);

	xmlrpc_mem_block *output = NULL;
	xmlrpc_registry_process_call2(&env, xmlrpcsrv_registry, data, size, NULL, &output);

	*reslen = xmlrpc_mem_block_size(output);
	*response = malloc(*reslen);
	if (!*response) {
		pomlog(POMLOG_ERR "Not enough memory to allocate %u bytes for response", *reslen);
		xmlrpc_mem_block_free(output);
		xmlrpc_env_clean(&env);
		return POM_ERR;
	}
	memcpy(*response, xmlrpc_mem_block_contents(output), *reslen);

	xmlrpc_mem_block_free(output);
	xmlrpc_env_clean(&env);

	return POM_OK;
}

int xmlrpcsrv_cleanup() {

	if (xmlrpcsrv_registry) {
		xmlrpc_registry_free(xmlrpcsrv_registry);
		xmlrpcsrv_registry = NULL;
	}

	// Cleanup libxml2 stuff
	xmlCleanupCharEncodingHandlers();
	xmlCleanupParser();

	return POM_OK;
}

int xmlrpcsrv_register_command(struct xmlrpcsrv_command *cmd) {

	if (!xmlrpcsrv_registry)
		return POM_ERR;

	xmlrpc_env env;
	xmlrpc_env_init(&env);

	xmlrpc_registry_add_method_w_doc(&env, xmlrpcsrv_registry, NULL, cmd->name, cmd->callback_func, NULL, cmd->signature, cmd->help);
	if (env.fault_occurred) {
		xmlrpc_env_clean(&env);
		return POM_ERR;
	}
	xmlrpc_env_clean(&env);

	return POM_OK;

}
