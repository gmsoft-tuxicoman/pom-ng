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
#include "xmlrpccmd.h"
#include "xmlrpcsrv.h"

#include "xmlrpccmd_registry.h"

#include "registry.h"


static uint32_t xmlrpccmd_serial = 0;
static pthread_mutex_t xmlrpccmd_serial_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t xmlrpccmd_serial_cond = PTHREAD_COND_INITIALIZER;

#define XMLRPCCMD_NUM 2
static struct xmlrpcsrv_command xmlrpccmd_commands[XMLRPCCMD_NUM] = {

	{
		.name = "core.getVersion",
		.callback_func = xmlrpccmd_core_get_version,
		.signature = "s:",
		.help = "Get " PACKAGE_NAME " version",
	},

	{
		.name = "core.serialPoll",
		.callback_func = xmlrpccmd_core_serial_poll,
		.signature = "S:i",
		.help = "Poll the serial numbers",
	},

};


int xmlrpccmd_cleanup() {

	pom_mutex_lock(&xmlrpccmd_serial_lock);
	pthread_cond_broadcast(&xmlrpccmd_serial_cond);
	pom_mutex_unlock(&xmlrpccmd_serial_lock);

	return POM_OK;
}

int xmlrpccmd_register_all() {

	int i;

	for (i = 0; i < XMLRPCCMD_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpccmd_commands[i]) == POM_ERR)
			return POM_ERR;
	}

	int res = POM_OK;
	res += xmlrpccmd_registry_register_all();

	return res;

}


void xmlrcpcmd_serial_inc() {
	pom_mutex_lock(&xmlrpccmd_serial_lock);
	xmlrpccmd_serial++;
	if (pthread_cond_broadcast(&xmlrpccmd_serial_cond)) {
		pomlog(POMLOG_ERR "Error while signaling the serial condition. Aborting");
		abort();
	}
	pom_mutex_unlock(&xmlrpccmd_serial_lock);

}

xmlrpc_value *xmlrpccmd_core_get_version(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	return xmlrpc_string_new(envP, "WIP");
}

xmlrpc_value *xmlrpccmd_core_serial_poll(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	uint32_t last_serial = 0;
	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &last_serial);
	if (envP->fault_occurred)
		return NULL;
	

	pom_mutex_lock(&xmlrpccmd_serial_lock);
	if (last_serial == xmlrpccmd_serial) {
		// Wait for update
		if (pthread_cond_wait(&xmlrpccmd_serial_cond, &xmlrpccmd_serial_lock)) {
			xmlrpc_faultf(envP, "Error while waiting for serial condition : %s", pom_strerror(errno));
			abort();
			return NULL;
		}
	
	}

	xmlrpc_value *res = xmlrpc_build_value(envP, "{s:i,s:i}",
						"main", xmlrpccmd_serial,
						"registry", registry_serial_get());

	pom_mutex_unlock(&xmlrpccmd_serial_lock);

	return res;

}
