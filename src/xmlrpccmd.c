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

#include "xmlrpccmd_evtmon.h"
#include "xmlrpccmd_registry.h"

#include "registry.h"


static uint32_t xmlrpccmd_serial = 0;
static pthread_mutex_t xmlrpccmd_serial_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t xmlrpccmd_serial_cond = PTHREAD_COND_INITIALIZER;

#define XMLRPCCMD_NUM 3
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

	{
		.name = "core.getLog",
		.callback_func = xmlrpccmd_core_get_log,
		.signature = "A:i",
		.help = "Get the logs",
	},

};


int xmlrpccmd_cleanup() {

	pom_mutex_lock(&xmlrpccmd_serial_lock);
	pthread_cond_broadcast(&xmlrpccmd_serial_cond);
	pom_mutex_unlock(&xmlrpccmd_serial_lock);

	xmlrpccmd_evtmon_cleanup();

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
	res += xmlrpccmd_evtmon_register_all();

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

	return xmlrpc_string_new(envP, VERSION);
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

	last_serial = xmlrpccmd_serial;
	pom_mutex_unlock(&xmlrpccmd_serial_lock);

	registry_lock();
	pomlog_rlock();

	struct pomlog_entry *last_log = pomlog_get_tail();
	
	xmlrpc_value *res = xmlrpc_build_value(envP, "{s:i,s:i,s:i}",
						"main", last_serial,
						"registry", registry_serial_get(),
						"log", last_log->id);

	pomlog_unlock();
	registry_unlock();

	return res;

}

xmlrpc_value *xmlrpccmd_core_get_log(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t last_id;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &last_id);
	if (envP->fault_occurred)
		return NULL;

	xmlrpc_value *res = xmlrpc_array_new(envP);
	if (envP->fault_occurred)
		return NULL;

	pomlog_rlock();

	struct pomlog_entry *log = pomlog_get_tail();

	if (log->id <= last_id) {
		pomlog_unlock();
		return res;
	}

	while (log && log->id > last_id + 1)
		log = log->prev;

	while (log) {
		xmlrpc_value *entry = xmlrpc_build_value(envP, "{s:i,s:i,s:s,s:s,s:t}",
								"id", log->id,
								"level", log->level,
								"file", log->file,
								"data", log->data,
								"timestamp", (time_t)log->ts.tv_sec);
		xmlrpc_array_append_item(envP, res, entry);
		xmlrpc_DECREF(entry);
		log = log->next;

	}
	pomlog_unlock();

	return res;
}

