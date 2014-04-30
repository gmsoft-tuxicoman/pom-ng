/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#include "xmlrpccmd_monitor.h"
#include "xmlrpccmd_registry.h"

#include "registry.h"


#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_timestamp.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/ptype_uint64.h>


static uint32_t xmlrpccmd_serial = 0;
static pthread_mutex_t xmlrpccmd_serial_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t xmlrpccmd_serial_cond = PTHREAD_COND_INITIALIZER;

static struct ptype_reg *pt_bool = NULL, *pt_string = NULL, *pt_timestamp = NULL, *pt_uint8 = NULL, *pt_uint16 = NULL, *pt_uint32 = NULL, *pt_uint64 = NULL;

#define XMLRPCCMD_NUM 5
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
		.name = "core.serialPoll2",
		.callback_func = xmlrpccmd_core_serial_poll2,
		.signature = "S:S",
		.help = "Poll the serial numbers",
	},

	{
		.name = "core.getLog",
		.callback_func = xmlrpccmd_core_get_log,
		.signature = "A:i",
		.help = "Get the logs",
	},

	{
		.name = "core.pollLog",
		.callback_func = xmlrpccmd_core_poll_log,
		.signature = "A:ii",
		.help = "Poll the logs",
	},

};


int xmlrpccmd_init() {

	pt_bool = ptype_get_type("bool");
	pt_string = ptype_get_type("string");
	pt_timestamp = ptype_get_type("timestamp");
	pt_uint8 = ptype_get_type("uint8");
	pt_uint16 = ptype_get_type("uint16");
	pt_uint32 = ptype_get_type("uint32");
	pt_uint64 = ptype_get_type("uint64");

	if (!pt_bool || !pt_string || !pt_timestamp || !pt_uint8 || !pt_uint16 || !pt_uint32 || !pt_uint64) {
		pomlog(POMLOG_ERR "Some ptype where not loaded correctly");
		return POM_ERR;
	}
	return POM_OK;
}

int xmlrpccmd_cleanup() {

	pom_mutex_lock(&xmlrpccmd_serial_lock);
	pthread_cond_broadcast(&xmlrpccmd_serial_cond);
	pom_mutex_unlock(&xmlrpccmd_serial_lock);

	xmlrpccmd_monitor_cleanup();

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
	res += xmlrpccmd_monitor_register_all();

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


xmlrpc_value *xmlrpccmd_ptype_to_val(xmlrpc_env* const envP, struct ptype* p) {

	if (p->type == pt_bool) {
		return xmlrpc_bool_new(envP, *PTYPE_BOOL_GETVAL(p));
	} else if (p->type == pt_string) {
		return xmlrpc_string_new(envP, PTYPE_STRING_GETVAL(p));
	} else if (p->type == pt_timestamp) {
		// Don't use the time version of xmlrpc as it's not precise enough
		ptime t = *PTYPE_TIMESTAMP_GETVAL(p);
		return xmlrpc_build_value(envP, "{s:i,s:i}", "sec", pom_ptime_sec(t), "usec", pom_ptime_usec(t));
	} else if (p->type == pt_uint8) {
		return xmlrpc_int_new(envP, *PTYPE_UINT8_GETVAL(p));
	} else if (p->type == pt_uint16) {
		return xmlrpc_int_new(envP, *PTYPE_UINT16_GETVAL(p));
	} else if (p->type == pt_uint32) {
		return xmlrpc_int_new(envP, *PTYPE_UINT32_GETVAL(p));
	} else if (p->type == pt_uint64) {
		return xmlrpc_i8_new(envP, *PTYPE_UINT64_GETVAL(p));
	}

	// The type is not handled, return a string
	
	char *value = ptype_print_val_alloc(p, NULL);
	if (!value) {
		xmlrpc_faultf(envP, "Error while getting ptype value");
		return NULL;
	}

	xmlrpc_value *retval = xmlrpc_string_new(envP, value);
	free(value);
	return retval;
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
	while (last_serial == xmlrpccmd_serial) {
		// Wait for update

		struct timeval now;
		gettimeofday(&now, NULL);
		struct timespec then = { 0 };
		then.tv_sec = now.tv_sec + XMLRPCSRV_POLL_TIMEOUT;

		int res = pthread_cond_timedwait(&xmlrpccmd_serial_cond, &xmlrpccmd_serial_lock, &then);

		if (res == ETIMEDOUT) {
			break; // Return current values
		} else if (res) {
			xmlrpc_faultf(envP, "Error while waiting for serial condition : %s", pom_strerror(res));
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

xmlrpc_value *xmlrpccmd_core_serial_poll2(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *serials = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(S)", &serials);

	if (envP->fault_occurred)
		return NULL;

	xmlrpc_value *xml_registry_serial = NULL;
	xmlrpc_struct_find_value(envP, serials, "registry", &xml_registry_serial);
	xmlrpc_int registry_serial = 0, last_registry_serial = 0;
	if (xml_registry_serial) {
		xmlrpc_read_int(envP, xml_registry_serial, &registry_serial);
		xmlrpc_DECREF(xml_registry_serial);
		registry_lock();
		last_registry_serial = registry_serial_get();
		registry_unlock();
	}
	
	xmlrpc_value *xml_log_serial = NULL;
	xmlrpc_struct_find_value(envP, serials, "log", &xml_log_serial);
	xmlrpc_int log_serial = 0, last_log_serial = 0;
	if (xml_log_serial) {
		xmlrpc_read_int(envP, xml_log_serial, &log_serial);
		xmlrpc_DECREF(xml_log_serial);
		pomlog_rlock();
		struct pomlog_entry *last_log = pomlog_get_tail();
		last_log_serial = last_log->id;
		pomlog_unlock();
	}

	xmlrpc_DECREF(serials);


	if (envP->fault_occurred)
		return NULL;
	
	if (!xml_registry_serial && !xml_log_serial) {
		xmlrpc_faultf(envP, "No known serial provided");
		return NULL;
	}


	while ( (!xml_registry_serial || (registry_serial == last_registry_serial)) && (!xml_log_serial || (log_serial == last_log_serial)) ) {
		// Wait for update

		struct timeval now;
		gettimeofday(&now, NULL);
		struct timespec then = { 0 };
		then.tv_sec = now.tv_sec + XMLRPCSRV_POLL_TIMEOUT;

		pom_mutex_lock(&xmlrpccmd_serial_lock);
		int res = pthread_cond_timedwait(&xmlrpccmd_serial_cond, &xmlrpccmd_serial_lock, &then);
		pom_mutex_unlock(&xmlrpccmd_serial_lock);

		if (res == ETIMEDOUT) {
			break; // Return current values
		} else if (res) {
			xmlrpc_faultf(envP, "Error while waiting for serial condition : %s", pom_strerror(errno));
			abort();
		}

		// Update serials
		if (xml_registry_serial) {
			registry_lock();
			last_registry_serial = registry_serial_get();
			registry_unlock();
		}

		if (xml_log_serial) {
			pomlog_rlock();
			struct pomlog_entry *last_log = pomlog_get_tail();
			last_log_serial = last_log->id;
			pomlog_unlock();
		}
	
	}


	
	xmlrpc_value *res = xmlrpc_struct_new(envP);

	if (xml_registry_serial) {
		xml_registry_serial = xmlrpc_int_new(envP, last_registry_serial);
		xmlrpc_struct_set_value(envP, res, "registry", xml_registry_serial);
		xmlrpc_DECREF(xml_registry_serial);
	}

	if (xml_log_serial) {
		xml_log_serial = xmlrpc_int_new(envP, last_log_serial);
		xmlrpc_struct_set_value(envP, res, "log", xml_log_serial);
		xmlrpc_DECREF(xml_log_serial);
	}

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
		log = log->main_prev;

	while (log) {
		xmlrpc_value *entry = xmlrpc_build_value(envP, "{s:i,s:i,s:s,s:s,s:t}",
								"id", log->id,
								"level", log->level,
								"file", log->file,
								"data", log->data,
								"timestamp", (time_t)log->ts.tv_sec);
		xmlrpc_array_append_item(envP, res, entry);
		xmlrpc_DECREF(entry);
		log = log->main_next;

	}
	pomlog_unlock();

	return res;
}

xmlrpc_value *xmlrpccmd_core_poll_log(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {
	
	uint32_t last_id;
	int level, max_results;

	xmlrpc_decompose_value(envP, paramArrayP, "(iii)", &last_id, &level, &max_results);

	if (envP->fault_occurred)
		return NULL;

	xmlrpc_value *res = xmlrpc_array_new(envP);
	if (envP->fault_occurred)
		return NULL;

	struct timeval now;
	gettimeofday(&now, NULL);
	struct timespec then = { 0 };
	then.tv_sec = now.tv_sec + XMLRPCSRV_POLL_TIMEOUT;

	int count = 0, results = 0;

	while (1) {


		pomlog_rlock();
		struct pomlog_entry *log = pomlog_get_tail();

		// Go to the last entry we were at
		while (log && log->main_prev && log->id > last_id + 1) {
			log = log->main_prev;

			if (log->level <= level)
				count++;
			if (max_results && count >= max_results - 1)
				break;
		}
		
		// If we already have the last, don't do anything
		if (log && log->id <= last_id)
			log = NULL;

		// Add whatever is after our last entry
		for (; log; log = log->main_next) {
			if (log->level > level)
				continue;
			xmlrpc_value *entry = xmlrpc_build_value(envP, "{s:i,s:i,s:s,s:s,s:t}",
									"id", log->id,
									"level", log->level,
									"file", log->file,
									"data", log->data,
									"timestamp", (time_t)log->ts.tv_sec);
			xmlrpc_array_append_item(envP, res, entry);
			xmlrpc_DECREF(entry);
			results++;

		}
		pomlog_unlock();

		if (results)
			break;

		gettimeofday(&now, NULL);
		if (now.tv_sec > then.tv_sec)
			break;
		
		pomlog_poll(&then);
	};

	return res;

}
