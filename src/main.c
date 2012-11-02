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

#include <getopt.h>
#include <pwd.h>
#include <signal.h>
#include <sys/msg.h>
#include <sys/wait.h>

#include "main.h"
#include "input.h"
#include "core.h"
#include "xmlrpcsrv.h"
#include "httpd.h"
#include "registry.h"
#include "mod.h"
#include "pomlog.h"
#include "proto.h"
#include "packet.h"
#include "timer.h"
#include "analyzer.h"
#include "output.h"
#include "datastore.h"
#include "addon.h"

#include <pom-ng/ptype.h>

static char* shutdown_reason = NULL;
static int running = 1, shutdown_in_error = 0;
static struct datastore *system_store = NULL;
static pthread_t main_thread = 0;

void signal_handler(int signal) {

	switch (signal) {
		case SIGCHLD:
			break;
		case SIGINT:
		case SIGTERM:
		default:
			printf("Main process received signal %u, shutting down ...\n", signal);
			halt_signal("Received signal");
			break;

	}
}

void print_usage() {
	printf(	"Usage : " PACKAGE_NAME " [options]\n"
		"\n"
		"Options :\n"
		" -d, --debug=LEVEL		specify the debug level <0-4> (default: 3)\n"
		" -h, --help			print this usage\n"
		" -u, --user=USER		drop privilege to this user\n"
		" -s, --system-store=STORE	URI to use for the system datastore (default: '" POMNG_SYSTEM_DATASTORE "')\n"
		" -t, --threads=num		number of processing threads to start (default: number of cpu)\n"
		"\n"
		);
}

struct datastore *open_system_datastore(char *dstore_uri) {

	// Parse the URI
	// Format of the URI : type:datastore_name?param1_name=param1_value&param2_name=param2_value&..."


	char my_store[1024] = {0};
	strncpy(my_store, dstore_uri, sizeof(my_store) - 1);
	char *type = my_store;
	char *store = strchr(type, ':');
	if (!store) {
		pomlog(POMLOG_ERR "Unparseable config_datastore URI");
		return NULL;
	}

	*store = 0;
	store++;

	char *params = strchr(store, '?');
	if (params) {
		*params = 0;
		params++;
	}

	// Add the datastore instance
	if (datastore_instance_add(type, store) != POM_OK) {
		pomlog(POMLOG_ERR "Unable to create the config datastore instance");
		return NULL;
	}

	struct datastore *dstore = datastore_instance_get(store);
	if (!dstore) {
		pomlog(POMLOG_ERR "Error while getting the config datastore instance");
		return NULL;
	}

	// Set the parameters
	char *str, *token, *saveptr = NULL;
	for (str = params; ; str = NULL) {
		token = strtok_r(str, "&", &saveptr);
		if (!token)
			break;

		char *value = strchr(token, '=');
		if (!value) {
			pomlog(POMLOG_ERR "No value provided for parameter %s", token);
			return NULL;
		}

		*value = 0;
		value++;
		
		if (registry_set_param(dstore->reg_instance, token, value) != POM_OK)
			return NULL;

	}

	if (datastore_open(dstore) != POM_OK)
		return NULL;

	return dstore;

}


int main(int argc, char *argv[]) {

	// Parse options

	int c;
	
	uid_t uid = 0;
	gid_t gid = 0;
	int num_threads = 0;

	char *system_store_uri = POMNG_SYSTEM_DATASTORE;

	while (1) {

		static struct option long_options[] = {
			{ "user", 1, 0, 'u' },
			{ "debug", 1, 0, 'd' },
			{ "threads", 1, 0, 't' },
			{ "system-store", 1, 0, 's' },
			{ "help", 0, 0, 'h' },
			{ 0 }
		};

		
		char *args = "u:d:t:s:h";

		c = getopt_long(argc, argv, args, long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
			case 'u': {
				char *user = optarg;
				struct passwd pwd, *res;

				long buffsize = sysconf(_SC_GETPW_R_SIZE_MAX);
				if (buffsize < 0) {
					pomlog(POMLOG_ERR "Could not find out buffer size for getpwnam_r()");
					return -1;
				}

				char *buff = malloc(buffsize);

				getpwnam_r(user, &pwd, buff, buffsize, &res);
				if (!res) {
					pomlog(POMLOG_ERR "Could not get user info, does user %s exists ?", user);
					return -1;
				}
				free(buff);


				uid = pwd.pw_uid;
				gid = pwd.pw_gid;

				break;
			}
			case 'd': {
				unsigned int debug_level = 0;
				if (sscanf(optarg, "%u", &debug_level) == 1) {
					pomlog_set_debug_level(debug_level);
				} else {
					printf("Invalid debug level \"%s\"\n", optarg);
					print_usage();
					return -1;
				}
				break;
			}
			case 's': {
				system_store_uri = optarg;
				break;
			}
			case 't': {
				if (sscanf(optarg, "%u", &num_threads) != 1) {
					printf("Invalid number of threads : \"%s\"\n", optarg);
					print_usage();
					return -1;
				}
				break;
			}
			case 'h':
			default:
				print_usage();
				return 1;
		}


	}

	pomlog("Starting " PACKAGE_NAME " ...");

	// Drop privileges if provided

	if (gid && setegid(gid)) {
		pomlog(POMLOG_ERR "Failed to drop group privileges : %s", strerror(errno));
		return -1;
	}
	if (uid && seteuid(uid)) {
		pomlog(POMLOG_ERR "Failed to drop user privileges : %s", strerror(errno));
		return -1;
	}

	if (uid || gid)
		pomlog(POMLOG_ERR "Dropped privileges to uid/gid %u/%u", geteuid(), getegid());

	// Install signal handler

	struct sigaction mysigaction;
	sigemptyset(&mysigaction.sa_mask);
	mysigaction.sa_flags = 0;
	mysigaction.sa_handler = signal_handler;
	sigaction(SIGINT, &mysigaction, NULL);
	sigaction(SIGTERM, &mysigaction, NULL);
	sigaction(SIGCHLD, &mysigaction, NULL);

	main_thread = pthread_self();

	// Initialize components
	
	if (registry_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the registry");
		goto err_registry;
	}

	if (proto_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the protocols");
		goto err_proto;
	}

	if (analyzer_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the analyzers");
		goto err_analyzer;
	}

	if (input_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the inputs");
		goto err_input;
	}

	if (output_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the outputs");
		goto err_output;
	}

	if (datastore_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the datastores");
		goto err_datastore;
	}

	// Load all the available modules
	if (mod_load_all() != POM_OK) { 
		pomlog(POMLOG_ERR "Error while loading modules. Exiting");
		goto err_datastore;
	}

	if (xmlrpcsrv_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while starting XML-RPC server");
		goto err_xmlrpcsrv;
	}

	if (httpd_init(POMNG_HTTPD_PORT, POMNG_HTTPD_WWW_DATA) != POM_OK) {
		pomlog(POMLOG_ERR "Error while starting HTTP server");
		goto err_httpd;
	}

	if (core_init(num_threads) != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing core");
		goto err_core;
	}

	system_store = open_system_datastore(system_store_uri);
	if (!system_store) {
		pomlog(POMLOG_ERR "Unable to open the system datastore");
		goto err_dstore;
	}

	if (addon_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing addons");
		goto err_addon;
	}

	// Main loop
	
	pomlog(PACKAGE_NAME " started !");

	while (running)
		sleep(10);

	pomlog(POMLOG_INFO "Shutting down : %s", shutdown_reason);
	free(shutdown_reason);
	shutdown_reason = NULL;

	input_stop_all();

	if (!shutdown_in_error)
		core_wait_state(core_state_idle);

	// Cleanup components

	core_cleanup(shutdown_in_error);

	packet_pool_cleanup();
	packet_buffer_pool_cleanup();
	input_cleanup();
	httpd_cleanup();
	xmlrpcsrv_cleanup();
	output_cleanup();
	analyzer_cleanup();
	proto_cleanup();
	addon_cleanup();
	datastore_close(system_store);
	datastore_cleanup();
	registry_cleanup();
	timers_cleanup();

	mod_unload_all();


	pomlog_cleanup();
	printf(PACKAGE_NAME " shutted down\n");



	return 0;
	
	// Error path below


err_addon:
	addon_cleanup();
err_dstore:
	core_cleanup(1);
err_core:
	httpd_cleanup();
err_httpd:
	xmlrpcsrv_cleanup();
err_xmlrpcsrv:
	datastore_cleanup();
err_datastore:
	output_cleanup();
err_output:
	input_cleanup();
err_input:
	analyzer_cleanup();
err_analyzer:
	proto_cleanup();
err_proto:
	registry_cleanup();
err_registry:
	timers_cleanup();
	mod_unload_all();
	pomlog_cleanup();

	printf(PACKAGE_NAME " failed to initialize\n");
	return -1; 
}

int halt(char *reason, int error) {

	shutdown_reason = strdup(reason);
	shutdown_in_error = error;
	running = 0;

	pthread_kill(main_thread, SIGCHLD);
	
	return POM_OK;
}

int halt_signal(char *reason) {
	// Called from a signal handler, don't use pomlog()
	if (shutdown_reason)
		free(shutdown_reason);
	shutdown_reason = strdup(reason);

	running = 0;

	return POM_OK;
}

struct datastore *system_datastore() {
	return system_store;
}
