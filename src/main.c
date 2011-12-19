/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2011 Guy Martin <gmsoft@tuxicoman.be>
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
#include "input_server.h"
#include "input_client.h"
#include "input_ipc.h"
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

#include <pom-ng/ptype.h>

static char* shutdown_reason = NULL;
static pid_t input_process_pid = 0;
static int running = 1, shutdown_in_error = 0;
static pthread_t input_ipc_thread;

void signal_handler(int signal) {

	switch (signal) {
		case SIGCHLD:
			if (running)
				halt_signal("Input process died :-(\n");
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
		" -d, --debug=LEVEL	specify the debug level <0-4> (default: 3)\n"
		" -h, --help		print this usage\n"
		" -u, --user=USER	drop privilege to this user\n"
		" -t, --threads=num     number of processing threads to start (default: number of cpu)\n"
		"\n"
		);
}


int main(int argc, char *argv[]) {

	// Parse options

	int c;
	
	uid_t uid = 0;
	gid_t gid = 0;
	int num_threads = 0;

	while (1) {

		static struct option long_options[] = {
			{ "user", 1, 0, 'u' },
			{ "debug", 1, 0, 'd' },
			{ "threads", 1, 0, 't' },
			{ "help", 0, 0, 'h' },
		};

		
		char *args = "u:d:t:h";

		c = getopt_long(argc, argv, args, long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
			case 'u': {
				char *user = optarg;
				struct passwd pwd, *res;

				size_t buffsize = sysconf(_SC_GETPW_R_SIZE_MAX);
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

	// Create IPC key and queue
	
	key_t input_ipc_key = 0;
	
	int i;
	for (i = 0; i < strlen(PACKAGE_NAME); i++)
		input_ipc_key += PACKAGE_NAME[i];
	input_ipc_key += getpid();

	int input_ipc_queue = input_ipc_create_queue(input_ipc_key);
	if (input_ipc_queue == POM_ERR) {
		pomlog(POMLOG_ERR "Unable to create IPC message queue");
		return -1;
	}
	
	// Change the permissions of the queue to the low privilege user
	if (uid || gid) {
		if (input_ipc_set_uid_gid(input_ipc_queue, uid, gid) != POM_OK) {
			pomlog(POMLOG_ERR "Could not set right permissions on the IPC queue");
			return -1;
		}
	}

	// Fork the input process while we have root privileges
	input_process_pid = fork();

	if (input_process_pid == -1) {
		pomlog(POMLOG_ERR "Error while forking()");
		return -1;
	}

	if (!input_process_pid) { // Child
		return input_server_main(input_ipc_key, uid, gid);
	}

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
		pomlog(POMLOG_ERR "Main process dropped privileges to uid/gid %u/%u", geteuid(), getegid());

	// Install signal handler

	struct sigaction mysigaction;
	sigemptyset(&mysigaction.sa_mask);
	mysigaction.sa_flags = 0;
	mysigaction.sa_handler = signal_handler;
	sigaction(SIGINT, &mysigaction, NULL);
	sigaction(SIGCHLD, &mysigaction, NULL);
	sigaction(SIGTERM, &mysigaction, NULL);

	// Initialize components
	
	// Wait for the IPC queue to be created
	int input_queue_id = input_ipc_get_queue(input_ipc_key);
	if (input_queue_id == -1)
		goto err_early;

	// Init the input IPC log thread
	if (pomlog_ipc_thread_init(&input_queue_id) != POM_OK)
		goto err_early;

	if (registry_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the registry");
		goto err_registry;
	}

	if (proto_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the protocols");
		goto err_proto;
	}

	if (analyzer_init(DATAROOT "/mime_types.xml") != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the analyzers");
		goto err_analyzer;
	}

	if (output_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the outputs");
		goto err_output;
	}

	if (input_client_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the input_client module");
		goto err_input_client;
	}

	if (input_ipc_create_processing_thread(&input_ipc_thread, &input_queue_id, &running) != POM_OK) {
		goto err_input_ipc_thread;
	}

	// Load all the available modules
	if (mod_load_all() != POM_OK) { 
		pomlog(POMLOG_ERR "Error while loading modules. Exiting");
		goto err_mod;
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

	// Main loop
	
	pomlog(PACKAGE_NAME " started !");

	while (running)
		sleep(10);

	pomlog(POMLOG_INFO "Shutting down : %s", shutdown_reason);
	free(shutdown_reason);
	shutdown_reason = NULL;

	if (!shutdown_in_error)
		core_wait_state(core_state_idle);

	// Cleanup components

	packet_pool_cleanup();


	core_cleanup(shutdown_in_error);


	
	httpd_cleanup();
	xmlrpcsrv_cleanup();
	timers_cleanup();
	input_client_cleanup(shutdown_in_error);
	output_cleanup();
	analyzer_cleanup();
	proto_cleanup();
	registry_cleanup();

	input_ipc_server_halt();
	pomlog("Waiting for input process to terminate ...");
	waitpid(input_process_pid, NULL, 0);
	input_ipc_cleanup();

	pthread_cancel(input_ipc_thread);
	pthread_join(input_ipc_thread, NULL);

	mod_unload_all();


	pomlog_cleanup();
	// Delete the IPC queue
	if (msgctl(input_ipc_queue, IPC_RMID, 0)) {
		printf("Unable to remove the IPC msg queue while terminating\n");
	}
	printf(PACKAGE_NAME " shutted down\n");



	return 0;
	
	// Error path below

err_core:
	httpd_cleanup();
err_httpd:
	xmlrpcsrv_cleanup();
err_xmlrpcsrv:
	mod_unload_all();
err_mod:
	pthread_cancel(input_ipc_thread);
	pthread_join(input_ipc_thread, NULL);
err_input_ipc_thread:
	input_client_cleanup(shutdown_in_error);
err_input_client:
	output_cleanup();
err_output:
	analyzer_cleanup();
err_analyzer:
	proto_cleanup();
err_proto:
	registry_cleanup();
err_registry:
	input_ipc_server_halt();
	pomlog("Waiting for input process to terminate ...");
	waitpid(input_process_pid, NULL, 0);
	input_ipc_cleanup();
err_early:
	timers_cleanup();
	pomlog_cleanup();

	// Delete the IPC queue
	if (msgctl(input_ipc_queue, IPC_RMID, 0)) {
		printf("Unable to remove the IPC msg queue while terminating\n");
	}


	printf(PACKAGE_NAME " failed to initialize\n");
	return -1; 
}

int halt(char *reason) {
	if (halt_signal(reason) != POM_OK)
		return POM_ERR;

	shutdown_in_error = 1;

	return POM_OK;
}

int halt_signal(char *reason) {
	// Can be called from a signal handler, don't use pomlog()
	shutdown_reason = strdup(reason);

	running = 0;

	return POM_OK;
}

