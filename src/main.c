/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include "event.h"
#include "pload.h"

#include <pom-ng/ptype.h>

static char* shutdown_reason = NULL;
static int running = 1, shutdown_in_error = 0;
static struct datastore *system_store = NULL;
static pthread_t main_thread = 0;
static int httpd_port = POMNG_HTTPD_PORT;
static char *httpd_addresses = POMNG_HTTPD_ADDRESSES;
static char *httpd_ssl_cert = NULL, *httpd_ssl_key = NULL;

static struct main_timer *main_timer_head = NULL, *main_timer_tail = NULL;
static pthread_mutex_t main_timer_lock;

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
		" -d, --debug=LEVEL           specify the debug level <0-4> (default: 3)\n"
		" -h, --help                  print this usage\n"
		" -u, --user=USER             drop privilege to this user\n"
		" -s, --system-store=STORE    URI to use for the system datastore (default: '" POMNG_SYSTEM_DATASTORE "')\n"
		" -t, --threads=num           number of processing threads to start (default: number of cpu - 1)\n"
		" -b, --bind=addresses        comma separated list of ip address to bind to (v4 or v6) (default : '0.0.0.0;::')\n"
		" -p, --port=num              port fo the HTTP interface (default: %u)\n"
		" -c, --ssl-certificate=file  cerficate file for HTTPS (default: none)\n"
		" -k, --ssl-key=file          key file for HTTPS (default: none)\n"
		"\n"
		, POMNG_HTTPD_PORT);
}

struct datastore *system_datastore_open(char *dstore_uri) {

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

int system_datastore_close() {
	system_store = NULL;
	return POM_OK;
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
			{ "bind", 1, 0, 'b'},
			{ "port", 1, 0, 'p' },
			{ "help", 0, 0, 'h' },
			{ 0 }
		};

		
		char *args = "u:d:t:s:b:p:c:k:h";

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
			case 'b' : {
				httpd_addresses = optarg;
				break;
			}
			case 'p': {
				if (sscanf(optarg, "%u", &httpd_port) != 1) {
					printf("Invalid port number : \"%s\"\n", optarg);
					print_usage();
					return -1;
				}
				break;
			}
			case 'c': {
				httpd_ssl_cert = optarg;
				break;
			}
			case 'k': {
				httpd_ssl_key = optarg;
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

	if (event_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the events");
		goto err_event;
	}

	if (proto_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the protocols");
		goto err_proto;
	}

	if (pload_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initialize the payloads");
		goto err_pload;
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

	if (core_init(num_threads) != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing core");
		goto err_core;
	}

	if (httpd_init(httpd_addresses, httpd_port, POMNG_HTTPD_WWW_DATA, httpd_ssl_cert, httpd_ssl_key) != POM_OK) {
		pomlog(POMLOG_ERR "Error while starting HTTP server");
		goto err_httpd;
	}

	if (timers_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the timers");
		goto err_timer;
	}

	if (packet_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing the packets");
		goto err_packet;
	}

	system_store = system_datastore_open(system_store_uri);
	if (!system_store) {
		pomlog(POMLOG_ERR "Unable to open the system datastore");
		goto err_dstore;
	}

	if (addon_init() != POM_OK) {
		pomlog(POMLOG_ERR "Error while initializing addons");
		goto err_addon;
	}

	// Main loop
	
	pomlog(PACKAGE_NAME " started ! You can now connect using pom-ng-console.");

	while (running) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		pom_mutex_lock(&main_timer_lock);
		while (main_timer_head && main_timer_head->expiry <= tv.tv_sec) {
			struct main_timer *t = main_timer_head;
			main_timer_head = main_timer_head->next;
			if (!main_timer_head) {
				main_timer_tail = NULL;
			} else {
				main_timer_head->prev = NULL;
			}

			pom_mutex_unlock(&main_timer_lock);
			if (t->handler(t->priv) != POM_OK)
				pomlog(POMLOG_ERR "Error while running main_timer handler");
			pom_mutex_lock(&main_timer_lock);
		}
		pom_mutex_unlock(&main_timer_lock);
		sleep(MAIN_TIMER_DELAY);
	}

	pomlog(POMLOG_INFO "Shutting down : %s", shutdown_reason);
	free(shutdown_reason);
	shutdown_reason = NULL;

	input_stop_all();

	if (!shutdown_in_error)
		core_wait_state(core_state_idle);

	// Cleanup components

	core_cleanup(shutdown_in_error);

	input_cleanup();
	xmlrpcsrv_stop();
	httpd_cleanup();
	xmlrpcsrv_cleanup();
	output_cleanup();
	analyzer_cleanup();
	pload_cleanup();
	proto_cleanup();
	addon_cleanup();
	datastore_close(system_store);
	datastore_cleanup();
	event_finish();
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
err_timer:
err_packet:
err_httpd:
	httpd_cleanup();
err_core:
	core_cleanup(1);
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
	pload_cleanup();
err_pload:
	proto_cleanup();
err_proto:
	event_finish();
err_event:
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


struct main_timer* main_timer_alloc(void *priv, int (*handler) (void*)) {
	struct main_timer *res = malloc(sizeof(struct main_timer));
	if (!res) {
		pom_oom(sizeof(struct main_timer));
		return NULL;
	}
	memset(res, 0, sizeof(struct main_timer));
	res->priv = priv;
	res->handler = handler;

	return res;
}

int main_timer_queue(struct main_timer *t, time_t timeout) {

	struct timeval tv;
	gettimeofday(&tv, NULL);
	t->expiry = tv.tv_sec + timeout;

	pom_mutex_lock(&main_timer_lock);
	struct main_timer *tmp = main_timer_head;
	while (tmp && tmp->expiry < t->expiry)
		tmp = tmp->next;

	if (!tmp) {
		t->prev = main_timer_tail;
	} else {
		t->next = tmp;
		t->prev = tmp->prev;
	}

	if (t->prev) {
		t->prev->next = t;
	} else {
		main_timer_head = t;	
	}

	if (t->next) {
		t->next->prev = t;
	} else {
		main_timer_tail = t;
	}
	pom_mutex_unlock(&main_timer_lock);
	
	return POM_OK;
}

int main_timer_dequeue(struct main_timer *t) {

	pom_mutex_lock(&main_timer_lock);
	if (t->prev || t->next || main_timer_head == t) {
		if (t->prev)
			t->prev->next = t->next;
		else
			main_timer_head = t->next;
		if (t->next)
			t->next->prev = t->prev;
		else
			main_timer_tail = t->prev;
		t->prev = NULL;
		t->next = NULL;
	}
	pom_mutex_unlock(&main_timer_lock);
	return POM_OK;
}

int main_timer_cleanup(struct main_timer *t) {

	pom_mutex_lock(&main_timer_lock);
	if (t->prev || t->next || main_timer_head == t) {
		if (t->prev)
			t->prev->next = t->next;
		else
			main_timer_head = t->next;
		if (t->next)
			t->next->prev = t->prev;
		else
			main_timer_tail = t->prev;
	}
	pom_mutex_unlock(&main_timer_lock);

	free(t);
	return POM_OK;
}
