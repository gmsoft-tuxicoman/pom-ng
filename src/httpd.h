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


#ifndef __HTTPD_H__
#define __HTTPD_H__

#include <sys/socket.h>
#include <microhttpd.h>
#include <uthash.h>
#include <pom-ng/pload.h>

#define HTTPD_CONN_UNK	0
#define HTTPD_CONN_GET	1
#define HTTPD_CONN_POST	2

#define HTTPD_POST_BUFF_SIZE	512

#define HTTPD_STATUS_URL	"/status.html"
#define HTTPD_INDEX_PAGE	"index.html"
#define HTTPD_PLOAD_URL		"/pload/"

#define HTTPD_ADMIN_USER	"admin"
#define HTTPD_REALM		"POM-NG Authentication"

#define HTTPD_AUTH_NONE		0
#define HTTPD_AUTH_OK		1
#define HTTPD_AUTH_FAILED	2

#define HTTPD_PLOAD_DEFAULT_MIME_TYPE	"application/octet-stream"

struct httpd_daemon_list {
	struct MHD_Daemon *daemon;
	int listen_fd;
	struct httpd_daemon_list *next;
};

struct httpd_conn_info {

	char *buff;
	size_t buffsize;
	size_t buffpos;
	unsigned int auth;

};

struct httpd_pload {

	uint64_t id;
	struct pload_store *store;
	char *mime_type;
	UT_hash_handle hh;

};

struct httpd_pload_response {

	struct pload_store *store;
	struct pload_store_map *map;
};

int httpd_init(char *addresses, int port, char* www_data, char *ssl_cert, char *ssl_key);
int httpd_mhd_answer_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);
void httpd_mhd_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe);
int httpd_cleanup();
void httpd_logger(void *arg, const char *fmt, va_list ap);

uint64_t httpd_pload_add(struct pload *pload);
void httpd_pload_remove(uint64_t id);

ssize_t httpd_pload_response_callback(void *cls, uint64_t pos, char *buf, size_t max);
void httpd_pload_response_callback_free(void *cls);

#endif
