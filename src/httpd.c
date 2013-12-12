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
#include "httpd.h"
#include "xmlrpcsrv.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static struct MHD_Daemon *httpd_daemon_v4 = NULL;
static struct MHD_Daemon *httpd_daemon_v6 = NULL;
static char *httpd_www_data = NULL;


int httpd_init(int port, char *www_data) {

	unsigned int mhd_flags = MHD_USE_THREAD_PER_CONNECTION;

	httpd_www_data = strdup(www_data);
	if (!httpd_www_data) {
		pom_oom(strlen(www_data) + 1);
		return POM_ERR;
	}

#ifdef MHD_USE_POLL
	mhd_flags |= MHD_USE_POLL;
#endif

	// Start the IPv4 daemon
	httpd_daemon_v4 = MHD_start_daemon(mhd_flags, port, NULL, NULL, &httpd_mhd_answer_connection, NULL, MHD_OPTION_NOTIFY_COMPLETED, httpd_mhd_request_completed, NULL, MHD_OPTION_END);

	if (!httpd_daemon_v4)
		return POM_ERR;


	// Start the IPv6 daemon (don't check for failure here)
	mhd_flags |= MHD_USE_IPv6;
	httpd_daemon_v6 = MHD_start_daemon(mhd_flags, port, NULL, NULL, &httpd_mhd_answer_connection, NULL, MHD_OPTION_NOTIFY_COMPLETED, httpd_mhd_request_completed, NULL, MHD_OPTION_END);

	return POM_OK;
}

int httpd_mhd_answer_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {

	// Store some info about this connection
	// This will be freed by httpd_mhd_request_completed()

	struct MHD_Response *response = NULL;
	char *mime_type = NULL;
	unsigned int status_code = MHD_HTTP_OK;
	struct httpd_conn_info *info = *con_cls;
	if (!info) {
		info = malloc(sizeof(struct httpd_conn_info));
		if (!info) {
			pomlog(POMLOG_ERR "Not enough memory to allocate struct httpd_conn_info");
			return MHD_NO;
		}

		memset(info, 0, sizeof(struct httpd_conn_info));


		*con_cls = (void*) info;
		return MHD_YES;
	}


	if (!strcmp(method, MHD_HTTP_METHOD_POST) && !strcmp(url, XMLRPCSRV_URI)) {

		// Process XML-RPC command
		
		if (*upload_data_size) {
			size_t totlen = info->buffpos + *upload_data_size + 1;
			if (totlen > info->buffsize) {
				info->buff = realloc(info->buff, totlen);
				if (!info->buff) {
					pomlog(POMLOG_ERR "Not enough memory to store XML-RPC request");
					return MHD_NO;
				}
				info->buffsize = totlen;
			}
			memcpy(info->buff + info->buffpos, upload_data, *upload_data_size);
			info->buffpos += *upload_data_size;
			*upload_data_size = 0;

			// Terminate with a null just in case
			*(info->buff + info->buffpos) = 0;
			return MHD_YES;

		}

		// Process the query and send the output
		char *xml_response = NULL;
		size_t xml_reslen = 0;
		xmlrpcsrv_process(info->buff, info->buffpos, &xml_response, &xml_reslen);
		free(info->buff);

		response = MHD_create_response_from_data(xml_reslen, (void *)xml_response, MHD_YES, MHD_NO);
		mime_type = "text/xml";

	} else if (!strcmp(method, MHD_HTTP_METHOD_GET)) {
		// Process GET request

		if (!strcmp(url, HTTPD_STATUS_URL)) {
			const char *replystr = "<html><body>It works !<br/>I'm running as uid %u and gid %u.</body></html>";

			size_t buffsize = strlen(replystr) + 20;

			char *buffer = malloc(buffsize);
			if (!buffer) {
				pomlog(POMLOG_ERR "Not enough memory to allocate a buffer of %u bytes", buffsize);
				return MHD_NO;
			}
			memset(buffer, 0, buffsize);

			snprintf(buffer, buffsize - 1, replystr, geteuid(), getegid());

			response = MHD_create_response_from_data(strlen(buffer), (void *) buffer, MHD_YES, MHD_NO);
			mime_type = "text/html";
		} else if (strstr(url, "..")) {
			// We're not supposed to have .. in a url
			status_code = MHD_HTTP_NOT_FOUND;

			char *replystr = "<html><head><title>Not found</title></head><body>Go away.</body></html>";
			response = MHD_create_response_from_data(strlen(replystr), (void *) replystr, MHD_NO, MHD_NO);

		} else {
			char *filename = malloc(strlen(httpd_www_data) + strlen(url) + 1);
			if (!filename) {
				pom_oom(strlen(httpd_www_data) + strlen(url) + 1);
				goto err;
			}
			strcpy(filename, httpd_www_data);
			strcat(filename, url);

			if (strlen(filename) && filename[strlen(filename) - 1] == '/') {
				// Directory, add index page.
				char *index_filename = realloc(filename, strlen(filename) + strlen(HTTPD_INDEX_PAGE) + 1);
				if (!index_filename) {
					pom_oom(strlen(filename) + strlen(HTTPD_INDEX_PAGE) + 1);
					free(filename);
					goto err;
				}
				strcat(index_filename, HTTPD_INDEX_PAGE);
				filename = index_filename;
			}

			// Guess the mime type
			mime_type = "binary/octet-stream";
			char *ext = strrchr(filename, '.');
			if (ext) {
				ext++;
				if (!strcasecmp(ext, "html") || !strcasecmp(ext, "htm"))
					mime_type = "text/html";
				else if (!strcasecmp(ext, "png"))
					mime_type = "image/png";
				else if (!strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg"))
					mime_type = "image/jpeg";
				else if (!strcasecmp(ext, "js"))
					mime_type = "application/javascript";
				else if (!strcasecmp(ext, "css"))
					mime_type = "text/css";
			}


			int fd = open(filename, O_RDONLY);
			size_t file_size;

			if (fd != -1) {
				struct stat buf;
				if (fstat(fd, &buf)) {
					close(fd);
					fd = -1;
				} else {
					file_size = buf.st_size;
				}
			}

			if (fd == -1) {
				char *replystr = "<html><head><title>Not found</title></head><body>File not found</body></html>";
				response = MHD_create_response_from_data(strlen(replystr), (void *) replystr, MHD_NO, MHD_NO);
				status_code = MHD_HTTP_NOT_FOUND;
			} else {
				response = MHD_create_response_from_fd(file_size, fd);
			}

			free(filename);
		}

	} else {
		pomlog(POMLOG_INFO "Unknown request %s for %s using version %s", method, url, version);
		return MHD_NO;
	}

	if (!response) {
		pomlog(POMLOG_ERR "Error while creating response for request \"%s\"", url);
		return MHD_NO;
	}
	
	if (mime_type && MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, mime_type) == MHD_NO) {
		pomlog(POMLOG_ERR "Error, could not add " MHD_HTTP_HEADER_CONTENT_TYPE " header to the response");
		goto err;
	}

	if (MHD_add_response_header(response, MHD_HTTP_HEADER_SERVER, PACKAGE_NAME) == MHD_NO) {
		pomlog(POMLOG_ERR "Error, could not add " MHD_HTTP_HEADER_SERVER " header to the response");
		goto err;
	}

	if (MHD_queue_response(connection, status_code, response) == MHD_NO) {
		pomlog(POMLOG_ERR "Error, could not queue HTTP response");
		goto err;
	}

	MHD_destroy_response(response);
	return MHD_YES;

err:
	MHD_destroy_response(response);
	return MHD_NO;

}


void httpd_mhd_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {

	struct httpd_conn_info *info = (struct httpd_conn_info*) *con_cls;

	if (!info)
		return;

	free(info);
	*con_cls = NULL;

}


int httpd_cleanup() {

	if (httpd_daemon_v4) {
		MHD_stop_daemon(httpd_daemon_v4);
		httpd_daemon_v4 = NULL;
	}

	if (httpd_daemon_v6) {
		MHD_stop_daemon(httpd_daemon_v6);
		httpd_daemon_v6 = NULL;
	}

	free(httpd_www_data);

	return POM_OK;
}
