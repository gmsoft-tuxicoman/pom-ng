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
#include "httpd.h"
#include "xmlrpcsrv.h"

static struct MHD_Daemon *httpd_daemon_v4 = NULL;
static struct MHD_Daemon *httpd_daemon_v6 = NULL;


int httpd_init(int port) {

	unsigned int mhd_flags = MHD_USE_THREAD_PER_CONNECTION;

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

	} else {
		pomlog(POMLOG_INFO "Unknown request %s for %s using version %s", method, url, version);
		return MHD_NO;
	}

	if (!response) {
		pomlog(POMLOG_ERR "Error while creating response for request \"%s\"", url);
		return MHD_NO;
	}
	
	if (MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, mime_type) == MHD_NO) {
		pomlog(POMLOG_ERR "Error, could not add " MHD_HTTP_HEADER_CONTENT_TYPE " header to the response");
		goto err;
	}

	if (MHD_add_response_header(response, MHD_HTTP_HEADER_SERVER, PACKAGE_NAME) == MHD_NO) {
		pomlog(POMLOG_ERR "Error, could not add " MHD_HTTP_HEADER_SERVER " header to the response");
		goto err;
	}

	if (MHD_queue_response(connection, MHD_HTTP_OK, response) == MHD_NO) {
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

	return POM_OK;
}
