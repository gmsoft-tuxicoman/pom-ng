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
#include "httpd.h"
#include "xmlrpcsrv.h"
#include "core.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

static char *httpd_www_data = NULL;
static struct httpd_daemon_list *http_daemons = NULL;
static char *httpd_ssl_cert = NULL, *httpd_ssl_key = NULL;

int httpd_init(char *addresses, int port, char *www_data, char *ssl_cert, char *ssl_key) {

	unsigned int mhd_flags = MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL | MHD_USE_DEBUG;

	if ((ssl_cert || ssl_key) && (!ssl_cert || !ssl_key)) {
		pomlog(POMLOG_ERR "Both SSL certificate and key must be provided.");
		return POM_ERR;
	}

	httpd_www_data = strdup(www_data);
	if (!httpd_www_data) {
		pom_oom(strlen(www_data) + 1);
		return POM_ERR;
	}

	if (ssl_cert) {
		int fd = open(ssl_cert, O_RDONLY);
		if (fd == -1) {
			pomlog(POMLOG_ERR "Unable to open the SSL cert : %s", pom_strerror(errno));
			goto err;
		}
		
		struct stat s;
		if (fstat(fd, &s) != 0) {
			pomlog(POMLOG_ERR "Could not get stats for SSL cert : %s", pom_strerror(errno));
			close(fd);
			goto err;
		}

		httpd_ssl_cert = malloc(s.st_size);
		if (!httpd_ssl_cert) {
			pom_oom(s.st_size);
			goto err;
		}
		
		if (pom_read(fd, httpd_ssl_cert, s.st_size) != POM_OK)
			goto err;

		close(fd);

	}

	if (ssl_key) {
		int fd = open(ssl_key, O_RDONLY);
		if (fd == -1) {
			pomlog(POMLOG_ERR "Unable to open the SSL key : %s", pom_strerror(errno));
			goto err;
		}
		
		struct stat s;
		if (fstat(fd, &s) != 0) {
			pomlog(POMLOG_ERR "Could not get stats for SSL key : %s", pom_strerror(errno));
			close(fd);
			goto err;
		}

		httpd_ssl_key = malloc(s.st_size);
		if (!httpd_ssl_key) {
			pom_oom(s.st_size);
			goto err;
		}
		
		if (pom_read(fd, httpd_ssl_key, s.st_size) != POM_OK)
			goto err;

		close(fd);

	}


	char *addr_tmp = strdup(addresses);
	if (!addr_tmp) {
		pom_oom(strlen(addresses) + 1);
		goto err;
	}

	char *str, *token, *saveptr = NULL;
	for (str = addr_tmp; ; str = NULL) {
		token = strtok_r(str, "; ", &saveptr);
		if (!token)
			break;



		// Get the address
		struct addrinfo hints, *res;
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_flags = AI_PASSIVE;hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		char port_str[16];
		snprintf(port_str, 16, "%u", port);
		
		if (getaddrinfo(token, port_str, &hints, &res) < 0) {
			pomlog(POMLOG_ERR "Cannot get info for address %s : %s. Ignoring.", token, pom_strerror(errno));
			continue;
		}

		struct addrinfo *tmpres;
		for (tmpres = res; tmpres; tmpres = tmpres->ai_next) {

			// Try to bind each result
			struct httpd_daemon_list *lst = malloc(sizeof(struct httpd_daemon_list));
			if (!lst) {
				pom_oom(sizeof(struct httpd_daemon_list));
				break;
			}
			memset(lst, 0, sizeof(struct httpd_daemon_list));

			unsigned int flags = mhd_flags;
			if (tmpres->ai_family == AF_INET6) {
				flags |= MHD_USE_IPv6;
			} else if (tmpres->ai_family != AF_INET) {
				continue;
			}

			if (httpd_ssl_cert && httpd_ssl_key) {
				flags |= MHD_USE_SSL;
				lst->daemon = MHD_start_daemon(flags, port, NULL, NULL, &httpd_mhd_answer_connection, NULL, MHD_OPTION_NOTIFY_COMPLETED, httpd_mhd_request_completed, NULL, MHD_OPTION_SOCK_ADDR, tmpres->ai_addr, MHD_OPTION_HTTPS_MEM_CERT, httpd_ssl_cert, MHD_OPTION_HTTPS_MEM_KEY, httpd_ssl_key, MHD_OPTION_EXTERNAL_LOGGER, httpd_logger, NULL, MHD_OPTION_END);

			} else {
				lst->daemon = MHD_start_daemon(flags, port, NULL, NULL, &httpd_mhd_answer_connection, NULL, MHD_OPTION_NOTIFY_COMPLETED, httpd_mhd_request_completed, NULL, MHD_OPTION_SOCK_ADDR, tmpres->ai_addr, MHD_OPTION_EXTERNAL_LOGGER, httpd_logger, NULL, MHD_OPTION_END);
			}

			if (lst->daemon) {
				lst->next = http_daemons;
				http_daemons = lst;
				if (httpd_ssl_cert && httpd_ssl_key) {
					pomlog(POMLOG_INFO "HTTPS daemon started on %s, port %s", token, port_str);
				} else {
					pomlog(POMLOG_INFO "HTTP daemon started on %s, port %s", token, port_str);
				}
			} else {
				free(lst);
				pomlog(POMLOG_ERR "Error while starting daemon on address \"%s\" and port %u", token, port);
			}

		}

		freeaddrinfo(res);

	}

	free(addr_tmp);

	if (!http_daemons) {
		pomlog(POMLOG_ERR "No HTTP daemon could be started");
		goto err;
	}

	return POM_OK;

err:
	free(httpd_www_data);
	httpd_www_data = NULL;

	if (httpd_ssl_cert) {
		free(httpd_ssl_cert);
		httpd_ssl_cert = NULL;
	}

	if (httpd_ssl_key) {
		free(httpd_ssl_key);
		httpd_ssl_key = NULL;
	}

	return POM_ERR;
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

	// Check credential if any
	char *admin_passwd = core_get_http_admin_password();

	if (admin_passwd && info->auth == HTTPD_AUTH_NONE) {

		char *password = NULL;
		char *username = NULL;
		
		username = MHD_basic_auth_get_username_password(connection, &password);

		if (!username || !password || strcmp(username, HTTPD_ADMIN_USER) || strcmp(password, admin_passwd)) {
			info->auth = HTTPD_AUTH_FAILED;
		} else {
			info->auth = HTTPD_AUTH_OK;
		}

		if (username)
			free(username);
		if (password)
			free(password);
	}

	if (info->auth == HTTPD_AUTH_FAILED) {

		// Only answer until we have the whole packet
		if (*upload_data_size) {
			*upload_data_size = 0;
			return MHD_YES;
		}

		static char *page = "<html><body>Invalid username or password</body></html>";
		response = MHD_create_response_from_data(strlen(page), (void *) page, MHD_NO, MHD_NO);

		if (MHD_add_response_header(response, MHD_HTTP_HEADER_WWW_AUTHENTICATE, "Basic realm=\"" HTTPD_REALM "\"") == MHD_NO) {
			pomlog(POMLOG_ERR "Error, could not add " MHD_HTTP_HEADER_WWW_AUTHENTICATE " header to the response");
			goto err;
		}

		status_code = MHD_HTTP_UNAUTHORIZED;
		mime_type = "text/html";

	} else if (!strcmp(method, MHD_HTTP_METHOD_POST) && !strcmp(url, XMLRPCSRV_URI)) {

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


	pomlog(POMLOG_INFO "Waiting for HTTP connections to timeout ...");

	while (http_daemons) {
		struct httpd_daemon_list *tmp = http_daemons;
		http_daemons = tmp->next;
		MHD_stop_daemon(tmp->daemon);
		free(tmp);
	}

	free(httpd_www_data);

	if (httpd_ssl_cert) {
		free(httpd_ssl_cert);
		httpd_ssl_cert = NULL;
	}

	if (httpd_ssl_key) {
		free(httpd_ssl_key);
		httpd_ssl_key = NULL;
	}
	return POM_OK;
}


void httpd_logger(void *arg, const char *fmt, va_list ap) {

	char buff[POMLOG_LINE_SIZE] = { 0 };

	vsnprintf(buff, POMLOG_LINE_SIZE - 1, fmt, ap);

	size_t len = strlen(buff);
	while (len) {
		if (buff[len - 1] == '\r' || buff[len - 1] == '\n')
			buff[len - 1] = 0;
		else
			break;
		len--;
	}

	pomlog(POMLOG_ERR "%s", buff);

}
