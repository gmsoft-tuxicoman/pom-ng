/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_ANALYZER_HTTP_H__
#define __POM_NG_ANALYZER_HTTP_H__

#define ANALYZER_HTTP_EVT_REQUEST_DATA_COUNT 19

enum analyzer_http_evt_request_data {
	analyzer_http_request_server_name = 0,
	analyzer_http_request_server_addr,
	analyzer_http_request_server_port,
	analyzer_http_request_client_addr,
	analyzer_http_request_client_port,
	analyzer_http_request_request_proto,
	analyzer_http_request_request_method,
	analyzer_http_request_first_line,
	analyzer_http_request_url,
	analyzer_http_request_query_time,
	analyzer_http_request_response_time,
	analyzer_http_request_status,
	analyzer_http_request_username,
	analyzer_http_request_password,
	analyzer_http_request_query_headers,
	analyzer_http_request_response_headers,
	analyzer_http_request_post_data,
	analyzer_http_request_query_size,
	analyzer_http_request_response_size,
};

#define ANALYZER_HTTP_EVT_COUNT 1

enum analyzer_http_events {
	analyzer_http_evt_request = 0,
};


#endif
