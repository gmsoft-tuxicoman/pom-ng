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

#ifndef __POM_NG_PROTO_HTTP_H__
#define __POM_NG_PROTO_HTTP_H__

#define PROTO_HTTP_EVT_COUNT 2

enum {
	proto_http_evt_query,
	proto_http_evt_response,
};

#define PROTO_HTTP_EVT_QUERY_DATA_COUNT 7

enum {
	proto_http_query_first_line,
	proto_http_query_proto,
	proto_http_query_method,
	proto_http_query_url,
	proto_http_query_start_time,
	proto_http_query_end_time,
	proto_http_query_headers,
};

#define PROTO_HTTP_EVT_RESPONSE_DATA_COUNT 5


enum {
	proto_http_response_status,
	proto_http_response_proto,
	proto_http_response_start_time,
	proto_http_response_end_time,
	proto_http_response_headers,
};

#endif
