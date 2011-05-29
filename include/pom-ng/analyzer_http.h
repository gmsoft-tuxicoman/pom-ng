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

#define ANALYZER_HTTP_DATA_FIELDS_COUNT 14

enum analyzer_http_fields {
	analyzer_http_data_server_name = 0,
	analyzer_http_data_server_addr,
	analyzer_http_data_server_port,
	analyzer_http_data_client_addr,
	analyzer_http_data_client_port,
	analyzer_http_data_request_proto,
	analyzer_http_data_request_method,
	analyzer_http_data_first_line,
	analyzer_http_data_url,
	analyzer_http_data_query_time,
	analyzer_http_data_response_time,
	analyzer_http_data_status,
	analyzer_http_data_username,
	analyzer_http_data_password,
};


#endif
