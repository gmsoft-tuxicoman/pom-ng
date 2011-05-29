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

#define PROTO_HTTP_FIELD_NUM	8

enum proto_http_fields {
	proto_http_field_host = 0,
	proto_http_field_first_line,
	proto_http_field_err_code,
	proto_http_field_request_proto,
	proto_http_field_request_method,
	proto_http_field_url,
	proto_http_field_headers,
	proto_http_field_request_dir,
};

#endif
