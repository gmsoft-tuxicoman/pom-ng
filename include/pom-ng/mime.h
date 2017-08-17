/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_MIME_H__
#define __POM_NG_MIME_H__

#include <pom-ng/data.h>
#include <pom-ng/base.h>

#define MIME_MAX_PARAMETERS	5

// From RFC 2046

enum mime_dispositions {
	mime_disposition_unknown = 0,
	mime_disposition_inline,
	mime_disposition_attachement,
};

struct mime_parameter {
	char *name;
	char *value;
};

struct mime_type {
	
	char *name;
	struct mime_parameter params[MIME_MAX_PARAMETERS];

};

struct mime_disposition {
	enum mime_dispositions disposition;
	struct mime_parameter params[MIME_MAX_PARAMETERS];
};


struct mime_type *mime_type_parse(char *content_type);
void mime_type_cleanup(struct mime_type *mime);

struct mime_disposition *mime_disposition_parse(char *content_disposition);
void mime_disposition_cleanup(struct mime_disposition *mime_disposition);

char *mime_type_get_param(struct mime_type *mime_type, char *param_name);
char *mime_disposition_get_param(struct mime_disposition *mime_disposition, char *param_name);

int mime_header_parse(struct data *data, char *line, size_t line_len);

int mime_header_parse_encoded_value(char *buff, size_t in_len, size_t *out_len);


#endif

