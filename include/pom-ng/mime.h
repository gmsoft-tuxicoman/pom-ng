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

enum mime_top_type {
	// Discrete types
	mime_top_type_text,
	mime_top_type_image,
	mime_top_type_audio,
	mime_top_type_video,
	mime_top_type_application,
	mime_top_type_binary,

	// Composite top-level types
	mime_top_type_multipart,
	mime_top_type_message,

	// Unknown type
	mime_top_type_unknown,

};

struct mime_type_parameter {
	char *name;
	char *value;
};

struct mime_type {
	
	enum mime_top_type top_type;
	char *name;
	struct mime_type_parameter params[MIME_MAX_PARAMETERS];

};


struct mime_type *mime_type_alloc(enum mime_top_type, char *name);
enum mime_top_type mime_top_type_parse(char *top_type);
struct mime_type *mime_type_parse(char *content_type);
void mime_type_cleanup(struct mime_type *mime);

int mime_type_set_param(struct mime_type *mime_type, char *param_name, char* param_value);
char *mime_type_get_param(struct mime_type *mime, char *param_name);

int mime_header_parse(struct data *data, char *line, size_t line_len);

char *mime_top_type_str(enum mime_top_type type);

#endif

