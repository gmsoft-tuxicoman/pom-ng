/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/base.h>
#include <pom-ng/analyzer.h>

#define MIME_MAX_PARAMETERS	5

// From RFC 2046

enum mime_top_type {
	// Unknown type
	mime_top_type_unknown,

	// Discrete types
	mime_top_type_text,
	mime_top_type_image,
	mime_top_type_audio,
	mime_top_type_video,
	mime_top_type_application,

	// Composite top-level types
	mime_top_type_multipart,
	mime_top_type_message
};

struct mime_parameter {
	char *name;
	char *value;
};

struct mime {
	
	enum mime_top_type top_type;
	char *type_str;
	struct mime_parameter params[MIME_MAX_PARAMETERS];

};


struct mime *mime_parse(char *content_type);
void mime_cleanup(struct mime *mime);

char *mime_get_param(struct mime *mime, char *param_name);

int mime_parse_header(struct data *data, char *line, size_t line_len);


#endif

