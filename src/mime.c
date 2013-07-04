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


#include "common.h"
#include <pom-ng/mime.h>

struct mime_top_type_str {
	enum mime_top_type top_type;
	char *str;
};

static struct mime_top_type_str mime_top_types_str[] = {
	{ mime_top_type_text, "text" },
	{ mime_top_type_image, "image" },
	{ mime_top_type_audio, "audio" },
	{ mime_top_type_video, "video" },
	{ mime_top_type_application, "application" },
	{ mime_top_type_multipart, "multipart" },
	{ mime_top_type_message, "message" },
	{ mime_top_type_unknown, NULL },
};

struct mime *mime_parse(char *content_type) {

	if (!content_type)
		return NULL;

	while (*content_type == ' ')
		content_type++;


	struct mime *mime = malloc(sizeof(struct mime));
	if (!mime) {
		pom_oom(sizeof(struct mime));
		return NULL;
	}
	memset(mime, 0, sizeof(struct mime));

	// First, copy the filtered content_type
	
	char *sc = strchr(content_type, ';');

	size_t type_len;
	if (sc)
		type_len = sc - content_type;
	else
		type_len = strlen(content_type);

	while (type_len > 0 && content_type[type_len - 1] == ' ')
		type_len--;

	mime->type_str = strndup(content_type, type_len);
	if (!mime->type_str) {
		pom_oom(type_len);
		free(mime);
		return NULL;
	}

	// Find the top type
	int i;
	for (i = 0; mime_top_types_str[i].str; i++) {
		if (!strncasecmp(mime_top_types_str[i].str, mime->type_str, strlen(mime_top_types_str[i].str))) {
			mime->top_type = mime_top_types_str[i].top_type;
			break;
		}
	}

	if (!sc) // No parameters
		return mime;

	// Parse parameters
	char *p = sc + 1;
	unsigned int param_num;
	for (param_num = 0; p && param_num < MIME_MAX_PARAMETERS; param_num++) {

		// Trim left
		while (*p == ' ')
			p++;

		char *eq = strchr(p, '=');
		if (!eq) {
			// Parameter without value, abort parsing
			return mime;
		}

		char *param_name = strndup(p, eq - p);
		if (!param_name) {
			mime_cleanup(mime);
			pom_oom(eq - p);
			return NULL;
		}
		
		// Parse the value
		char *pv = eq + 1;
		char pv_end = ' ';
		if (*pv == '"') { // The parameters is enclosed between ""
			pv_end = '"';
			pv++;
		}

		char *param_value = NULL;
		char *next_p = strchr(pv, pv_end);
		if (!next_p) { // Last parameters
			param_value = strdup(pv);
		} else {
			param_value = strndup(pv, next_p - pv);
		}

		if (!param_value) {
			mime_cleanup(mime);
			pom_oom(strlen(pv));
			return NULL;
		}

		mime->params[param_num].name = param_name;
		mime->params[param_num].value = param_value;

		p = next_p;
	}
	

	return mime;
}

void mime_cleanup(struct mime *mime) {

	if (mime->type_str)
		free(mime->type_str);
	int i;
	for (i = 0; i < MIME_MAX_PARAMETERS && mime->params[i].name; i++) {
		if (mime->params[i].value)
			free(mime->params[i].value);
		free(mime->params[i].name);
	}

	free(mime);
}

char *mime_get_param(struct mime *mime, char *param_name) {

	int i;
	for (i = 0; i < MIME_MAX_PARAMETERS && mime->params[i].name; i++) {
		if (!strcmp(mime->params[i].name, param_name))
			return mime->params[i].value;
	}
	return NULL;
}



