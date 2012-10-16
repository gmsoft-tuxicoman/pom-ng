/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2012 Guy Martin <gmsoft@tuxicoman.be>
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

#include "analyzer_http_post.h"
#include <pom-ng/ptype_string.h>
#include <pom-ng/decode.h>

int analyzer_http_post_init(struct analyzer *analyzer) {

	struct analyzer_pload_type *pload_type = analyzer_pload_type_get_by_name(ANALYZER_HTTP_POST_PLOAD_TYPE);

	if (!pload_type) {
		pomlog(POMLOG_ERR "Payload type " ANALYZER_HTTP_POST_PLOAD_TYPE " not found");
		return POM_ERR;
	}

	static struct analyzer_pload_reg pload_reg;
	memset(&pload_reg, 0, sizeof(struct analyzer_pload_reg));
	pload_reg.analyzer = analyzer;
	pload_reg.process = analyzer_http_post_pload_process_full;

	return analyzer_pload_register(pload_type, &pload_reg);
}


int analyzer_http_post_pload_process_full(struct analyzer *analyzer, struct analyzer_pload_buffer *pload) {

	if (!pload->rel_event) {
		pomlog(POMLOG_ERR "No related event for this payload. Ignoring");
		return POM_OK;
	}

	char *data = pload->buff;

	size_t len = pload->buff_pos;
	while (1) {
		// Find the next param
		char *eq = memchr(data, '=', len);
		char *amp = memchr(data, '&', len);

		if (!eq) {
			// Nothing more to parse
			break;
		}

		if (amp && amp < eq) {
			// Parameter without value, skip to next param
			len -= amp - data + 1;
			data = amp + 1;
			continue;
		}

		size_t name_len = eq - data;
		char *name = malloc(name_len + 1);
		if (!name) {
			pom_oom(name_len);
			return POM_ERR;
		}
		size_t name_size = decode_percent(name, data, name_len);
		*(name + name_size) = 0;

		data = eq + 1;

		size_t value_len = len - name_len - 1;
		if (amp)
			value_len = amp - data;

		char *value = malloc(value_len + 1);
		if (!value) {
			pom_oom(value_len);
			free(name);
			return POM_ERR;
		}

		size_t value_size = decode_percent(value, data, value_len);
		*(value + value_size) = 0;


		struct ptype *value_pt = data_item_add(pload->rel_event->data, pload->rel_event->reg->info->data_reg, analyzer_http_request_post_data, name);

		if (!value_pt) {
			free(name);
			free(value);
			return POM_ERR;
		}

		PTYPE_STRING_SETVAL_P(value_pt, value);

		// Do not free value and name

		if (!amp)
			break;
	
		data = amp + 1;
		len -= value_len + name_len + 2;
	}


	return POM_OK;
}


