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

#include "analyzer_rfc822.h"

#include <pom-ng/ptype_string.h>
#include <pom-ng/mime.h>

struct mod_reg_info* analyzer_rfc822_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_rfc822_mod_register;
	reg_info.unregister_func = analyzer_rfc822_mod_unregister;
	reg_info.dependencies = "ptype_string";

	return &reg_info;
}

static int analyzer_rfc822_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_rfc822;
	memset(&analyzer_rfc822, 0, sizeof(struct analyzer_reg));
	analyzer_rfc822.name = "rfc822";
	analyzer_rfc822.api_ver = ANALYZER_API_VER;
	analyzer_rfc822.mod = mod;
	analyzer_rfc822.init = analyzer_rfc822_init;

	return analyzer_register(&analyzer_rfc822);

}

static int analyzer_rfc822_mod_unregister() {

	return analyzer_unregister("rfc822");
}

static int analyzer_rfc822_init(struct analyzer *analyzer) {

	struct analyzer_pload_type *pload_type = analyzer_pload_type_get_by_name(ANALYZER_RFC822_PLOAD_TYPE);
	
	if (!pload_type) {
		pomlog(POMLOG_ERR "Payload type " ANALYZER_RFC822_PLOAD_TYPE " not found");
		return POM_ERR;
	}

	static struct data_item_reg pload_rfc822_data_items[ANALYZER_RFC822_PLOAD_DATA_COUNT] = { { 0 } };
	pload_rfc822_data_items[analyzer_rfc822_pload_headers].name = "headers";
	pload_rfc822_data_items[analyzer_rfc822_pload_headers].flags = DATA_REG_FLAG_LIST;

	static struct data_reg pload_rfc822_data = {
		.items = pload_rfc822_data_items,
		.data_count = ANALYZER_RFC822_PLOAD_DATA_COUNT
	};

	static struct analyzer_pload_reg pload_reg;
	memset(&pload_reg, 0, sizeof(struct analyzer_pload_reg));
	pload_reg.analyzer = analyzer;
	pload_reg.analyze = analyzer_rfc822_pload_analyze;
	pload_reg.process = analyzer_rfc822_pload_process;
	pload_reg.cleanup = analyzer_rfc822_pload_cleanup;
	pload_reg.data_reg = &pload_rfc822_data;
	pload_reg.flags = ANALYZER_PLOAD_PROCESS_PARTIAL;


	if (analyzer_pload_register(pload_type, &pload_reg) != POM_OK)
		return POM_ERR;

	return POM_OK;

}

static int analyzer_rfc822_pload_analyze(struct analyzer *analyzer, struct analyzer_pload_buffer *pload, void *buff, size_t buff_len) {


	struct analyzer_rfc822_pload_priv *priv = analyzer_pload_buffer_get_priv(pload);

	if (!priv) {
		priv = malloc(sizeof(struct analyzer_rfc822_pload_priv));
		if (!priv) {
			pom_oom(sizeof(struct analyzer_rfc822_pload_priv));
			return POM_ERR;
		}
		memset(priv, 0, sizeof(struct analyzer_rfc822_pload_priv));
		analyzer_pload_buffer_set_priv(pload, priv);
	}

	// We are parsing the header
	
	char *hdr = buff + priv->pload_pos;
	size_t hdrlen = buff_len - priv->pload_pos;

	while (hdrlen) {
		// CR and LF are not supposed to appear independently
		// Yet, we search for LF and strip CR if any
		char *crlf = memchr(hdr, '\n', hdrlen);
		size_t line_len = crlf - hdr;
		char *line = hdr;
		if (crlf != buff && *(crlf - 1) == '\r')
			line_len--;
		crlf++;
		hdrlen -= crlf - hdr;
		hdr = crlf;

		struct data *data = analyzer_pload_buffer_get_data(pload);
		if (!line_len) {
			// Last line of headers, the body is now
			analyzer_pload_buffer_set_state(pload, analyzer_pload_buffer_state_analyzed);
			break;
		} else if (mime_parse_header(&data[analyzer_rfc822_pload_headers], line, line_len) != POM_OK) {
			return POM_ERR;
		}


		priv->pload_pos = (void*)crlf - buff;
	}

	return POM_OK;
}

static int analyzer_rfc822_pload_process(struct analyzer *analyzer, struct analyzer_pload_buffer *pload, void *data, size_t len) {

	
	struct analyzer_rfc822_pload_priv *priv = analyzer_pload_buffer_get_priv(pload);

	if (priv->state == analyzer_rfc822_pload_state_initial) {

		if (priv->pload_pos > 0) {
			if (priv->pload_pos > len) {
				priv->pload_pos -= len;
				return POM_OK;
			}
			len -= priv->pload_pos;
			data += priv->pload_pos;
			priv->pload_pos = 0;
			if (!len)
				return POM_OK;
		}

		priv->sub_pload = analyzer_pload_buffer_alloc(0, 0);
		if (!priv->sub_pload) {
			priv->state = analyzer_rfc822_pload_state_done;
			return POM_ERR;
		}

		// Parse the headers
		unsigned int content_type_found = 0, content_encoding_found = 0;
		struct data *data = analyzer_pload_buffer_get_data(pload);
		struct data_item *itm = data[analyzer_rfc822_pload_headers].items;
		while (itm && (!content_type_found && !content_encoding_found)) {
			if (!strcasecmp(itm->key, "Content-Type")) {
				content_type_found = 1;
				analyzer_pload_buffer_set_type_by_content_type(priv->sub_pload, PTYPE_STRING_GETVAL(itm->value));
			} else if (!strcasecmp(itm->key, "Content-Transfer-Encoding")) {
				pomlog(POMLOG_DEBUG "Transfer encoding is %s", PTYPE_STRING_GETVAL(itm->value));
			}

			itm = itm->next;
		}

		if (!content_type_found)
			analyzer_pload_buffer_set_type_by_content_type(priv->sub_pload, "text/plain; charset=US-ASCII");
		if (!content_encoding_found)
			pomlog(POMLOG_DEBUG "Transfer encoding is %s", "7bit");

		analyzer_pload_buffer_set_related_event(priv->sub_pload, analyzer_pload_buffer_get_related_event(pload));
		priv->state = analyzer_rfc822_pload_state_processing;

	}
	
	if (priv->state == analyzer_rfc822_pload_state_processing) {
		if (analyzer_pload_buffer_append(priv->sub_pload, data, len) != POM_OK) {
			priv->state = analyzer_rfc822_pload_state_done;
			return POM_ERR;
		}
	}

	return POM_OK;
}

static int analyzer_rfc822_pload_cleanup(struct analyzer *analyzer, struct analyzer_pload_buffer *pload) {

	struct analyzer_rfc822_pload_priv *priv = analyzer_pload_buffer_get_priv(pload);
	if (!priv)
		return POM_OK;

	if (priv->sub_pload)
		analyzer_pload_buffer_cleanup(priv->sub_pload);

	free(priv);

	return POM_OK;
}

