/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2015 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/mime.h>

struct mod_reg_info* analyzer_rfc822_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_rfc822_mod_register;
	reg_info.unregister_func = analyzer_rfc822_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_uint32";

	return &reg_info;
}

static int analyzer_rfc822_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_rfc822;
	memset(&analyzer_rfc822, 0, sizeof(struct analyzer_reg));
	analyzer_rfc822.name = "rfc822";
	analyzer_rfc822.mod = mod;
	analyzer_rfc822.init = analyzer_rfc822_init;
	analyzer_rfc822.cleanup = analyzer_rfc822_cleanup;

	return analyzer_register(&analyzer_rfc822);

}

static int analyzer_rfc822_mod_unregister() {

	return analyzer_unregister("rfc822");
}

static int analyzer_rfc822_init(struct analyzer *analyzer) {

	static struct data_item_reg pload_rfc822_data_items[ANALYZER_RFC822_PLOAD_DATA_COUNT] = { { 0 } };
	pload_rfc822_data_items[analyzer_rfc822_pload_headers].name = "headers";
	pload_rfc822_data_items[analyzer_rfc822_pload_headers].flags = DATA_REG_FLAG_LIST;
	pload_rfc822_data_items[analyzer_rfc822_pload_headers_len].name = "header_len";
	pload_rfc822_data_items[analyzer_rfc822_pload_headers_len].value_type = ptype_get_type("uint32");

	static struct data_reg pload_rfc822_data = {
		.items = pload_rfc822_data_items,
		.data_count = ANALYZER_RFC822_PLOAD_DATA_COUNT
	};

	static struct pload_analyzer pload_analyzer_reg = { 0 };
	pload_analyzer_reg.analyze = analyzer_rfc822_pload_analyze;
	pload_analyzer_reg.cleanup = analyzer_rfc822_pload_analyze_cleanup;
	pload_analyzer_reg.data_reg = &pload_rfc822_data;

	if (pload_set_analyzer(ANALYZER_RFC822_PLOAD_TYPE, &pload_analyzer_reg))
		return POM_ERR;

	if (pload_listen_start(analyzer, ANALYZER_RFC822_PLOAD_TYPE, NULL, analyzer_rfc822_pload_open, analyzer_rfc822_pload_write, analyzer_rfc822_pload_close) != POM_OK)
		return POM_ERR;
	

	return POM_OK;

}

static int analyzer_rfc822_cleanup(struct analyzer *analyzer) {

	return pload_listen_stop(analyzer, ANALYZER_RFC822_PLOAD_TYPE);
}

static int analyzer_rfc822_pload_analyze(struct pload *pload, struct pload_buffer *pb, void *priv) {


	size_t *pload_pos = pload_get_analyzer_priv(pload);
	if (!pload_pos) {
		pload_pos = malloc(sizeof(size_t));
		if (!pload_pos) {
			pom_oom(sizeof(size_t));
			return POM_ERR;
		}
		pload_set_analyzer_priv(pload, pload_pos);
	}
	*pload_pos = 0;

	// We are parsing the header
	
	char *hdr = pb->data + *pload_pos;
	size_t hdrlen = pb->data_len - *pload_pos;

	while (hdrlen) {
		// CR and LF are not supposed to appear independently
		// Yet, we search for LF and strip CR if any
		char *crlf = memchr(hdr, '\n', hdrlen);
		size_t line_len = crlf - hdr;
		char *line = hdr;
		if (crlf != pb->data && *(crlf - 1) == '\r')
			line_len--;
		crlf++;
		hdrlen -= crlf - hdr;
		hdr = crlf;

		*pload_pos = (void*)crlf - pb->data;

		struct data *data = pload_get_data(pload);
		if (!line_len) {
			// Last line of headers, the body is now
			PTYPE_UINT32_SETVAL(data[analyzer_rfc822_pload_headers_len].value, *pload_pos);
			data_set(data[analyzer_rfc822_pload_headers_len]);
			return PLOAD_ANALYSIS_OK;
		} else if (mime_header_parse(&data[analyzer_rfc822_pload_headers], line, line_len) != POM_OK) {
			return POM_ERR;
		}
	}

	return PLOAD_ANALYSIS_MORE;
}

static int analyzer_rfc822_pload_analyze_cleanup(struct pload *p, void *priv) {
	if (priv)
		free(priv);
	return POM_OK;
}


static int analyzer_rfc822_pload_open(void *obj, void **priv, struct pload *pload) {

	// We should only receive rfc822 payloads here
	
	struct data *data = pload_get_data(pload);

	if (!data_is_set(data[analyzer_rfc822_pload_headers_len]))
		return PLOAD_OPEN_STOP;

	struct analyzer_rfc822_pload_priv *p = malloc(sizeof(struct analyzer_rfc822_pload_priv));
	if (!p) {
		pom_oom(sizeof(struct analyzer_rfc822_pload_priv));
		return PLOAD_OPEN_ERR;
	}
	memset(p, 0, sizeof(struct analyzer_rfc822_pload_priv));

	p->pload_pos = *PTYPE_UINT32_GETVAL(data[analyzer_rfc822_pload_headers_len].value);
	p->pload = pload;

	*priv = p;

	return PLOAD_OPEN_CONTINUE;
}

static int analyzer_rfc822_pload_write(void *obj, void *priv, void *data, size_t len) {

	
	struct analyzer_rfc822_pload_priv *p = priv;

	if (p->state == analyzer_rfc822_pload_state_initial) {

		if (p->pload_pos > 0) {
			if (p->pload_pos > len) {
				p->pload_pos -= len;
				return POM_OK;
			}
			len -= p->pload_pos;
			data += p->pload_pos;
			p->pload_pos = 0;
			if (!len)
				return POM_OK;
		}

		struct event *rel_evt = pload_get_related_event(p->pload);
		p->sub_pload = pload_alloc(rel_evt, 0);
		if (!p->sub_pload) {
			p->state = analyzer_rfc822_pload_state_done;
			return POM_ERR;
		}

		pload_set_parent(p->sub_pload, p->pload);

		// Parse the headers
		unsigned int content_type_found = 0, content_encoding_found = 0;
		struct data *pload_data = pload_get_data(p->pload);
		struct data_item *itm = pload_data[analyzer_rfc822_pload_headers].items;
		while (itm && (!content_type_found && !content_encoding_found)) {
			if (!strcasecmp(itm->key, "Content-Type")) {
				content_type_found = 1;
				pload_set_mime_type_str(p->sub_pload, PTYPE_STRING_GETVAL(itm->value));
			} else if (!strcasecmp(itm->key, "Content-Transfer-Encoding")) {
				content_encoding_found = 1;
				pload_set_encoding(p->sub_pload, PTYPE_STRING_GETVAL(itm->value));
			}

			itm = itm->next;
		}

		if (!content_type_found) // Set the default according to the RFC
			pload_set_mime_type_str(p->sub_pload, "text/plain; charset=US-ASCII");

		p->state = analyzer_rfc822_pload_state_processing;

	}
	
	if (p->state == analyzer_rfc822_pload_state_processing) {
		if (pload_append(p->sub_pload, data, len) != POM_OK) {
			p->state = analyzer_rfc822_pload_state_done;
			return POM_ERR;
		}
	}

	return POM_OK;
}

static int analyzer_rfc822_pload_close(void *obj, void *priv) {

	struct analyzer_rfc822_pload_priv *p = priv;
	if (!p)
		return POM_OK;

	if (p->sub_pload)
		pload_end(p->sub_pload);

	free(p);

	return POM_OK;
}

