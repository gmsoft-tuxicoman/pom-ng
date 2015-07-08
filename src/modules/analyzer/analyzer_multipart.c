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

#include "analyzer_multipart.h"

#include <pom-ng/ptype_string.h>
#include <pom-ng/mime.h>

struct mod_reg_info* analyzer_multipart_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_multipart_mod_register;
	reg_info.unregister_func = analyzer_multipart_mod_unregister;
	reg_info.dependencies = "ptype_string";

	return &reg_info;
}

static int analyzer_multipart_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_multipart;
	memset(&analyzer_multipart, 0, sizeof(struct analyzer_reg));
	analyzer_multipart.name = "multipart";
	analyzer_multipart.mod = mod;
	analyzer_multipart.init = analyzer_multipart_init;
	analyzer_multipart.cleanup = analyzer_multipart_cleanup;

	return analyzer_register(&analyzer_multipart);

}

static int analyzer_multipart_mod_unregister() {

	return analyzer_unregister("multipart");
}

static int analyzer_multipart_init(struct analyzer *analyzer) {

	return pload_listen_start(analyzer, ANALYZER_MULTIPART_PLOAD_TYPE, NULL, analyzer_multipart_pload_open, analyzer_multipart_pload_write, analyzer_multipart_pload_close);
}

static int analyzer_multipart_cleanup(struct analyzer *analyzer) {
	
	return pload_listen_stop(analyzer, ANALYZER_MULTIPART_PLOAD_TYPE);
}

static int analyzer_multipart_pload_open(void *obj, void **priv, struct pload *pload) {

	struct mime_type *mime_type = pload_get_mime_type(pload);
	if (!mime_type) {
		free(priv);
		return PLOAD_OPEN_STOP;
	}

	char *boundary = mime_type_get_param(mime_type, "boundary");
	if (!boundary) {
		pomlog(POMLOG_DEBUG "Multipart boundary not found in mime type informations !");
		free(priv);
		return PLOAD_OPEN_STOP;
	}

	struct analyzer_multipart_pload_priv *p = malloc(sizeof(struct analyzer_multipart_pload_priv));
	if (!p) {
		pom_oom(sizeof(struct analyzer_multipart_pload_priv));
		return PLOAD_OPEN_ERR;
	}
	memset(p, 0, sizeof(struct analyzer_multipart_pload_priv));

	p->boundary = malloc(strlen(boundary) + 3);
	if (!p->boundary) {
		free(p);
		pom_oom(strlen(boundary) + 3);
		return PLOAD_OPEN_ERR;
	}

	p->boundary[0] = '-';
	p->boundary[1] = '-';
	strcpy(p->boundary + 2, boundary);
		
	p->boundary_len = strlen(p->boundary);
	p->parent_pload = pload;

	*priv = p;

	return PLOAD_OPEN_CONTINUE;
}

static int analyzer_multipart_pload_process_line(struct analyzer_multipart_pload_priv *priv, char *line, size_t len) {

	char *my_line = line;
	size_t my_len = len;
	while (my_len > 0 && (*my_line == '\r' || *my_line == '\n')) {
		my_line++;
		my_len--;
	}

	if (my_len >= priv->boundary_len && !memcmp(my_line, priv->boundary, priv->boundary_len)) {
		// Process the rest of the payload

		if (priv->pload) {
			if (priv->pload_start && pload_append(priv->pload, priv->pload_start, priv->pload_end - priv->pload_start) != POM_OK)
				return POM_ERR;

			pload_end(priv->pload);
			priv->pload = NULL;
		}
		priv->pload_start = NULL;
		priv->pload_end = NULL;

		if (my_len >= priv->boundary_len + 2 && my_line[priv->boundary_len] == '-' && my_line[priv->boundary_len + 1] == '-')
			priv->state = analyzer_multipart_pload_state_end;
		else
			priv->state = analyzer_multipart_pload_state_header;
	
		return POM_OK;
	} else if (priv->state == analyzer_multipart_pload_state_header) {

		if (!my_len) {
			// End of the headers
			priv->state = analyzer_multipart_pload_state_content;
			return POM_OK;
		}

		if (mime_header_parse(&priv->pload_data, my_line, my_len) != POM_OK) {
			priv->state = analyzer_multipart_pload_state_error;
			return POM_OK;
		}


	} else if (priv->state == analyzer_multipart_pload_state_content) {

		if (!priv->pload) {
			struct event *rel_event = pload_get_related_event(priv->parent_pload);
			priv->pload = pload_alloc(rel_event, 0);
			if (!priv->pload)
				return POM_ERR;
			
			pload_set_parent(priv->pload, priv->parent_pload);

			// Parse the headers
			while (priv->pload_data.items) {
				struct data_item *itm = priv->pload_data.items;
				priv->pload_data.items = itm->next;

				if (!strcasecmp(itm->key, "Content-Type")) {
					pload_set_mime_type(priv->pload, PTYPE_STRING_GETVAL(itm->value));
				} else if (!strcasecmp(itm->key, "Content-Transfer-Encoding")) {
					pload_set_encoding(priv->pload, PTYPE_STRING_GETVAL(itm->value));
				}
				free(itm->key);
				ptype_cleanup(itm->value);
				free(itm);
			}

			// If it's the begining, discard CRLF
			line = my_line;
			len = my_len;
		}

		if (priv->pload_end != line) {
			// Process the payload we had and queue the this one
			if (priv->pload_start && pload_append(priv->pload, priv->pload_start, priv->pload_end - priv->pload_start) != POM_OK)
				return POM_ERR;
			priv->pload_start = line;
			priv->pload_end = line + len;
		} else {
			priv->pload_end += len;
		}
	}

	return POM_OK;
}

static int analyzer_multipart_pload_write(void *obj, void *p, void *data, size_t len) {

	struct analyzer_multipart_pload_priv *priv = p;

	if (priv->state == analyzer_multipart_pload_state_end)
		return POM_OK;

	if (priv->state == analyzer_multipart_pload_state_error)
		return POM_ERR;

	unsigned int line_len, remaining_len = len;

	while (remaining_len > 0) {
	
		// Because of the NOTE in RFC 2046 section 5.1.1, line start at CR 

		void *cr = memchr(data + 1, '\r', remaining_len - 1);
		if (!cr || priv->last_line) {

			size_t add_len = remaining_len;
			if (cr)
				add_len = cr - data;

			size_t new_len = add_len + 1;
			if (priv->last_line)
				new_len += strlen(priv->last_line);
			if (!priv->last_line || priv->last_line_len < new_len) {
				char *new_last_line = realloc(priv->last_line, new_len);
				if (!new_last_line) {
					pom_oom(new_len);
					goto err;
				}
				if (!priv->last_line_len)
					new_last_line[0] = 0;
				priv->last_line_len = new_len;
				priv->last_line = new_last_line;
			}
			strncat(priv->last_line, data, add_len);
			priv->last_line[new_len - 1] = 0;

			if (!cr)
				break;

			// Process this line and continue to the next
			if (analyzer_multipart_pload_process_line(priv, priv->last_line, strlen(priv->last_line)) != POM_OK)
				goto err;

			// We need to process this part of the payload
			if (priv->state == analyzer_multipart_pload_state_content && priv->pload_start) {
				if (pload_append(priv->pload, priv->pload_start, priv->pload_end - priv->pload_start) != POM_OK)
					goto err;
			}

			priv->pload_start = NULL;
			priv->pload_end = NULL;
			
			free(priv->last_line);
			priv->last_line = NULL;
			priv->last_line_len = 0;
			data = cr;
			remaining_len -= add_len;
			
			continue;
		}

		line_len = cr - data;
		
		if (analyzer_multipart_pload_process_line(priv, data, line_len) != POM_OK)
			goto err;

		remaining_len -= line_len;
		data = cr;
	}

	if (priv->state == analyzer_multipart_pload_state_content && priv->pload_start) {
		if (pload_append(priv->pload, priv->pload_start, priv->pload_end - priv->pload_start) != POM_OK)
			goto err;
	}

	priv->pload_start = NULL;
	priv->pload_end = NULL;

	return POM_OK;

err:
	if (priv->pload) {
		pload_end(priv->pload);
		priv->pload = NULL;
	}

	priv->state = analyzer_multipart_pload_state_error;
	return POM_ERR;
}

static int analyzer_multipart_pload_close(void *obj, void *p) {


	struct analyzer_multipart_pload_priv *priv = p;

	if (!priv)
		return POM_OK;

	if (priv->boundary)
		free(priv->boundary);

	if (priv->pload)
		pload_end(priv->pload);

	if (priv->last_line)
		free(priv->last_line);


	while (priv->pload_data.items) {
		struct data_item *itm = priv->pload_data.items;
		priv->pload_data.items = itm->next;

		if (itm->key)
			free(itm->key);
		if (itm->value)
			ptype_cleanup(itm->value);

		free(itm);
	}

	free(priv);

	return POM_OK;
}
