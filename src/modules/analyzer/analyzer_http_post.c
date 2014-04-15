/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2014 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/decoder.h>

int analyzer_http_post_init(struct analyzer *analyzer) {

	return pload_listen_start(analyzer, ANALYZER_HTTP_POST_PLOAD_TYPE, NULL, analyzer_http_post_pload_open, analyzer_http_post_pload_write, analyzer_http_post_pload_close);
}

int analyzer_http_post_cleanup(struct analyzer *analyzer) {
	
	return pload_listen_stop(analyzer, ANALYZER_HTTP_POST_PLOAD_TYPE);
}


int analyzer_http_post_pload_open(void *obj, void **priv, struct pload *pload) {

	struct event *evt = pload_get_related_event(pload);

	if (!evt)
		return PLOAD_OPEN_STOP;

	struct analyzer_http_post_pload_priv *p = malloc(sizeof(struct analyzer_http_post_pload_priv));
	if (!p) {
		pom_oom(sizeof(struct analyzer_http_post_pload_priv));
		return PLOAD_OPEN_ERR;
	}
	memset(p, 0, sizeof(struct analyzer_http_post_pload_priv));
	p->evt = evt;

	*priv = p;
	
	return PLOAD_OPEN_CONTINUE;
}

int analyzer_http_post_pload_write(void *obj, void *p, void *data, size_t len) {

	struct analyzer_http_post_pload_priv *priv = p;

	char *buff = data;
	size_t buff_len = len;

	if (priv->buff) {
		buff_len = strlen(priv->buff) + len;
		buff = realloc(priv->buff, buff_len  + 1);
		if (!buff) {
			free(priv->buff);
			priv->buff = NULL;
			return POM_ERR;
		}
		priv->buff = buff;
		strncat(buff, data, len);
		buff[buff_len] = 0; // Make sure it ends with a 0
	}


	while (buff_len) {
		// Find the next param
		char *eq = memchr(buff, '=', buff_len);
		char *amp = memchr(buff, '&', buff_len);

		if (!eq) {
			// Nothing more to parse
			break;
		}

		if (amp && amp < eq) {
			// Parameter without value, skip to next param
			buff_len -= amp - buff + 1;
			buff = amp + 1;
			continue;
		}

		size_t name_len = eq - buff;

		char *name = NULL;
		size_t name_size = 0;
		if (decoder_decode_simple("percent", buff, name_len, &name, &name_size) == DEC_ERR) {
			continue;
		}

		buff = eq + 1;

		size_t value_len = buff_len - name_len - 1;
		if (amp)
			value_len = amp - buff;

		char *value = NULL;
		size_t value_size = 0;
		if (decoder_decode_simple("percent", buff, value_len, &value, &value_size) == DEC_ERR) {
			free(name);
			continue;
		}

		struct ptype *value_pt = event_data_item_add(priv->evt, analyzer_http_request_post_data, name);

		if (!value_pt) {
			free(name);
			free(value);
			return POM_ERR;
		}

		PTYPE_STRING_SETVAL_P(value_pt, value);

		// Do not free value and name

		if (!amp)
			break;
	
		buff = amp + 1;
		buff_len -= value_len + name_len + 2;
	}

	if (buff_len) {
		if (!priv->buff) {
			priv->buff = malloc(buff_len + 1);
			if (!priv->buff) {
				pom_oom(buff_len + 1);
				return POM_ERR;
			}
		} // If priv->buff already exists, it's at least as big as the memory it holds
		memmove(priv->buff, buff, buff_len);
		
	} else {
		free(priv->buff);
		priv->buff = NULL;
	}

	return POM_OK;
}

int analyzer_http_post_pload_close(void *obj, void *p) {

	struct analyzer_http_post_pload_priv *priv = p;
	if (!priv)
		return POM_ERR;

	if (priv->buff) {
		pomlog(POMLOG_DEBUG "Some parts were not used in HTTP POST data.");
		free(priv->buff);
	}
	free(priv);

	return POM_OK;
}


