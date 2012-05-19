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

#include "analyzer_png.h"
#include <pom-ng/ptype_uint16.h>

#include <arpa/inet.h>

#if 0
#define debug_png(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_png(x ...)
#endif

struct mod_reg_info* analyzer_png_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_png_mod_register;
	reg_info.unregister_func = analyzer_png_mod_unregister;

	return &reg_info;
}

static int analyzer_png_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_png;
	memset(&analyzer_png, 0, sizeof(struct analyzer_reg));
	analyzer_png.name = "png";
	analyzer_png.api_ver = ANALYZER_API_VER;
	analyzer_png.mod = mod;
	analyzer_png.init = analyzer_png_init;
	analyzer_png.cleanup = analyzer_png_cleanup;

	return analyzer_register(&analyzer_png);

}

static int analyzer_png_mod_unregister() {

	return analyzer_unregister("png");
}

static int analyzer_png_init(struct analyzer *analyzer) {

	struct analyzer_pload_type *pload_type = analyzer_pload_type_get_by_name(ANALYZER_PNG_PLOAD_TYPE);
	
	if (!pload_type) {
		pomlog(POMLOG_ERR "Payload type " ANALYZER_PNG_PLOAD_TYPE " not found");
		return POM_ERR;
	}

	struct analyzer_png_priv *priv = malloc(sizeof(struct analyzer_png_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_png_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_png_priv));

	priv->ptype_uint16 = ptype_alloc("uint16");
	if (!priv->ptype_uint16) {
		free(priv);
		return POM_ERR;
	}

	analyzer->priv = priv;

	static struct data_item_reg pload_png_data_items[ANALYZER_PNG_PLOAD_DATA_COUNT] = { { 0 } };
	pload_png_data_items[analyzer_png_pload_width].name = "width";
	pload_png_data_items[analyzer_png_pload_width].value_template = priv->ptype_uint16;
	pload_png_data_items[analyzer_png_pload_height].name = "height";
	pload_png_data_items[analyzer_png_pload_height].value_template = priv->ptype_uint16;

	static struct data_reg pload_png_data = {
		.items = pload_png_data_items,
		.data_count = ANALYZER_PNG_PLOAD_DATA_COUNT
	};

	static struct analyzer_pload_reg pload_reg;
	memset(&pload_reg, 0, sizeof(struct analyzer_pload_reg));
	pload_reg.analyzer = analyzer;
	pload_reg.process = analyzer_png_pload_process;
	pload_reg.data_reg = &pload_png_data;
	pload_reg.flags = ANALYZER_PLOAD_PROCESS_PARTIAL;

	return analyzer_pload_register(pload_type, &pload_reg);
}

int analyzer_png_cleanup(struct analyzer *analyzer) {

	struct analyzer_png_priv *priv = analyzer->priv;
	ptype_cleanup(priv->ptype_uint16);
	free(priv);

	return POM_OK;
}

static int analyzer_png_pload_process(struct analyzer *analyzer, struct analyzer_pload_buffer *pload) {

	if (pload->buff_pos < ANALYZER_PNG_HEADER_MIN_SIZE)
		return POM_OK;

	if (!memcmp(pload->buff, ANALYZER_PNG_SIGNATURE, strlen(ANALYZER_PNG_SIGNATURE))) {
		// We got a PNG file
		if (!memcmp(pload->buff + 12, ANALYZER_PNG_HEADER_NAME, strlen(ANALYZER_PNG_HEADER_NAME))) {
			// We got the right header
			uint16_t height, width;
			width = ntohl(*(unsigned int*)(pload->buff + 16));
			height = ntohl(*(unsigned int*)(pload->buff + 20));

			pload->state = analyzer_pload_buffer_state_analyzed;
	
			PTYPE_UINT16_SETVAL(pload->data[analyzer_png_pload_width].value, width);
			PTYPE_UINT16_SETVAL(pload->data[analyzer_png_pload_height].value, height);
			debug_png("Got PNG of %ux%u", width, height);

		} else {
			pomlog(POMLOG_DEBUG "IHDR not found where it was supposed to be");
			pload->type = NULL;
		}

	} else {
		pomlog(POMLOG_DEBUG "PNG signature not found");
		pload->type = NULL;
	}

	return POM_OK;
}


