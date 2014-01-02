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

#include "analyzer_gif.h"

#include <pom-ng/ptype_uint16.h>

#if 0
#define debug_gif(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_gif(x ...)
#endif

struct mod_reg_info* analyzer_gif_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_gif_mod_register;
	reg_info.unregister_func = analyzer_gif_mod_unregister;
	reg_info.dependencies = "ptype_uint16";

	return &reg_info;
}

static int analyzer_gif_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_gif;
	memset(&analyzer_gif, 0, sizeof(struct analyzer_reg));
	analyzer_gif.name = "gif";
	analyzer_gif.mod = mod;
	analyzer_gif.init = analyzer_gif_init;

	return analyzer_register(&analyzer_gif);

}

static int analyzer_gif_mod_unregister() {

	return analyzer_unregister("gif");
}

static int analyzer_gif_init(struct analyzer *analyzer) {

	struct analyzer_pload_type *pload_type = analyzer_pload_type_get_by_name(ANALYZER_GIF_PLOAD_TYPE);
	
	if (!pload_type) {
		pomlog(POMLOG_ERR "Payload type " ANALYZER_GIF_PLOAD_TYPE " not found");
		return POM_ERR;
	}

	static struct data_item_reg pload_gif_data_items[ANALYZER_GIF_PLOAD_DATA_COUNT] = { { 0 } };
	pload_gif_data_items[analyzer_gif_pload_width].name = "width";
	pload_gif_data_items[analyzer_gif_pload_width].value_type = ptype_get_type("uint16");
	pload_gif_data_items[analyzer_gif_pload_height].name = "height";
	pload_gif_data_items[analyzer_gif_pload_height].value_type = ptype_get_type("uint16");

	static struct data_reg pload_gif_data = {
		.items = pload_gif_data_items,
		.data_count = ANALYZER_GIF_PLOAD_DATA_COUNT
	};

	static struct analyzer_pload_reg pload_reg;
	memset(&pload_reg, 0, sizeof(struct analyzer_pload_reg));
	pload_reg.analyzer = analyzer;
	pload_reg.analyze = analyzer_gif_pload_analyze;
	pload_reg.data_reg = &pload_gif_data;
	pload_reg.flags = ANALYZER_PLOAD_PROCESS_PARTIAL;


	return analyzer_pload_register(pload_type, &pload_reg);
}

static int analyzer_gif_pload_analyze(struct analyzer *analyzer, struct analyzer_pload_buffer *pload, void *buffer, size_t buff_len) {

	if (buff_len < ANALYZER_GIF_HEADER_MIN_SIZE)
		return POM_OK;

	unsigned char *buff = buffer;

	if (!memcmp(buff, ANALYZER_GIF_VERSION_87A, strlen(ANALYZER_GIF_VERSION_87A)) || !memcmp(buff, ANALYZER_GIF_VERSION_89A, strlen(ANALYZER_GIF_VERSION_89A))) {
		// We got a GIF file
		uint16_t height, width;
		width = (buff[7] << 8) + buff[8];
		height = (buff[9] << 8) + buff[10];

		analyzer_pload_buffer_set_state(pload, analyzer_pload_buffer_state_analyzed);

		struct data *pload_data = analyzer_pload_buffer_get_data(pload);

		PTYPE_UINT16_SETVAL(pload_data[analyzer_gif_pload_width].value, width);
		data_set(pload_data[analyzer_gif_pload_width]);
		PTYPE_UINT16_SETVAL(pload_data[analyzer_gif_pload_height].value, height);
		data_set(pload_data[analyzer_gif_pload_height]);

		debug_gif("Got GIF image of %ux%u", width, height);

	} else {
		pomlog(POMLOG_DEBUG "GIF signature not found");
		analyzer_pload_buffer_set_state(pload, analyzer_pload_buffer_state_analysis_failed);
	}

	return POM_OK;
}

