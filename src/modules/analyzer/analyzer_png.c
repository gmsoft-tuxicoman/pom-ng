/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#include <arpa/inet.h>

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


	static struct analyzer_data_reg pload_png_data[ANALYZER_PNG_PLOAD_DATA_COUNT + 1];
	memset(&pload_png_data, 0, sizeof(struct analyzer_data_reg) * (ANALYZER_PNG_PLOAD_DATA_COUNT + 1));
	pload_png_data[analyzer_png_pload_width].name = "width";
	pload_png_data[analyzer_png_pload_height].name = "height";

	static struct analyzer_pload_reg pload_reg;
	memset(&pload_reg, 0, sizeof(struct analyzer_pload_reg));
	pload_reg.analyzer = analyzer;
	pload_reg.process = analyzer_png_pload_process;
	pload_reg.data = pload_png_data;
	pload_reg.flags = ANALYZER_PLOAD_PROCESS_PARTIAL;


	return analyzer_pload_register(pload_type, &pload_reg);
}

static int analyzer_png_pload_process(struct analyzer *analyzer, struct analyzer_pload_buffer *pload) {

	if (pload->analyzer_priv) // We've already processed the header
		return POM_OK;

	if (pload->buff_pos < ANALYZER_PNG_HEADER_MIN_SIZE)
		return POM_OK;

	pload->analyzer_priv = (void*)1;

	if (!memcmp(pload->buff, ANALYZER_PNG_SIGNATURE, strlen(ANALYZER_PNG_SIGNATURE))) {
		// We got a PNG file
		if (!memcmp(pload->buff + 12, ANALYZER_PNG_HEADER_NAME, strlen(ANALYZER_PNG_HEADER_NAME))) {
			// We got the right header
			uint16_t height, width;
			width = ntohl(*(unsigned int*)(pload->buff + 16));
			height = ntohl(*(unsigned int*)(pload->buff + 20));
		
			pomlog(POMLOG_DEBUG "Got PNG image with height %u and width %u", height, width);

		} else {
			pomlog(POMLOG_DEBUG "IHDR not found where it was supposed to be");
		}

	}

	return POM_OK;
}


