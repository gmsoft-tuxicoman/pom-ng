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

#include "analyzer_jpeg.h"

#include <stdio.h>
#include <jpeglib.h>

struct mod_reg_info* analyzer_jpeg_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_jpeg_mod_register;
	reg_info.unregister_func = analyzer_jpeg_mod_unregister;

	return &reg_info;
}

static int analyzer_jpeg_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_jpeg;
	memset(&analyzer_jpeg, 0, sizeof(struct analyzer_reg));
	analyzer_jpeg.name = "jpeg";
	analyzer_jpeg.api_ver = ANALYZER_API_VER;
	analyzer_jpeg.mod = mod;
	analyzer_jpeg.init = analyzer_jpeg_init;
	analyzer_jpeg.cleanup = analyzer_jpeg_cleanup;

	return analyzer_register(&analyzer_jpeg);

}

static int analyzer_jpeg_mod_unregister() {

	return analyzer_unregister("http");
}

static int analyzer_jpeg_init(struct analyzer *analyzer) {

	struct analyzer_pload_type *pload_type = analyzer_pload_type_get_by_name(ANALYZER_JPEG_PLOAD_TYPE);
	
	if (!pload_type) {
		pomlog(POMLOG_ERR "Payload type " ANALYZER_JPEG_PLOAD_TYPE " not found");
		return POM_ERR;
	}


	static struct analyzer_data_reg pload_jpeg_data[ANALYZER_JPEG_PLOAD_DATA_COUNT + 1];
	memset(&pload_jpeg_data, 0, sizeof(struct analyzer_data_reg) * (ANALYZER_JPEG_PLOAD_DATA_COUNT + 1));
	pload_jpeg_data[analyzer_jpeg_pload_width].name = "width";
	pload_jpeg_data[analyzer_jpeg_pload_height].name = "height";

	static struct analyzer_pload_reg pload_reg;
	memset(&pload_reg, 0, sizeof(struct analyzer_pload_reg));
	pload_reg.analyzer = analyzer;
	pload_reg.process = analyzer_jpeg_pload_process_full;
	pload_reg.data = pload_jpeg_data;


	return analyzer_pload_register(pload_type, &pload_reg);
}


static int analyzer_jpeg_cleanup(struct analyzer *analyzer) {


	return POM_OK;
}


static int analyzer_jpeg_pload_process_full(struct analyzer *analyzer, struct analyzer_pload_buffer *pload) {


	unsigned char *data = pload->buff;
	unsigned long len = pload->buff_pos;


	struct jpeg_decompress_struct cinfo;

	struct jpeg_error_mgr jerr;
	cinfo.err = jpeg_std_error(&jerr);

	jpeg_create_decompress(&cinfo);

	jpeg_mem_src(&cinfo, data, len);

	int res = jpeg_read_header(&cinfo, FALSE);

	pomlog("JPEG read header returned %u, image is %ux%u", res, cinfo.image_width, cinfo.image_height);

	jpeg_destroy_decompress(&cinfo);


	return POM_OK;
}
