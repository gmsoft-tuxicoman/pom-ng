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

#if 0
#define debug_jpeg(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_jpeg(x ...)
#endif

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

	return analyzer_register(&analyzer_jpeg);

}

static int analyzer_jpeg_mod_unregister() {

	return analyzer_unregister("jpeg");
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
	pload_reg.process = analyzer_jpeg_pload_process;
	pload_reg.cleanup = analyzer_jpeg_pload_cleanup;
	pload_reg.data = pload_jpeg_data;
	pload_reg.flags = ANALYZER_PLOAD_PROCESS_PARTIAL;


	return analyzer_pload_register(pload_type, &pload_reg);
}

static int analyzer_jpeg_pload_process(struct analyzer *analyzer, struct analyzer_pload_buffer *pload) {


	struct analyzer_jpeg_pload_priv *priv = pload->analyzer_priv;

	if (!priv) {
		priv = malloc(sizeof(struct analyzer_jpeg_pload_priv));
		if (!priv) {
			pom_oom(sizeof(struct analyzer_jpeg_pload_priv));
			return POM_ERR;
		}
		memset(priv, 0, sizeof(struct analyzer_jpeg_pload_priv));
		
		// Setup error handler
		struct jpeg_error_mgr jerr;
		priv->cinfo.err = jpeg_std_error(&jerr);
		priv->cinfo.err->error_exit = analyzer_jpeg_lib_error_exit;

		// Allocate the decompressor
		jpeg_create_decompress(&priv->cinfo);

		priv->cinfo.client_data = pload;

		// Allocate the source
		
		struct jpeg_source_mgr *src = malloc(sizeof(struct jpeg_source_mgr));
		if (!src) {
			pom_oom(sizeof(struct jpeg_source_mgr));
			jpeg_destroy_decompress(&priv->cinfo);
			free(priv);
			return POM_ERR;
		}
		memset(src, 0, sizeof(struct jpeg_source_mgr));

		src->init_source = analyzer_jpeg_lib_init_source;
		src->fill_input_buffer = analyzer_jpeg_lib_fill_input_buffer;
		src->skip_input_data = analyzer_jpeg_lib_skip_input_data;
		src->resync_to_restart = jpeg_resync_to_restart;
		src->term_source = analyzer_jpeg_lib_term_source;
		priv->cinfo.src = src;


		pload->analyzer_priv = priv;

	}

	if (priv->jpeg_lib_pos < pload->buff_pos) {

		int res = jpeg_read_header(&priv->cinfo, TRUE);

		if (res == JPEG_SUSPENDED) // Headers are incomplete
			return POM_OK;
		
		debug_jpeg("JPEG read header returned %u, image is %ux%u", res, priv->cinfo.image_width, priv->cinfo.image_height);

		free(priv->cinfo.src);
		jpeg_destroy_decompress(&priv->cinfo);
		free(priv);
		pload->analyzer_priv = NULL;

		pload->state = analyzer_pload_buffer_state_analyzed;

	}

	return POM_OK;
}

static int analyzer_jpeg_pload_cleanup(struct analyzer *analyzer, struct analyzer_pload_buffer *pload) {

	struct analyzer_jpeg_pload_priv *priv = pload->analyzer_priv;

	if (!priv)
		return POM_OK;

	free(priv->cinfo.src);
	jpeg_destroy_decompress(&priv->cinfo);
	free(priv);

	return POM_OK;
}


static void analyzer_jpeg_lib_init_source(j_decompress_ptr cinfo) {

	struct analyzer_pload_buffer *pload = cinfo->client_data;
	struct analyzer_jpeg_pload_priv *priv = pload->analyzer_priv;

	cinfo->src->next_input_byte = pload->buff;
	cinfo->src->bytes_in_buffer = pload->buff_pos;

	priv->jpeg_lib_pos = pload->buff_pos;

}

static void analyzer_jpeg_lib_skip_input_data(j_decompress_ptr cinfo, long num_bytes) {

	if (num_bytes <= 0)
		return;

	// Find out remaining bytes
	if (num_bytes >= cinfo->src->bytes_in_buffer) {
		cinfo->src->bytes_in_buffer = 0;
	} else {
		cinfo->src->next_input_byte += num_bytes;
		cinfo->src->bytes_in_buffer -= num_bytes;
	}

}

static boolean analyzer_jpeg_lib_fill_input_buffer(j_decompress_ptr cinfo) {

	struct analyzer_pload_buffer *pload = cinfo->client_data;
	struct analyzer_jpeg_pload_priv *priv = pload->analyzer_priv;

	// Remove whatever wasn't used

	if (priv->jpeg_lib_pos >= pload->buff_pos)
		return FALSE;

	cinfo->src->next_input_byte = pload->buff + priv->jpeg_lib_pos;
	cinfo->src->bytes_in_buffer = pload->buff_pos - priv->jpeg_lib_pos;

	priv->jpeg_lib_pos = pload->buff_pos;


	return TRUE;
}

static void analyzer_jpeg_lib_term_source(j_decompress_ptr cinfo) {

	// Never called according to documentation
	pomlog(POMLOG_WARN "analyzer_jpeg_lib_term_source() called while not supposed to !");
}

static void analyzer_jpeg_lib_error_exit(j_common_ptr cinfo) {
	pomlog(POMLOG_WARN "Fatal exit error from libjpeg");
}
