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


#include "../../../config.h"
#include "analyzer_jpeg.h"
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>

#ifdef HAVE_LIBEXIF
#include <exif-data.h>
#endif

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
	reg_info.dependencies = "ptype_uint16";

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

	static struct data_item_reg pload_jpeg_data_items[ANALYZER_JPEG_PLOAD_DATA_COUNT] = { { 0 } };
	pload_jpeg_data_items[analyzer_jpeg_pload_width].name = "width";
	pload_jpeg_data_items[analyzer_jpeg_pload_width].value_type = ptype_get_type("uint16");
	pload_jpeg_data_items[analyzer_jpeg_pload_height].name = "height";
	pload_jpeg_data_items[analyzer_jpeg_pload_height].value_type = ptype_get_type("uint16");
	pload_jpeg_data_items[analyzer_jpeg_pload_exif].name = "exif";
	pload_jpeg_data_items[analyzer_jpeg_pload_exif].flags = ANALYZER_DATA_FLAG_LIST;

	static struct data_reg pload_jpeg_data = {
		.items = pload_jpeg_data_items,
		.data_count = ANALYZER_JPEG_PLOAD_DATA_COUNT
	};

	static struct analyzer_pload_reg pload_reg;
	memset(&pload_reg, 0, sizeof(struct analyzer_pload_reg));
	pload_reg.analyzer = analyzer;
	pload_reg.process = analyzer_jpeg_pload_process;
	pload_reg.cleanup = analyzer_jpeg_pload_cleanup;
	pload_reg.data_reg = &pload_jpeg_data;
	pload_reg.flags = ANALYZER_PLOAD_PROCESS_PARTIAL;

	return analyzer_pload_register(pload_type, &pload_reg);
}

#ifdef HAVE_LIBEXIF
static void analyzer_jpeg_exif_entry_process(ExifEntry *entry, void *pload) {

	ExifIfd ifd = exif_content_get_ifd(entry->parent);

	const char *tag_name = exif_tag_get_name_in_ifd(entry->tag, ifd);
	if (!tag_name) // Unknown tag
		return;

	struct ptype *value = NULL;
	// First parse ascii values
	if (entry->format == EXIF_FORMAT_ASCII) {
		char *str = malloc(entry->size);
		if (!str) {
			pom_oom(entry->size);
			return;
		}
		memcpy(str, entry->data, entry->size);
		// Make sure it's NULL terminated
		str[entry->size - 1] = 0;

		value = ptype_alloc("string");
		if (!value) {
			free(str);
			return;
		}
		PTYPE_STRING_SETVAL_P(value, str);
	} else if (entry->components == 1) {
		
		ExifByteOrder byte_order = exif_data_get_byte_order(entry->parent->parent);
		if (entry->format == EXIF_FORMAT_BYTE) {
			value = ptype_alloc("uint8");
			if (!value)
				return;
			PTYPE_UINT8_SETVAL(value, *entry->data);
		} else if (entry->format == EXIF_FORMAT_SHORT)	{
			value = ptype_alloc("uint16");
			if (!value)
				return;
			PTYPE_UINT16_SETVAL(value, exif_get_short(entry->data, byte_order));
		} else if (entry->format == EXIF_FORMAT_LONG) {
			value = ptype_alloc("uint32");
			if (!value)
				return;
			PTYPE_UINT32_SETVAL(value, exif_get_long(entry->data, byte_order));
		}

	}

	if (!value) {
		// Fallback for types not parsed by us yet
		// FIXME this is subject to the locale

		char buff[256];
		buff[sizeof(buff) - 1] = 0;
		exif_entry_get_value(entry, buff, sizeof(buff) - 1);

		value = ptype_alloc("string");
		if (!value)
			return;
		PTYPE_STRING_SETVAL(value, buff);

	}

	char *key = strdup(tag_name);
	if (!key) {
		pom_oom(strlen(tag_name) + 1);
		return;
	}

	struct analyzer_pload_buffer *p = pload;
	data_item_add_ptype(p->data, analyzer_jpeg_pload_exif, key, value);

}

static void analyzer_jpeg_exif_content_process(ExifContent *content, void *pload) {

	ExifIfd ifd = exif_content_get_ifd(content);

	// Don't parse IFD_1 which is the thumbnail IFD and the interop one which holds no interesting data
	if (ifd == EXIF_IFD_1 || ifd == EXIF_IFD_INTEROPERABILITY)
		return;

	exif_content_foreach_entry(content, analyzer_jpeg_exif_entry_process, pload);
}
#endif

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
		struct jpeg_error_mgr *jerr = malloc(sizeof(struct jpeg_error_mgr));
		if (!jerr) {
			free(priv);
			pom_oom(sizeof(struct jpeg_error_mgr));
			return POM_ERR;
		}
		memset(jerr, 0, sizeof(struct jpeg_error_mgr));
		priv->cinfo.err = jpeg_std_error(jerr);
		priv->cinfo.err->error_exit = analyzer_jpeg_lib_error_exit;

		// Allocate the decompressor
		jpeg_create_decompress(&priv->cinfo);

		priv->cinfo.client_data = pload;

#ifdef HAVE_LIBEXIF
		// Save APP1
		jpeg_save_markers(&priv->cinfo, JPEG_APP0 + 1, 0xFFFF);
#endif

		// Allocate the source
		
		struct jpeg_source_mgr *src = malloc(sizeof(struct jpeg_source_mgr));
		if (!src) {
			free(priv->cinfo.err);
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


	if (priv->jpeg_lib_pos >= pload->buff_pos)
		// Nothing more to process
		return POM_OK;

	int res = POM_OK;
	if (!setjmp(priv->jmp_buff)) {

		if (priv->jpeg_lib_pos) {
			// It's not garanteed that pload->buff points to the
			// same memory area after each call, so we reset it here
			priv->cinfo.src->next_input_byte = pload->buff + priv->jpeg_lib_pos;
		}

		if (jpeg_read_header(&priv->cinfo, TRUE) == JPEG_SUSPENDED)
			return POM_OK; // Headers are incomplete

		PTYPE_UINT16_SETVAL(pload->data[analyzer_jpeg_pload_width].value, priv->cinfo.image_width);
		data_set(pload->data[analyzer_jpeg_pload_width]);
		PTYPE_UINT16_SETVAL(pload->data[analyzer_jpeg_pload_height].value, priv->cinfo.image_height);
		data_set(pload->data[analyzer_jpeg_pload_height]);
		debug_jpeg("JPEG read header returned %u, image is %ux%u", res, priv->cinfo.image_width, priv->cinfo.image_height);

#ifdef HAVE_LIBEXIF		
		// Parse the exif data
		jpeg_saved_marker_ptr marker;
		for (marker = priv->cinfo.marker_list; marker && marker->marker != JPEG_APP0 + 1; marker = marker->next);

		if (marker) {
			ExifData *exif_data = exif_data_new_from_data(marker->data, marker->data_length);
			if (!exif_data) {
				pomlog(POMLOG_DEBUG "Unable to parse EXIF data");
			}

			exif_data_foreach_content(exif_data, analyzer_jpeg_exif_content_process, pload);

			exif_data_free(exif_data);
		}
#endif

		pload->state = analyzer_pload_buffer_state_analyzed;

	} else {
		pomlog(POMLOG_DEBUG "Error while parsing JPEG headers");
		res = POM_ERR;
	}

	free(priv->cinfo.err);
	free(priv->cinfo.src);
	jpeg_destroy_decompress(&priv->cinfo);
	free(priv);
	pload->analyzer_priv = NULL;

	return res;
}

static int analyzer_jpeg_pload_cleanup(struct analyzer *analyzer, struct analyzer_pload_buffer *pload) {

	struct analyzer_jpeg_pload_priv *priv = pload->analyzer_priv;

	if (!priv)
		return POM_OK;

	free(priv->cinfo.err);
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

	struct analyzer_pload_buffer *pload = cinfo->client_data;
	struct analyzer_jpeg_pload_priv *priv = pload->analyzer_priv;

	// Find out remaining bytes
	if ((size_t)num_bytes >= cinfo->src->bytes_in_buffer) {
		priv->jpeg_lib_pos += num_bytes - cinfo->src->bytes_in_buffer;
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
	
	struct analyzer_pload_buffer *pload = cinfo->client_data;
	struct analyzer_jpeg_pload_priv *priv = pload->analyzer_priv;

	longjmp(priv->jmp_buff, 1);
}
