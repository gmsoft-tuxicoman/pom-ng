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


#ifndef __ANALYZER_JPEG_H__
#define __ANALYZER_JPEG_H__

#include <pom-ng/analyzer.h>
#include <stdio.h>
#include <jpeglib.h>
#include <setjmp.h>

#define ANALYZER_JPEG_PLOAD_TYPE "jpeg"

#define ANALYZER_JPEG_PLOAD_DATA_COUNT 3

enum analyzer_jpeg_pload_data {
	analyzer_jpeg_pload_width = 0,
	analyzer_jpeg_pload_height,
	analyzer_jpeg_pload_exif
};

struct analyzer_jpeg_pload_priv {

	struct jpeg_decompress_struct cinfo;
	unsigned long jpeg_lib_pos;

	jmp_buf jmp_buff;

	void *pload_buff;
	size_t pload_buff_len;
};

struct mod_reg_info* analyzer_jpeg_reg_info();
static int analyzer_jpeg_mod_register(struct mod_reg *mod);
static int analyzer_jpeg_mod_unregister();

static int analyzer_jpeg_init(struct analyzer *analyzer);
static int analyzer_jpeg_pload_analyze(struct analyzer *analyzer, struct analyzer_pload_buffer *pload, void *buffer, size_t buff_len);
static int analyzer_jpeg_pload_cleanup(struct analyzer *analyzer, struct analyzer_pload_buffer *pload);

static void analyzer_jpeg_lib_init_source(j_decompress_ptr cinfo);
static void analyzer_jpeg_lib_skip_input_data(j_decompress_ptr cinfo, long num_bytes);
static boolean analyzer_jpeg_lib_fill_input_buffer(j_decompress_ptr cinfo);
static void analyzer_jpeg_lib_term_source(j_decompress_ptr cinfo);
static void analyzer_jpeg_lib_error_exit(j_common_ptr cinfo);
static void analyzer_jpeg_lib_output_message(j_common_ptr cinfo);

#endif
