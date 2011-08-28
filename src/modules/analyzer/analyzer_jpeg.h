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


#ifndef __ANALYZER_JPEG_H__
#define __ANALYZER_JPEG_H__

#include <pom-ng/analyzer.h>

#define ANALYZER_JPEG_PLOAD_TYPE "jpeg"

#define ANALYZER_JPEG_PLOAD_DATA_COUNT 2

enum analyzer_jpeg_pload_data {
	analyzer_jpeg_pload_width = 0,
	analyzer_jpeg_pload_height,
};

struct mod_reg_info* analyzer_jpeg_reg_info();
static int analyzer_jpeg_mod_register(struct mod_reg *mod);
static int analyzer_jpeg_mod_unregister();

static int analyzer_jpeg_init(struct analyzer *analyzer);
static int analyzer_jpeg_cleanup(struct analyzer *analyzer);
static int analyzer_jpeg_pload_process_full(struct analyzer *analyzer, struct analyzer_pload_buffer *pload);

#endif
