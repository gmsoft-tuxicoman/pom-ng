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


#ifndef __ANALYZER_PNG_H__
#define __ANALYZER_PNG_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/pload.h>

#define ANALYZER_PNG_PLOAD_TYPE "png"

#define ANALYZER_PNG_PLOAD_DATA_COUNT 2

#define ANALYZER_PNG_SIGNATURE "\x89PNG\r\n\x1a\n"
#define ANALYZER_PNG_HEADER_NAME "IHDR"

#define ANALYZER_PNG_HEADER_MIN_SIZE (8+4+4+4+4) // signature + 4 bytes hdr len + 4 byte header name (IHDR) + 4 bytes width + 4 bytes height

enum analyzer_png_pload_data {
	analyzer_png_pload_width = 0,
	analyzer_png_pload_height,
};

struct mod_reg_info* analyzer_png_reg_info();
static int analyzer_png_mod_register(struct mod_reg *mod);
static int analyzer_png_mod_unregister();

static int analyzer_png_init(struct analyzer *analyzer);
static int analyzer_png_pload_analyze(struct pload *p, struct pload_buffer *pb, void *priv);

#endif
