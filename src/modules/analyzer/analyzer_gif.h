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


#ifndef __ANALYZER_GIF_H__
#define __ANALYZER_GIF_H__

#include <pom-ng/analyzer.h>
#include <stdio.h>

#define ANALYZER_GIF_PLOAD_TYPE "gif"

#define ANALYZER_GIF_PLOAD_DATA_COUNT 2

#define ANALYZER_GIF_VERSION_87A "GIF87a"
#define ANALYZER_GIF_VERSION_89A "GIF89a"

#define ANALYZER_GIF_HEADER_MIN_SIZE 11 // signature + 2 bytes width + 2 bytes height

enum analyzer_gif_pload_data {
	analyzer_gif_pload_width = 0,
	analyzer_gif_pload_height,
};

struct mod_reg_info* analyzer_gif_reg_info();
static int analyzer_gif_mod_register(struct mod_reg *mod);
static int analyzer_gif_mod_unregister();

static int analyzer_gif_init(struct analyzer *analyzer);
static int analyzer_gif_pload_process(struct analyzer *analyzer, struct analyzer_pload_buffer *pload);

#endif
