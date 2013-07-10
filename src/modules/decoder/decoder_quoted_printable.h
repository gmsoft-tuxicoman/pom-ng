/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __DECODER_QUOTED_PRINTABLE_H_
#define __DECODER_QUOTED_PRINTABLE_H_

#include <pom-ng/decoder.h>

struct decoder_quoted_printable_priv {
	char buff[4];
	int buff_len;
};

struct mod_reg_info *decoder_quoted_printable_reg_info();

static int decoder_quoted_printable_mod_register(struct mod_reg *mod);
static int decoder_quoted_printable_mod_unregister();

static int decoder_quoted_printable_alloc(struct decoder *dec);
static int decoder_quoted_printable_cleanup(struct decoder *dec);

static size_t decoder_quoted_printable_estimate_size(size_t encoded_size);
static int decoder_quoted_printable_decode(struct decoder *dec);

#endif
