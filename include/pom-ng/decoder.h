/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_DECODER_H__
#define __POM_NG_DECODER_H__

#include <pom-ng/base.h>
#include <pom-ng/mod.h>

#define DEC_OK		POM_OK
#define DEC_ERR		POM_ERR
#define DEC_MORE	-2
#define DEC_END		-3

struct decoder {

	struct decoder_reg_info *reg;
	
	size_t avail_in;
	char *next_out;

	size_t avail_out;
	char *next_in;

	void *priv;
};

struct decoder_reg_info {

	char *name;
	struct mod_reg *mod;

	int (*alloc)(struct decoder *dec);

	size_t (*estimate_size) (size_t encoded_size);
	int (*decode) (struct decoder *dec);
	int (*cleanup) (struct decoder *dec);


};

int decoder_register(struct decoder_reg_info *reg_info);
int decoder_unregister(char *name);

struct decoder *decoder_alloc(char *name);
int decoder_cleanup(struct decoder *dec);

int decoder_estimate_output_size(struct decoder *dec, size_t in_len);
int decoder_decode(struct decoder *dec);
int decoder_decode_simple(char *encoding, char *in, size_t in_len, char **out, size_t *out_len);

#endif
