/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#include "decoder_gzip.h"
#include <zlib.h>

#define DECODER_GZIP_DEFAULT_SIZE 4096

struct mod_reg_info *decoder_gzip_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = decoder_gzip_mod_register;
	reg_info.unregister_func = decoder_gzip_mod_unregister;
	reg_info.dependencies = "";

	return &reg_info;

}

static int decoder_gzip_mod_register(struct mod_reg *mod) {

	static struct decoder_reg_info dec_gzip = { 0 };
	dec_gzip.name = "gzip";
	dec_gzip.mod = mod;
	dec_gzip.alloc = decoder_gzip_alloc;
	dec_gzip.cleanup = decoder_gzip_cleanup;
	dec_gzip.estimate_size = decoder_gzip_estimate_size;
	dec_gzip.decode = decoder_gzip_decode;

	if (decoder_register(&dec_gzip) != POM_OK)
		return POM_ERR;

	static struct decoder_reg_info dec_deflate = { 0 };
	dec_deflate.name = "deflate";
	dec_deflate.mod = mod;
	dec_deflate.alloc = decoder_gzip_alloc;
	dec_deflate.cleanup = decoder_gzip_cleanup;
	dec_deflate.estimate_size = decoder_gzip_estimate_size;
	dec_deflate.decode = decoder_gzip_decode;

	if (decoder_register(&dec_deflate) != POM_OK)
		return POM_ERR;

	return POM_OK;
}

static int decoder_gzip_mod_unregister() {

	int res = POM_OK;
	res += decoder_unregister("gzip");
	res += decoder_unregister("deflate");
	return res;
}

static int decoder_gzip_alloc(struct decoder *dec) {

	z_stream *zbuff = malloc(sizeof(z_stream));
	if (!zbuff) {
		pom_oom(sizeof(z_stream));
		return POM_ERR;
	}

	memset(zbuff, 0, sizeof(z_stream));

	if (inflateInit2(zbuff, 15 + 32) != Z_OK) {
		if (zbuff->msg)
			pomlog(POMLOG_ERR "Unable to init Zlib : %s", zbuff->msg);
		else
			pomlog(POMLOG_ERR "Unable to init Zlib : Unknown error");
		free(zbuff);
		return POM_ERR;
	}

	dec->priv = zbuff;

	return POM_OK;
}

static int decoder_gzip_cleanup(struct decoder *dec) {

	if (!dec->priv)
		return POM_OK;

	z_stream *zbuff = dec->priv;
	inflateEnd(zbuff);
	free(zbuff);


	return POM_OK;
}

static size_t decoder_gzip_estimate_size(size_t encoded_size) {

	long pagesize = sysconf(_SC_PAGESIZE);
	
	if (pagesize)
		return pagesize;

	return DECODER_GZIP_DEFAULT_SIZE;
}

static int decoder_gzip_decode(struct decoder *dec) {
	
	if (!dec->priv)
		return DEC_ERR;

	z_stream *zbuff = dec->priv;

	zbuff->next_in = (unsigned char *)dec->next_in;
	zbuff->avail_in = dec->avail_in;
	zbuff->next_out = (unsigned char *)dec->next_out;
	zbuff->avail_out = dec->avail_out;

	int res = DEC_OK;
	int zres = inflate(zbuff, Z_SYNC_FLUSH);
	if (zres != Z_OK && zres != Z_STREAM_END) {
		char *msg = zbuff->msg;
		if (!msg)
			msg = "Unknown error";
		pomlog(POMLOG_DEBUG "Error while decompressing gzip content : %s", msg);
		res = DEC_ERR;
	} else if (zres == Z_STREAM_END) {
		res = DEC_END;
	} else if (!zbuff->avail_out) {
		res = DEC_MORE;
	}

	dec->next_in = (char *)zbuff->next_in;
	dec->avail_in = zbuff->avail_in;
	dec->next_out = (char*)zbuff->next_out;
	dec->avail_out = zbuff->avail_out;

	return res;
}
