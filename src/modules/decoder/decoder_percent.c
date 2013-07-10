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

#include "decoder_percent.h"

struct mod_reg_info *decoder_percent_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = decoder_percent_mod_register;
	reg_info.unregister_func = decoder_percent_mod_unregister;
	reg_info.dependencies = "";

	return &reg_info;

}

static int decoder_percent_mod_register(struct mod_reg *mod) {

	static struct decoder_reg_info dec_percent = { 0 };
	dec_percent.name = "percent";
	dec_percent.mod = mod;
	dec_percent.alloc = decoder_percent_alloc;
	dec_percent.cleanup = decoder_percent_cleanup;
	dec_percent.estimate_size = decoder_percent_estimate_size;
	dec_percent.decode = decoder_percent_decode;

	return decoder_register(&dec_percent);

}

static int decoder_percent_mod_unregister() {

	return decoder_unregister("percent");
}

static int decoder_percent_alloc(struct decoder *dec) {
	
	struct decoder_percent_priv *priv = malloc(sizeof(struct decoder_percent_priv));
	if (!priv) {
		pom_oom(sizeof(struct decoder_percent_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct decoder_percent_priv));

	dec->priv = priv;

	return POM_OK;
}

static int decoder_percent_cleanup(struct decoder *dec) {

	if (dec->priv)
		free(dec->priv);

	return POM_OK;
}

static size_t decoder_percent_estimate_size(size_t encoded_size) {

	return encoded_size + 1;
}

int decoder_percent_decode(struct decoder *dec) {

	struct decoder_percent_priv *priv = dec->priv;

	if (dec->priv && priv->buff_len) {
		int i;
		for (i = 0; i < (3 - priv->buff_len) && i < dec->avail_in; i++) {
			priv->buff[priv->buff_len + i] = dec->next_in[i];
		}
		priv->buff_len += i;
		dec->avail_in -= i;
		dec->next_in += i;

		if (priv->buff_len < 3)
			return DEC_OK;

		// Setup a temporary struct decoder to decode these 3 bytes
		struct decoder tmp_dec = { 0 };
		tmp_dec.avail_in = 3;
		tmp_dec.next_in = priv->buff;
		tmp_dec.avail_out = dec->avail_out;
		tmp_dec.next_out = dec->next_out;

		int res = decoder_percent_decode(&tmp_dec);
		dec->avail_out = tmp_dec.avail_out;
		dec->next_out = tmp_dec.next_out;

		if (res != DEC_OK)
			return res;


		// Discard our buffer
		priv->buff_len = 0;

	}
	while (dec->avail_in && dec->avail_out) {

		// Copy up to the next percent sign
		char *percent = memchr(dec->next_in, '%', dec->avail_in);

		size_t len = dec->avail_in;
		
		if (percent)
			len = percent - dec->next_in;
		if (dec->avail_out < len)
			return DEC_MORE;

		memcpy(dec->next_out, dec->next_in, len);
		dec->next_out += len;
		dec->avail_out -= len;
		dec->next_in += len;
		dec->avail_in -= len;

		if (percent) {
			if (dec->avail_out < 1)
				return DEC_MORE;
			
			if (dec->avail_in >= 2 && *(dec->next_in + 1) == '%') {
				*dec->next_out = '%';
				dec->next_out++;
				dec->avail_out--;
				dec->next_in += 2;
				dec->avail_in -= 2;
				continue;
			} else if (dec->avail_in < 3) {
				memcpy(priv->buff, dec->next_in, dec->avail_in);
				priv->buff[dec->avail_in] = 0;
				priv->buff_len = dec->avail_in;
				dec->next_in += dec->avail_in;dec->avail_in = 0;
				return DEC_OK;
			}

			dec->next_in++;
			dec->avail_in--;

			char *in = dec->next_in;
			char *out = dec->next_out;
			*out = 0;

			int i;
			for (i = 0; i < 2; i++) {
				dec->next_in++;
				dec->avail_in--;
				if ((in[i] >= '0' && in[i] <= '9'))
					*out += (in[i] - '0') << (4 * (1 - i));
				else if (in[i] >= 'a' && in[i] <= 'f')
					*out += (in[i] - 'a' + 0xa) << (4 * (1 - i));
				else if (in[i] >= 'A' && in[i] <= 'F')
					*out += (in[i] - 'A' + 0xA) << (4 * (1 - i));
				else {
					// Copy the '%' sign and continue;
					*out = '%';
					break;
				}
			}

			dec->next_out++;
			dec->avail_out--;
		}
	}

	if (dec->avail_out > 0)
		*dec->next_out = 0;

	return DEC_OK;
}


