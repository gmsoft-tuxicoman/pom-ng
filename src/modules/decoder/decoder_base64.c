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

#include "decoder_base64.h"

struct mod_reg_info *decoder_base64_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = decoder_base64_mod_register;
	reg_info.unregister_func = decoder_base64_mod_unregister;
	reg_info.dependencies = "";

	return &reg_info;

}

static int decoder_base64_mod_register(struct mod_reg *mod) {

	static struct decoder_reg_info dec_base64 = { 0 };
	dec_base64.name = "base64";
	dec_base64.mod = mod;
	dec_base64.alloc = decoder_base64_alloc;
	dec_base64.cleanup = decoder_base64_cleanup;
	dec_base64.estimate_size = decoder_base64_estimate_size;
	dec_base64.decode = decoder_base64_decode;

	return decoder_register(&dec_base64);

}

static int decoder_base64_mod_unregister() {

	return decoder_unregister("base64");
}

static int decoder_base64_alloc(struct decoder *dec) {

	struct decoder_base64_priv *priv = malloc(sizeof(struct decoder_base64_priv));
	if (!priv) {
		pom_oom(sizeof(struct decoder_base64_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct decoder_base64_priv));

	dec->priv = priv;

	return POM_OK;
}

static int decoder_base64_cleanup(struct decoder *dec) {

	if (dec->priv)
		free(dec->priv);

	return POM_OK;
}

static size_t decoder_base64_estimate_size(size_t encoded_size) {

	return (encoded_size / 4) * 3 + 1;
}

int decoder_base64_decode(struct decoder *dec) {


	struct decoder_base64_priv *priv = dec->priv;

	if (dec->priv && priv->buff_len) {
		int i;
		for (i = 0; i < (4 - priv->buff_len) && i < dec->avail_in; i++) {
			priv->buff[priv->buff_len + i] = dec->next_in[i];
		}
		priv->buff_len += i;
		dec->avail_in -= i;
		dec->next_in += i;

		if (priv->buff_len < 4)
			return DEC_OK;

		// Setup a temporary struct decoder to decode these 3 bytes
		struct decoder tmp_dec = { 0 };
		tmp_dec.avail_in = 4;
		tmp_dec.next_in = priv->buff;
		tmp_dec.avail_out = dec->avail_out;
		tmp_dec.next_out = dec->next_out;

		int res = decoder_base64_decode(&tmp_dec);
		dec->avail_out = tmp_dec.avail_out;
		dec->next_out = tmp_dec.next_out;

		if (res != DEC_OK)
			return res;


		// Discard our buffer
		priv->buff_len = 0;

	}

	char value[4];
	int res = DEC_OK;

	while (dec->avail_in >= 4 && dec->avail_out >= 4) {
		char *block = dec->next_in;
		int i;
		for (i = 0; i < 4; i++) {
			if (block[i] >= 'A' && block[i] <= 'Z') {
				value[i] = block[i] - 'A';
			} else if (block[i] >= 'a' && block[i] <= 'z') {
				value[i] = block[i] - 'a' + 26;
			} else if (block[i] >= '0' && block[i] <= '9') {
				value[i] = block[i] - '0' + 52;
			} else if (block[i] == '+') {
				value[i] = 62;
			} else if (block[i] == '/') {
				value[i] = 63;
			} else if (block[i] == '=') {
				value[i] = 0;
			}
		}
		
		char *output = dec->next_out;
		if (block[1] == '=') {
			res = DEC_END;
			break;
		}
		output[0] = ((value[0] << 2) | (0x3 & (value[1] >> 4)));
		dec->avail_out--;
		dec->next_out++;

		if (block[2] == '=') {
			res = DEC_END;
			break;
		}
		output[1] = ((value[1] << 4) | (0xf & (value[2] >> 2)));
		dec->avail_out--;
		dec->next_out++;

		if (block[3] == '=') {
			res = DEC_END;
			break;
		}
		output[2] = ((value[2] << 6) | value[3]);
		dec->avail_out--;
		dec->next_out++;

		dec->next_in += 4;
		dec->avail_in -= 4;

	}

	if (dec->avail_out > 0)
		*dec->next_out = 0;

	if (dec->avail_in > 0) {
		memcpy(priv->buff, dec->next_in, dec->avail_in);
		priv->buff[dec->avail_in] = 0;
		priv->buff_len = dec->avail_in;
		dec->next_in += dec->avail_in;
		dec->avail_in = 0;
	}

	if (res == DEC_END) {
		dec->next_in += 4;
		dec->avail_in -= 4;
	}

	return res;
}
