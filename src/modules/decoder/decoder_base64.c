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
	dec_base64.estimate_size = decoder_base64_estimate_size;
	dec_base64.decode = decoder_base64_decode;

	return decoder_register(&dec_base64);

}

static int decoder_base64_mod_unregister() {

	return decoder_unregister("base64");
}

static size_t decoder_base64_estimate_size(size_t encoded_size) {

	return (encoded_size / 4) * 3 + 1;
}

int decoder_base64_decode(struct decoder *dec) {


	char value[4];

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
		if (block[1] == '=')
			break;
		output[0] = ((value[0] << 2) | (0x3 & (value[1] >> 4)));
		dec->avail_out--;
		dec->next_out++;

		if (block[2] == '=')
			break;
		output[1] = ((value[1] << 4) | (0xf & (value[2] >> 2)));
		dec->avail_out--;
		dec->next_out++;

		if (block[3] == '=')
			break;
		output[2] = ((value[2] << 6) | value[3]);
		dec->avail_out--;
		dec->next_out++;

		dec->next_in += 4;
		dec->avail_in -= 4;

	}

	if (dec->avail_out > 0)
		*dec->next_out = 0;
	if (dec->avail_in > 0)
		return DEC_MORE;

	return DEC_OK;
}
