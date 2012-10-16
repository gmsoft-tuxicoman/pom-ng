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

#include "common.h"

size_t decode_percent(char *dst, char *src, size_t length) {

	int state_search = 1;
	size_t res_len = 0;

	while (length > 0) {
		if (state_search) {
			if (*src == '%') {
				state_search = 0;
				src++;
				length--;
				continue;
			} else if (*src == '+') {
				*dst = ' ';
			} else {
				*dst = *src;	
			}
			src++;
			dst++;
			length--;
			res_len++;
		} else {

			if (length < 2) {
				*dst = '%';
				*(dst + 1) = *src;
				res_len += 2;
				break;
			}
				
			
			int i, failed = 0;
			unsigned char res = 0;
			for (i = 0; i < 2; i++) {
				if ((src[i] >= '0' && src[i] <= '9'))
					res += (src[i] - '0') << (4 * (1 - i));
				else if (src[i] >= 'a' && src[i] <= 'f')
					res += (src[i] - 'a') << (4 * (1 - i));
				else if (src[i] >= 'A' && src[i] <= 'F')
					res += (src[i] - 'A') << (4 * (1 - i));
				else {
					// Copy the '%' sign and continue;
					*dst = '%';
					dst++;
					res_len++;
					break;
				}
			}

			state_search = 1;

			if (failed)
				continue;

			*dst = res;
			dst++;
			src += 2;
			length -= 2;
			res_len++;
		}


	}


	return res_len;
}


size_t decode_base64(char *output, char *input, size_t out_len) {

	size_t len = strlen(input);

	if (len % 4) {
		pomlog(POMLOG_DEBUG "Base64 input length not multiple of 4");
		return POM_ERR;
	}

	if (out_len < ((len / 4) * 3 + 1)) {
		pomlog(POMLOG_DEBUG "Base64 output length too short");
		return POM_ERR;
	}

	char *block, value[4];
	
	len = POM_ERR;

	block = input;
	while (block[0]) {
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
			
		if (block[1] == '=')
			return len;
		output[0] = ((value[0] << 2) | (0x3 & (value[1] >> 4)));
		len++;

		if (block[2] == '=')
			return len;
		output[1] = ((value[1] << 4) | (0xf & (value[2] >> 2)));
		len++;

		if (block[3] == '=')
			return len;
		output[2] = ((value[2] << 6) | value[3]);
		len++;

		output += 3;
		block += 4;

	}

	return len;

}
