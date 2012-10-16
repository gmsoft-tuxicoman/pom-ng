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
