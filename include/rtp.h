/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __RTP_H__
#define __RTP_H__

#include <stdint.h>

struct rtphdr {
	
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t csrc_count:4;
	uint8_t extension:1;
	uint8_t padding:1;
	uint8_t version:2;

	uint8_t payload_type:7;
	uint8_t marker:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version:2;
	uint8_t padding:1;
	uint8_t extension:1;
	uint8_t csrc_count:4;

	uint8_t marker:1;
	uint8_t payload_type:7;
#else
# error "Please fix <endian.h>"
#endif
	uint16_t seq_num;
	uint32_t timestamp;
	uint32_t ssrc;

};

struct rtphdrext {
	uint16_t profile_defined;
	uint16_t length;
	uint8_t *header_extension;
};

#endif
