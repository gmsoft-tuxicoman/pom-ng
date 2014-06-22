
/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_TELEPHONY_H__
#define __POM_NG_TELEPHONY_H__

#include <pom-ng/ptype.h>


// Codec definitions

enum telephony_codec_type {
	telephony_codec_type_unknown = 0,
	telephony_codec_type_audio,
	telephony_codec_type_video,
	telephony_codec_type_text,
	telephony_codec_type_application,
	telephony_codec_type_message,

};


struct telephony_sdp *telephony_sdp_alloc();
int telephony_sdp_parse(struct telephony_sdp *sdp, void *data, size_t len);
int telephony_sdp_parse_end(struct telephony_sdp *sdp);

#endif
