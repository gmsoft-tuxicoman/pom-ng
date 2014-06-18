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

#ifndef __POM_NG_PROTO_SIP_H__
#define __POM_NG_PROTO_SIP_H__


enum {
	proto_sip_req_method = 0,
	proto_sip_req_uri
};

enum {
	proto_sip_rsp_status = 0,
	proto_sip_rsp_reason
};

enum {
	proto_sip_msg_first_line = 2,
	proto_sip_msg_call_id,
	proto_sip_msg_cseq_num,
	proto_sip_msg_cseq_method,
	proto_sip_msg_content_type,
	proto_sip_msg_content_len,
	proto_sip_msg_from_display,
	proto_sip_msg_from_uri,
	proto_sip_msg_from_tag,
	proto_sip_msg_to_display,
	proto_sip_msg_to_uri,
	proto_sip_msg_to_tag,
	proto_sip_msg_other_headers,
};

#endif
