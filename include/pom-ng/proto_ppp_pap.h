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

#ifndef __POM_NG_PROTO_PPP_PAP_H__
#define __POM_NG_PROTO_PPP_PAP_H__


enum {
	evt_ppp_pap_request_code = 0,
	evt_ppp_pap_request_identifier,
	evt_ppp_pap_request_peer_id,
	evt_ppp_pap_request_password
};

enum {
	evt_ppp_pap_ack_nack_code,
	evt_ppp_pap_ack_nack_identifier,
	evt_ppp_pap_ack_nack_message
};

#endif
