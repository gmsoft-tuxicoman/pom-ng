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

#ifndef __POM_NG_PROTO_EAP_H__
#define __POM_NG_PROTO_EAP_H__


enum {
	evt_eap_common_identifier = 0,
	evt_eap_common_code
};

enum {
	evt_eap_identity_identity = evt_eap_common_code + 1
};

enum {
	evt_eap_md5_challenge_value = evt_eap_common_code + 1,
	evt_eap_md5_challenge_name
};

enum {
	evt_eap_success_failure_success = evt_eap_common_identifier + 1
};

#endif
