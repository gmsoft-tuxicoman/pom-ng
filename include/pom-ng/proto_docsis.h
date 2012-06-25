/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_PROTO_DOCSIS_H__
#define __POM_NG_PROTO_DOCSIS_H__

enum proto_docsis_fields {
	proto_docsis_field_fc_type = 0,
	proto_docsis_field_fc_parm,
	proto_docsis_field_ehdr_on,
};

enum proto_docsis_mgmt_fields {
	proto_docsis_mgmt_field_saddr = 0,
	proto_docsis_mgmt_field_daddr,
	proto_docsis_mgmt_field_dsap,
	proto_docsis_mgmt_field_ssap,
	proto_docsis_mgmt_field_control,
	proto_docsis_mgmt_field_version,
	proto_docsis_mgmt_field_type
};

#endif
