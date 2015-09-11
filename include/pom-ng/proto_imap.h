/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2015 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_PROTO_IMAP_H__
#define __POM_NG_PROTO_IMAP_H__

#define PROTO_IMAP_EVT_CMD_DATA_COUNT 3

enum {
	proto_imap_cmd_tag,
	proto_imap_cmd_name,
	proto_imap_cmd_arg,
};

#define PROTO_IMAP_EVT_RESPONSE_DATA_COUNT 4

enum {
	proto_imap_response_tag,
	proto_imap_response_status,
	proto_imap_response_text,
	proto_imap_response_lines,
};

#endif
