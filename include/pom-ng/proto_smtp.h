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

#ifndef __POM_NG_PROTO_SMTP_H__
#define __POM_NG_PROTO_SMTP_H__

#define PROTO_SMTP_EVT_CMD_DATA_COUNT 2

enum {
	proto_smtp_cmd_name,
	proto_smtp_cmd_arg,
};

#define PROTO_SMTP_EVT_REPLY_DATA_COUNT 5

enum {
	proto_smtp_reply_code,
	proto_smtp_reply_text,
};

#endif
