/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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
#include "core.h"
#include "input.h"
#include "input_client.h"


void *core_process_thread(void *input) {

	struct input_client_entry *i = input;

	pomlog(POMLOG_INFO "New thread created for input %u", i->id);

	while (1) {
		if (input_client_get_packet(i) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while reading packet");
			return NULL;
		}
		pomlog(POMLOG_DEBUG "Got packet with size %u", i->pkt->len);
	}

	return NULL;
}
