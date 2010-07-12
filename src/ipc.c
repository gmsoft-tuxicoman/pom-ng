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
#include "ipc.h"

#include <sys/msg.h>

int ipc_send_msg(int queue_id, void *msg, size_t len) {
	
	while (1) {
		int res = msgsnd(queue_id, msg, len - sizeof(long), 0);
		if (res == -1) {
			if (errno == EINTR)
				continue;
			pomlog(POMLOG_ERR "Error while sending IPC message : %s", pom_strerror(errno));
			return POM_ERR;
		}
		return POM_OK;
	}

	return POM_OK;
}

int ipc_read_msg(int queue_id, long type, void* msg, size_t len) {

	len -= sizeof(long);

	int res = -1;

	res = msgrcv(queue_id, msg, len, type, 0);

	if (res == -1) {
		if (errno != EINTR)
			pomlog(POMLOG_ERR "Error while reading IPC message : %s", pom_strerror(errno));
		return POM_ERR;
	}


	if (res != len) {
		pomlog(POMLOG_ERR "Error, message size doesn't match : expected %u, got %u", len, res);
		return POM_ERR;
	}

	return POM_OK;
}

