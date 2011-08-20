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

char *pom_strerror(int err) {

	static __thread char buff[POM_STRERROR_BUFF_SIZE];
	memset(buff, 0, POM_STRERROR_BUFF_SIZE);
	strerror_r(errno, buff, POM_STRERROR_BUFF_SIZE - 1);

	return buff;
}


void pom_oom_internal(size_t size, char *file, unsigned int line) {
	pomlog(POMLOG_ERR "Not enough memory to allocate %u bytes at %s:%u", size, file, line);
}



int pom_write(int fd, const void *buf, size_t count) {

	size_t pos = 0;
	while (pos < count) {
		size_t len = write(fd, buf + pos, count - pos);
		if (len < 0) {
			pomlog(POMLOG_ERR "Write error : %s", pom_strerror(errno));
			return POM_ERR;
		}
		pos += len;
	}

	return POM_OK;
}
