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


#ifndef __POM_NG_PACKET_H__
#define __POM_NG_PACKET_H__

#define PACKET_INFO_MAX 8

#include <pthread.h>

struct packet {
	struct timeval *ts;
	size_t len;
	size_t bufflen;
	unsigned char *buff;
	struct packet_info_list *info_head, *info_tail;
};

struct packet_info_reg {
	char *name;
	struct ptype *value_template;
};

struct packet_info_val {
	struct packet_info_reg *reg;
	struct ptype *value;
};

struct packet_info_owner {
	char *name;
	unsigned int refcount;
	pthread_mutex_t lock;
	struct packet_info_reg info[PACKET_INFO_MAX + 1];

	struct packet_info_owner *prev, *next;
};

struct packet_info_list {
	struct packet_info_owner *owner;
	struct packet_info_val *values;
	struct packet_info_list *next, *prev;
};


struct packet_info_owner *packet_register_info_owner(char *owner, struct packet_info_reg *info);
int packet_unregister_info_owner(struct packet_info_owner *owner);
struct packet_info_list *packet_add_infos(struct packet *p, struct packet_info_owner *owner);


#endif
