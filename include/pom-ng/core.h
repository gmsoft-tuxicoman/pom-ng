/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __POM_NG_CORE_H__
#define __POM_NG_CORE_H__

#include <pom-ng/proto.h>

#define CORE_QUEUE_HAS_THREAD_AFFINITY	0x1
#define CORE_QUEUE_DROP_IF_FULL		0x2

#define CORE_PROTO_STACK_START		1
#define CORE_PROTO_STACK_MAX		16

int core_process_multi_packet(struct proto_process_stack *s, unsigned int stack_index, struct packet *p);
int core_queue_packet(struct packet *p, unsigned int flags, unsigned int thread_affinity);
struct proto_process_stack *core_stack_backup(struct proto_process_stack *stack, struct packet* old_pkt, struct packet *new_pkt);
void core_stack_release(struct proto_process_stack *stack);

#endif
