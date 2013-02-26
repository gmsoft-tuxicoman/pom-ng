/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __POM_NG_STREAM_H__
#define __POM_NG_STREAM_H__

#include <pom-ng/base.h>
#include <pom-ng/timer.h>
#include <pom-ng/conntrack.h>

#define STREAM_FLAG_PACKET_NO_COPY	0x1
#define STREAM_FLAG_BIDIR		0x2

struct proto_process_stack;

struct stream* stream_alloc(uint32_t start_seq, uint32_t start_ack, int direction, uint32_t max_buff_size, struct conntrack_entry *ce, unsigned int flags);
int stream_set_timeout(struct stream *stream, unsigned int same_dir_timeout, unsigned int rev_dir_timeout, int (*handler) (struct conntrack_entry *ce, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index));
int stream_increase_seq(struct stream *stream, int direction, uint32_t inc);
int stream_cleanup(struct stream *stream);
int stream_process_packet(struct stream *stream, struct packet *pkt, struct proto_process_stack *stack, unsigned int stack_index, uint32_t seq, uint32_t ack);

#endif
