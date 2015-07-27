/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __POM_NG_FILTER_H__
#define __POM_NG_FILTER_H__

#define FILTER_MATCH_NO		0
#define FILTER_MATCH_YES	1


// Avoid including external files
struct event;
struct event_reg;
struct pload;
struct proto_process_stack;

struct filter_node;

int filter_packet(char *filter_expr, struct filter_node **filter);
int filter_event(char *filter_expr, struct event_reg *evt_reg, struct filter_node **filter);
int filter_pload(char *filter_expr, struct filter_node **filter);

int filter_packet_match(struct filter_node *n, struct proto_process_stack *stack);
int filter_event_match(struct filter_node *n, struct event *evt);
int filter_pload_match(struct filter_node *n, struct pload *p);

void filter_cleanup(struct filter_node *n);

#endif
