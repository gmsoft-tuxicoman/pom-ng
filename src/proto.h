/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2011 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __PROTO_H__
#define __PROTO_H__

#include <pom-ng/proto.h>
#include "packet.h"
#include "conntrack.h"
#include "registry.h"

#define PROTO_REGISTRY "proto"

struct proto_event_analyzer_list {

	struct proto_event_analyzer_reg *analyzer_reg;
	struct proto_event_analyzer_list *next, *prev;

};

int proto_init();
void proto_dependency_refcount_inc(struct proto_dependency *proto_dep);
int proto_empty_conntracks();
int proto_cleanup();

#endif
