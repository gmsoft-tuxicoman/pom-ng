/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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


struct filter_node;

struct filter_proto *filter_proto_build(char *proto, char *field, unsigned int op, char *value);
struct filter_proto *filter_proto_build_branch(struct filter_proto *a, struct filter_proto *b, unsigned int op);
void filter_proto_cleanup(struct filter_proto *f);
int filter_proto_parse(char *expr, unsigned int len, struct filter_proto **f);

#endif
