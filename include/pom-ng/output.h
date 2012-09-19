/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __POM_NG_OUTPUT_H__
#define __POM_NG_OUTPUT_H__

#include <pom-ng/base.h>
#include <pom-ng/proto.h>
#include <pom-ng/conntrack.h>

// Current output API version
#define OUTPUT_API_VER 1

struct output;

struct output_reg_info {
	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;

	int (*init) (struct output *o);
	int (*open) (void *output_priv);
	int (*close) (void *output_priv);
	int (*cleanup) (void *output_priv);

};

int output_register(struct output_reg_info *reg_info);
int output_unregister(char *name);

void output_set_priv(struct output *o, void *priv);
int output_instance_add_param(struct output *o, struct registry_param *p);


#endif
