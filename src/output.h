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


#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include <pom-ng/output.h>

#define OUTPUT_REGISTRY "output"

struct output {

	char *name;
	struct output_reg *info;
	struct registry_instance *reg_instance;
	int running;

	struct registry_perf *perf_runtime;

	void *priv;

	struct output *prev, *next;

};

struct output_reg {

	struct output_reg_info *reg_info;

	struct output_reg *prev, *next;

};


int output_init();
int output_cleanup();
int output_instance_add(char *type, char *name);
int output_instance_remove(struct registry_instance *ri);
int output_instance_start_stop_handler(void *priv, struct registry_param *p, struct ptype *run);
int output_param_locked_while_running(void *output, struct registry_param *p, char *param);
#endif
