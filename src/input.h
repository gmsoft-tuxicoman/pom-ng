/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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



#ifndef __INPUT_H__
#define __INPUT_H__

#include <pom-ng/input.h>


#define INPUT_REGISTRY "input"

#define INPUT_RUN_RUNNING	0x1
#define INPUT_RUN_BUSY		0x2 // Either it's starting or it's stopping

struct input_reg {

	struct input_reg_info *info;
	struct mod_reg *module;
	unsigned int refcount;

	struct input_reg *next, *prev;

};



int input_init();
int input_cleanup();

int input_instance_add(char *type, char *name);
int input_instance_remove(struct registry_instance *ri);
int input_instance_start_stop_handler(void *priv, struct registry_param *p, struct ptype *run);
int input_stop_all();

void *input_process_thread(void *param);

int input_param_locked_while_running(void *input, struct registry_param *p, char *param);

#endif
