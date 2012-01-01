/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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

#define INPUT_RUN_STOPPED	0x0
#define INPUT_RUN_RUNNING	0x1
#define INPUT_RUN_STOPPING	0x2

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
int input_instance_start_stop_handler(void *priv, struct ptype *run);

void *input_process_thread(void *param);

#endif
