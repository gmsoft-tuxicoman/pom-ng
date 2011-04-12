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


#ifndef __MOD_H__
#define __MOD_H__

#include <pom-ng/mod.h>
#include <dlfcn.h>

#define MOD_LIBDIR_ENV_VAR "POM_LIBDIR"

// Flags used when loading libraries
#ifdef RTLD_GROUP
#define RTLD_FLAGS RTLD_NOW | RTLD_LOCAL | RTLD_GROUP
#else
#define RTLD_FLAGS RTLD_NOW | RTLD_LOCAL
#endif

#define POM_LIB_EXT ".so"

struct mod_reg {
	struct mod_reg_info *info;
	int refcount;
	pthread_mutex_t lock;
	char *name;
	char *filename;
	void *dl_handle;
	struct mod_reg *next, *prev;

};

int mod_load_all();
struct mod_reg *mod_load(char *name);

int mod_unload(struct mod_reg *mod);
int mod_unload_all();

void mod_refcount_inc(struct mod_reg *mod);
void mod_refcount_dec(struct mod_reg *mod);

#endif
