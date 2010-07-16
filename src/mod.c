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

#include "common.h"
#include "mod.h"

#include <sys/types.h>

static struct mod_reg *mod_reg_head = NULL;
static pthread_rwlock_t mod_reg_rwlock = PTHREAD_RWLOCK_INITIALIZER;

struct mod_reg *mod_load(char *name) {

	
	pomlog("Opening module %s", name);

	char filename[FILENAME_MAX];
	memset(filename, 0, FILENAME_MAX);

	char *env_libdir = getenv(MOD_LIBDIR_ENV_VAR);

	if (env_libdir)
		strcpy(filename, env_libdir);
	else
		strcpy(filename, POM_LIBDIR);

	if (filename[strlen(filename) - 1] != '/')
		strcat(filename, "/");

	strcat(filename, name);
	strcat(filename, ".so");

	void *dl_handle = dlopen(filename, RTLD_FLAGS);

	if (!dl_handle) {
		pomlog(POMLOG_ERR "Unable to load module %s : %s", name, dlerror());
		return NULL;
	}

	// Empty error buff
	dlerror();

	char func_name[FILENAME_MAX];
	strcpy(func_name, name);
	strcat(func_name, "_reg_info");

	struct mod_reg_info* (*mod_reg_func) () = NULL;
	mod_reg_func = dlsym(dl_handle, func_name);
	if (!mod_reg_func) {
		pomlog(POMLOG_ERR "Function %s not found in module %s", func_name, filename);
		return NULL;
	}



	struct mod_reg_info *reg_info = mod_reg_func();
	if (!reg_info) {
		pomlog(POMLOG_ERR "Function %s returned NULL", func_name);
		dlclose(dl_handle);
		return NULL;
	}

	if (reg_info->api_ver != MOD_API_VER) {
		pomlog(POMLOG_ERR "API version of module %s does not match : expected %u got %u", name, MOD_API_VER, reg_info->api_ver);
		dlclose(dl_handle);
		return NULL;
	}

	struct mod_reg *reg = malloc(sizeof(struct mod_reg));
	if (!reg) {
		pomlog(POMLOG_ERR "Not enough memory to allocate struct mod_reg");
		return NULL;
	}

	memset(reg, 0, sizeof(struct mod_reg));

	mod_reg_lock(1);

	reg->dl_handle = dl_handle;
	reg->filename = strdup(filename);
	reg->name = strdup(name);
	reg->info = reg_info;

	reg->next = mod_reg_head;
	mod_reg_head = reg;
	if (reg->next)
		reg->next->prev = reg;

	mod_reg_unlock();

	pomlog("Module %s loaded, registering components ...", reg->name);

	if (reg->info->register_func(reg) != POM_OK) {
		pomlog("Error while registering the components of module %s", reg->name);
		mod_unload(reg);
		return NULL;
	}

	return reg;

}

void mod_refcount_inc(struct mod_reg *mod) {

	if (!mod)
		return;

	mod_reg_lock(1);
	mod->refcount++;
	mod_reg_unlock();
}

void mod_refcount_dec(struct mod_reg *mod) {
	if (!mod)
		return;

	mod_reg_lock(1);
	mod->refcount--;
	mod_reg_unlock();
}


int mod_unload(struct mod_reg *mod) {

	if (!mod)
		return POM_ERR;

	// Try to unregister components registered by the module
	if (mod->info->unregister_func) {
		if (mod->info->unregister_func() != POM_OK) {
			pomlog(POMLOG_ERR "Unable to unregister module %s", mod->name);
			mod_reg_unlock();
			return POM_ERR;
		}
	}

	mod_reg_lock(1);
	if (mod->refcount) {
		pomlog(POMLOG_WARN "Cannot unload module %s as it's still in use", mod->name);
		mod_reg_unlock();
		return POM_ERR;
	}
	if (mod->prev)
		mod->prev->next = mod->next;
	else
		mod_reg_head = mod->next;

	if (mod->next)
		mod->next->prev = mod->prev;

	mod->next = NULL;
	mod->prev = NULL;

	mod_reg_unlock();

	if (dlclose(mod->dl_handle))
		pomlog(POMLOG_WARN "Error while closing module %s", mod->name);

	pomlog("Module %s unloaded", mod->name);

	free(mod->filename);
	free(mod->name);

	free(mod);


	return POM_OK;
}

void mod_reg_lock(int write) {
	int res = 0;

	if (write)
		res = pthread_rwlock_wrlock(&mod_reg_rwlock);
	else
		res = pthread_rwlock_rdlock(&mod_reg_rwlock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking the mod_reg lock");
		abort();
	}

}

void mod_reg_unlock() {

	if (pthread_rwlock_unlock(&mod_reg_rwlock)) {
		pomlog(POMLOG_ERR "Error while unlocking the mod_reg lock");
		abort();
	}

}
