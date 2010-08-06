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
#include <dirent.h>

static struct mod_reg *mod_reg_head = NULL;
static pthread_rwlock_t mod_reg_rwlock = PTHREAD_RWLOCK_INITIALIZER;

int mod_load_all() {

	char *path = getenv(MOD_LIBDIR_ENV_VAR);
	if (!path)
		path = POM_LIBDIR;

	DIR *d;
	d = opendir(path);

	if (!d) {
		pomlog(POMLOG_ERR "Could not open directory %s for browsing : %s", path, pom_strerror(errno));
		return POM_ERR;
	}

	struct dirent *dp;
	while ((dp = readdir(d))) {
		size_t len = strlen(dp->d_name);
		if (len < strlen(POM_LIB_EXT) + 1)
			continue;
		if (!strcmp(dp->d_name + strlen(dp->d_name) - strlen(POM_LIB_EXT), POM_LIB_EXT)) {
			char *name = strdup(dp->d_name);
			if (!name) {
				pomlog(POMLOG_ERR "Not enough memory to strdup(%s)", dp->d_name);
				return POM_ERR;
			}
			*(name + strlen(dp->d_name) - strlen(POM_LIB_EXT)) = 0;
			mod_load(name);
			free(name);
		}
	}
	closedir(d);

	return POM_OK;

}

struct mod_reg *mod_load(char *name) {

	
	pomlog(POMLOG_DEBUG "Opening module %s", name);

	mod_reg_lock(0);
	struct mod_reg *tmp;
	for (tmp = mod_reg_head; tmp && strcmp(tmp->name, name); tmp = tmp->next);
	if (tmp) {
		mod_reg_unlock();
		pomlog(POMLOG_WARN "Module %s is already registered");
		return NULL;
	}
	mod_reg_unlock();

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
	strcat(filename, POM_LIB_EXT);

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


	reg->dl_handle = dl_handle;
	reg->filename = strdup(filename);
	reg->name = strdup(name);
	reg->info = reg_info;

	if (!reg->filename || !reg->name) {
		if (reg->filename)
			free(reg->filename);
		if (reg->name)
			free(reg->name);
		free(reg);
		
		pomlog(POMLOG_ERR "Not enough memory to allocate name and filename of struct mod_reg");

		return NULL;
	}

	mod_reg_lock(1);

	reg->next = mod_reg_head;
	mod_reg_head = reg;
	if (reg->next)
		reg->next->prev = reg;

	mod_reg_unlock();

	pomlog(POMLOG_DEBUG "Module %s loaded, registering components ...", reg->name);

	if (reg->info->register_func(reg) != POM_OK) {
		pomlog(POMLOG_WARN "Error while registering the components of module %s", reg->name);
		mod_unload(reg);
		return NULL;
	}

	mod_reg_lock(0);
	if (!reg->refcount) {
		pomlog(POMLOG_DEBUG "Module %s did not register anything. Unloading it");
		mod_reg_unlock();
		mod_unload(reg);
		return NULL;
	}

	mod_reg_unlock();

	return reg;

}

void mod_refcount_inc(struct mod_reg *mod) {

	if (!mod)
		return;

	int res = pthread_rwlock_wrlock(&mod_reg_rwlock);
	if (res && res != EDEADLK) { // If we don't have the lock, lock it
		pomlog(POMLOG_ERR "Failed to aquire the lock to increment the refcount");
		abort();
	}
	mod->refcount++;
	if (res != EDEADLK)
		mod_reg_unlock();
}

void mod_refcount_dec(struct mod_reg *mod) {
	if (!mod)
		return;

	int res = pthread_rwlock_wrlock(&mod_reg_rwlock);
	if (res && res != EDEADLK) { // If we don't have the lock, lock it
		pomlog(POMLOG_ERR "Failed to aquire the lock to decrement the refcount");
		abort();
	}
	mod->refcount--;
	if (res != EDEADLK)
		mod_reg_unlock();
}

int mod_unload(struct mod_reg *mod) {

	if (!mod)
		return POM_ERR;

	mod_reg_lock(1);

	// Try to unregister components registered by the module
	if (mod->info->unregister_func) {
		if (mod->info->unregister_func() != POM_OK) {
			pomlog(POMLOG_ERR "Unable to unregister module %s", mod->name);
			mod_reg_unlock();
			return POM_ERR;
		}
	}

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

	pomlog(POMLOG_DEBUG "Module %s unloaded", mod->name);

	free(mod->filename);
	free(mod->name);

	free(mod);


	return POM_OK;
}

int mod_unload_all() {

	mod_reg_lock(1);

	struct mod_reg *mod;
	while (mod_reg_head) {
		mod = mod_reg_head;
		mod_reg_head = mod->next;
		if (mod->info->unregister_func) {
			if (mod->info->unregister_func() != POM_OK) {
				pomlog(POMLOG_ERR "Unable to unregister module %s", mod->name);
				mod = mod->next;
				continue;
			}
		}

		if (mod->refcount) {
			pomlog(POMLOG_WARN "Cannot unload module %s as it's still in use", mod->name);
			mod_reg_unlock();
			mod = mod->next;
			continue;
		}

		mod->next = NULL;
		mod->prev = NULL;

		if (dlclose(mod->dl_handle))
			pomlog(POMLOG_WARN "Error while closing module %s", mod->name);

		pomlog(POMLOG_DEBUG "Module %s unloaded", mod->name);

		free(mod->filename);
		free(mod->name);

		free(mod);
	}

	mod_reg_unlock();

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
