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
static pthread_mutex_t mod_reg_lock = PTHREAD_MUTEX_INITIALIZER;

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

	int ptype_pass = 1;
	struct dirent tmp, *dp;
	while (1) {
		if (readdir_r(d, &tmp, &dp) < 0) {
			pomlog(POMLOG_ERR "Error while reading directory entry : %s", pom_strerror(errno));
			closedir(d);
			return POM_ERR;
		}
		if (!dp) { // EOF
			if (ptype_pass) {
				// Reopen and load non ptype modules
				closedir(d);
				d = opendir(path);
				ptype_pass = 0;
				continue;
			}
			break;
		}


		size_t len = strlen(dp->d_name);
		if (len < strlen(POM_LIB_EXT) + 1)
			continue;
		if (!strcmp(dp->d_name + strlen(dp->d_name) - strlen(POM_LIB_EXT), POM_LIB_EXT)) {

			int is_ptype = 0;
			if (!strncmp(dp->d_name, "ptype", strlen("ptype")))
				is_ptype = 1;

			if (ptype_pass ^ is_ptype)
				continue;

			char *name = strdup(dp->d_name);
			if (!name) {
				pom_oom(strlen(dp->d_name));
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

	pom_mutex_lock(&mod_reg_lock);
	struct mod_reg *tmp;
	for (tmp = mod_reg_head; tmp && strcmp(tmp->name, name); tmp = tmp->next);
	if (tmp) {
		pom_mutex_unlock(&mod_reg_lock);
		pomlog(POMLOG_WARN "Module %s is already registered");
		return NULL;
	}
	pom_mutex_unlock(&mod_reg_lock);

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

	if (!reg->filename || !reg->name || pthread_mutex_init(&reg->lock, NULL)) {
		if (reg->filename)
			free(reg->filename);
		if (reg->name)
			free(reg->name);
		free(reg);
		
		pomlog(POMLOG_ERR "Not enough memory to allocate name and filename of struct mod_reg or failed to initialize the lock");

		return NULL;
	}

	pom_mutex_lock(&mod_reg_lock);

	reg->next = mod_reg_head;
	mod_reg_head = reg;
	if (reg->next)
		reg->next->prev = reg;

	pom_mutex_unlock(&mod_reg_lock);

	pomlog(POMLOG_DEBUG "Module %s loaded, registering components ...", reg->name);

	if (reg->info->register_func(reg) != POM_OK) {
		pomlog(POMLOG_WARN "Error while registering the components of module %s", reg->name);
		mod_unload(reg);
		return NULL;
	}

	pom_mutex_lock(&reg->lock);
	if (!reg->refcount) {
		pom_mutex_unlock(&reg->lock);
		pomlog(POMLOG_DEBUG "Module %s did not register anything. Unloading it", reg->name);
		mod_unload(reg);
		return NULL;
	}

	pom_mutex_unlock(&reg->lock);

	return reg;

}

void mod_refcount_inc(struct mod_reg *mod) {

	if (!mod)
		return;

	pthread_mutex_lock(&mod->lock);
	mod->refcount++;
	pthread_mutex_unlock(&mod->lock);
}

void mod_refcount_dec(struct mod_reg *mod) {

	if (!mod)
		return;

	pthread_mutex_lock(&mod->lock);
	mod->refcount--;
	pthread_mutex_unlock(&mod->lock);
}

int mod_unload(struct mod_reg *mod) {

	if (!mod)
		return POM_ERR;

	pom_mutex_lock(&mod_reg_lock);

	// Try to unregister components registered by the module
	if (mod->info->unregister_func) {
		if (mod->info->unregister_func() != POM_OK) {
			pomlog(POMLOG_ERR "Unable to unregister module %s", mod->name);
			pom_mutex_unlock(&mod_reg_lock);
			return POM_ERR;
		}
	}
	pom_mutex_lock(&mod->lock);
	if (mod->refcount) {
		pomlog(POMLOG_WARN "Cannot unload module %s as it's still in use", mod->name);
		pom_mutex_unlock(&mod->lock);
		pom_mutex_unlock(&mod_reg_lock);
		return POM_ERR;
	}
	if (mod->prev)
		mod->prev->next = mod->next;
	else
		mod_reg_head = mod->next;

	if (mod->next)
		mod->next->prev = mod->prev;

	pom_mutex_unlock(&mod->lock);
	pthread_mutex_destroy(&mod->lock);

	mod->next = NULL;
	mod->prev = NULL;

	pom_mutex_unlock(&mod_reg_lock);

	if (dlclose(mod->dl_handle))
		pomlog(POMLOG_WARN "Error while closing module %s", mod->name);

	pomlog(POMLOG_DEBUG "Module %s unloaded", mod->name);

	free(mod->filename);
	free(mod->name);

	free(mod);


	return POM_OK;
}

int mod_unload_all() {

	pom_mutex_lock(&mod_reg_lock);

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

		pom_mutex_lock(&mod->lock);
		if (mod->refcount) {
			pomlog(POMLOG_WARN "Cannot unload module %s as it's still in use", mod->name);
			pom_mutex_unlock(&mod->lock);
			pom_mutex_unlock(&mod_reg_lock);
			mod = mod->next;
			continue;
		}

		mod->next = NULL;
		mod->prev = NULL;

		pom_mutex_unlock(&mod->lock);
		pthread_mutex_destroy(&mod->lock);

		if (dlclose(mod->dl_handle))
			pomlog(POMLOG_WARN "Error while closing module %s", mod->name);

		pomlog(POMLOG_DEBUG "Module %s unloaded", mod->name);

		free(mod->filename);
		free(mod->name);

		free(mod);
	}

	pom_mutex_unlock(&mod_reg_lock);

	return POM_OK;
}

