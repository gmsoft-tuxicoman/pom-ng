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


#include "output_file.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include <sys/time.h>

#include <pom-ng/ptype_string.h>

struct mod_reg_info* output_file_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = output_file_mod_register;
	reg_info.unregister_func = output_file_mod_unregister;

	return &reg_info;

}

int output_file_mod_register(struct mod_reg *mod) {


	static struct output_reg_info output_file;
	memset(&output_file, 0, sizeof(struct output_reg_info));
	output_file.name = "file";
	output_file.api_ver = OUTPUT_API_VER;
	output_file.mod = mod;

	output_file.init = output_file_init;
	output_file.close = output_file_close;
	output_file.cleanup = output_file_cleanup;

	return output_register(&output_file);
}

int output_file_mod_unregister() {

	int res = POM_OK;

	res += output_unregister("file");

	return res;
}


int output_file_init(struct output *o) {

	struct output_file_priv *priv = malloc(sizeof(struct output_file_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_file_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct output_file_priv));
	o->priv = priv;

	priv->p_path = ptype_alloc("string");
	priv->p_filter = ptype_alloc("string");

	if (!priv->p_path || !priv->p_filter)
		goto err;

	struct registry_param *p = registry_new_param("path", "/tmp/", priv->p_path, "Path where to store the files", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("filter", "", priv->p_filter, "File filter", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;


	static struct analyzer_pload_output_reg output_reg;
	memset(&output_reg, 0, sizeof(struct analyzer_pload_output_reg));
	output_reg.open = output_file_pload_open;
	output_reg.write = output_file_pload_write;
	output_reg.close = output_file_pload_close;

	if (analyzer_pload_output_register(o, &output_reg) != POM_OK)
		goto err;

	
	return POM_OK;
err:
	output_file_cleanup(o);
	return POM_ERR;

}

int output_file_cleanup(struct output *o) {

	struct output_file_priv *priv = o->priv;
	if (priv) {
		if (priv->p_path)
			ptype_cleanup(priv->p_path);
		if (priv->p_filter)
			ptype_cleanup(priv->p_filter);
		free(priv);

	}

	analyzer_pload_output_unregister(o);
	
	return POM_OK;
}


int output_file_close(struct output *o) {

	//struct output_file_priv *priv = o->priv;

	// TODO close all the files

	return POM_OK;
}


int output_file_pload_open(struct analyzer_pload_output_list *po) {

	struct output_file_priv *priv = po->o->output->priv;

	// Open the file
	char filename[FILENAME_MAX + 1];
	strncpy(filename, PTYPE_STRING_GETVAL(priv->p_path), FILENAME_MAX);

	// TODO Use correct filename
	struct tm tmp;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	localtime_r((time_t*)&tv.tv_sec, &tmp);
	char *format = "%Y%m%d-%H%M%S";
	char buff[4+2+2+1+2+2+2+1];
	strftime(buff, sizeof(buff), format, &tmp);
	snprintf(filename + strlen(filename), FILENAME_MAX - strlen(filename), "%s-%u.bin", buff, (unsigned int)tv.tv_usec);


	int fd = open(filename, O_WRONLY | O_CREAT, 0666);
	if (fd == -1)
		return POM_ERR;


	// Store the fd in memory

	struct output_file_pload_priv *ppriv = malloc(sizeof(struct output_file_pload_priv));
	if (!ppriv) {
		close(fd);
		pom_oom(sizeof(struct output_file_pload_priv));
		return POM_ERR;
	}
	memset(ppriv, 0, sizeof(struct output_file_pload_priv));

	ppriv->fd = fd;
	ppriv->filename = strdup(filename);
	if (!ppriv->filename) {
		free(ppriv);
		pom_oom(strlen(filename));
		return POM_ERR;
	}

	po->priv = ppriv;

	return POM_OK;

}

ssize_t output_file_pload_write(struct analyzer_pload_output_list *po, void *data, size_t len) {


	struct output_file_pload_priv *ppriv = po->priv;
	ssize_t res = write(ppriv->fd, data, len);
	if (res == -1)
		pomlog(POMLOG_ERR "Error while writing to file %s : %s", ppriv->filename, pom_strerror(errno));

	return res;

}

int output_file_pload_close(struct analyzer_pload_output_list *po) {

	struct output_file_pload_priv *ppriv = po->priv;
	int fd = ppriv->fd;
	pomlog(POMLOG_DEBUG "File %s closed", ppriv->filename);
	free(ppriv->filename);
	free(ppriv);
	po->priv = NULL;

	return close(fd);
}

