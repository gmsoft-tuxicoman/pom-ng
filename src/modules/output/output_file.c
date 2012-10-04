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
#include <pom-ng/ptype_bool.h>

struct mod_reg_info* output_file_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = output_file_mod_register;
	reg_info.unregister_func = output_file_mod_unregister;
	reg_info.dependencies = "ptype_bool, ptype_string";

	return &reg_info;

}

int output_file_mod_register(struct mod_reg *mod) {


	static struct output_reg_info output_file;
	memset(&output_file, 0, sizeof(struct output_reg_info));
	output_file.name = "file";
	output_file.api_ver = OUTPUT_API_VER;
	output_file.mod = mod;

	output_file.init = output_file_init;
	output_file.open = output_file_open;
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
	output_set_priv(o, priv);

	priv->p_listen_pload_evt = ptype_alloc("bool");
	priv->p_path = ptype_alloc("string");

	if (!priv->p_path)
		goto err;

	
	struct registry_param *p = registry_new_param("listen_pload_events", "no", priv->p_listen_pload_evt, "Listen to all events that generate payloads", 0);
	if (output_instance_add_param(o, p) != POM_OK)
		goto err;

	p = registry_new_param("path", "/tmp/", priv->p_path, "Path where to store the files", 0);
	if (output_instance_add_param(o, p) != POM_OK)
		goto err;
	
	priv->output_reg.open = output_file_pload_open;
	priv->output_reg.write = output_file_pload_write;
	priv->output_reg.close = output_file_pload_close;

	return POM_OK;
err:
	output_file_cleanup(priv);
	return POM_ERR;

}

int output_file_cleanup(void *output_priv) {

	struct output_file_priv *priv = output_priv;
	if (priv) {
		if (priv->p_listen_pload_evt)
			ptype_cleanup(priv->p_listen_pload_evt);
		if (priv->p_path)
			ptype_cleanup(priv->p_path);
		free(priv);

	}

	return POM_OK;
}

int output_file_open(void *output_priv) {

	struct output_file_priv *priv = output_priv;

	char *listen_pload_evt = PTYPE_BOOL_GETVAL(priv->p_listen_pload_evt);
	if (*listen_pload_evt && event_payload_listen_start() != POM_OK)
		return POM_ERR;
		

	return analyzer_pload_output_register(priv, &priv->output_reg);

}

int output_file_close(void *output_priv) {

	if (analyzer_pload_output_unregister(output_priv) != POM_OK)
		return POM_ERR;
	
	struct output_file_priv *priv = output_priv;

	char *listen_pload_evt = PTYPE_BOOL_GETVAL(priv->p_listen_pload_evt);
	if (*listen_pload_evt)
		event_payload_listen_stop();

	return POM_OK;
}


int output_file_pload_open(struct analyzer_pload_instance *pi, void *output_priv) {

	struct output_file_priv *priv = output_priv;

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

	analyzer_pload_instance_set_priv(pi, ppriv);

	return POM_OK;

}

int output_file_pload_write(void *pload_instance_priv, void *data, size_t len) {


	struct output_file_pload_priv *ppriv = pload_instance_priv;
	int res = pom_write(ppriv->fd, data, len);
	if (res == POM_ERR)
		pomlog(POMLOG_ERR "Error while writing to file %s : %s", ppriv->filename, pom_strerror(errno));

	return res;

}

int output_file_pload_close(void *pload_instance_priv) {

	struct output_file_pload_priv *ppriv = pload_instance_priv;
	int fd = ppriv->fd;
	pomlog(POMLOG_DEBUG "File %s closed", ppriv->filename);
	free(ppriv->filename);
	free(ppriv);

	return close(fd);
}

