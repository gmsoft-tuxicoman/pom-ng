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


	static struct output_reg_info output_file = { 0 };
	output_file.name = "file";
	output_file.description = "Save payloads to files on the disk";
	output_file.mod = mod;

	output_file.init = output_file_init;
	output_file.open = output_file_open;
	output_file.close = output_file_close;
	output_file.cleanup = output_file_cleanup;

	static struct addon_plugin_pload_reg addon_file = { 0 };
	addon_file.name = "file";
	addon_file.mod = mod;

	addon_file.pload_open = addon_file_pload_open;
	addon_file.pload_write = output_file_pload_write;
	addon_file.pload_close = output_file_pload_close;

	static struct addon_pload_param_reg params[] = {
		{ "filename", "string" },
		{ 0 }
	};

	addon_file.pload_params = params;


	if (output_register(&output_file) != POM_OK ||
		addon_plugin_pload_register(&addon_file) != POM_OK) {
		output_file_mod_unregister();
		return POM_ERR;
	}

	return POM_OK;
}

int output_file_mod_unregister() {

	int res = POM_OK;

	res += output_unregister("file");
	res += addon_plugin_unregister("file");

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

	if (!priv->p_path || !priv->p_listen_pload_evt)
		goto err;

	struct registry_instance *inst = output_get_reg_instance(o);
	priv->perf_files_closed = registry_instance_add_perf(inst, "files_closed", registry_perf_type_counter, "Number of files fully written and closed", "files");
	priv->perf_files_open = registry_instance_add_perf(inst, "files_open", registry_perf_type_gauge, "Number of files currently open", "files");
	priv->perf_bytes_written = registry_instance_add_perf(inst, "bytes_written", registry_perf_type_counter, "Number of bytes written", "bytes");

	if (!priv->perf_files_closed || !priv->perf_files_open || !priv->perf_bytes_written)
		goto err;

	struct registry_param *p = registry_new_param("listen_pload_events", "no", priv->p_listen_pload_evt, "Listen to all events that generate payloads", 0);
	if (output_add_param(o, p) != POM_OK)
		goto err;

	p = registry_new_param("path", "/tmp/", priv->p_path, "Path where to store the files", 0);
	if (output_add_param(o, p) != POM_OK)
		goto err;
	
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
		

	return pload_listen_start(output_priv, NULL, NULL, output_file_pload_open, output_file_pload_write, output_file_pload_close);

}

int output_file_close(void *output_priv) {

	if (pload_listen_stop(output_priv, NULL) != POM_OK)
		return POM_ERR;

	struct output_file_priv *priv = output_priv;

	char *listen_pload_evt = PTYPE_BOOL_GETVAL(priv->p_listen_pload_evt);
	if (*listen_pload_evt)
		event_payload_listen_stop();

	return POM_OK;
}

static int file_pload_open(struct output_file_priv *output_priv, const char *filename, void **pload_priv) {

	// Create the private structure for the payload
	struct output_file_pload_priv *ppriv = malloc(sizeof(struct output_file_pload_priv));
	if (!ppriv) {
		pom_oom(sizeof(struct output_file_pload_priv));
		return POM_ERR;
	}
	memset(ppriv, 0, sizeof(struct output_file_pload_priv));

	ppriv->filename = strdup(filename);
	if (!ppriv->filename) {
		free(ppriv);
		pom_oom(strlen(filename) + 1);
		return POM_ERR;
	}

	ppriv->fd = pom_open(filename, O_WRONLY | O_CREAT, 0666);
	if (ppriv->fd == -1) {
		free(ppriv);
		return POM_ERR;
	}

	if (output_priv && output_priv->perf_files_open)
		registry_perf_inc(output_priv->perf_files_open, 1);
		

	pomlog(POMLOG_DEBUG "File %s open", ppriv->filename);

	*pload_priv = ppriv;

	return POM_OK;
}


int output_file_pload_open(void *obj, void **ppriv, struct pload *pload) {

	struct output_file_priv *priv = obj;

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

	return file_pload_open(obj, filename, ppriv);

}

int addon_file_pload_open(void *output_priv, void **priv, struct pload *pload, struct ptype *params[]) {

	char *filename = PTYPE_STRING_GETVAL(params[0]);
	return file_pload_open(output_priv, filename, priv);
}


int output_file_pload_write(void *output_priv, void *pload_instance_priv, void *data, size_t len) {

	struct output_file_priv *priv = output_priv;
	struct output_file_pload_priv *ppriv = pload_instance_priv;
	int res = pom_write(ppriv->fd, data, len);
	if (res == POM_ERR)
		pomlog(POMLOG_ERR "Error while writing to file %s : %s", ppriv->filename, pom_strerror(errno));
	else if (priv && priv->perf_bytes_written)
		registry_perf_inc(priv->perf_bytes_written, len);
		

	return res;

}

int output_file_pload_close(void *output_priv, void *pload_instance_priv) {

	struct output_file_pload_priv *ppriv = pload_instance_priv;
	int fd = ppriv->fd;
	pomlog(POMLOG_DEBUG "File %s closed", ppriv->filename);
	free(ppriv->filename);
	free(ppriv);

	struct output_file_priv *priv = output_priv;
	if (priv) {
		if (priv->perf_files_open)
			registry_perf_dec(priv->perf_files_open, 1);
		if (priv->perf_files_closed)
			registry_perf_inc(priv->perf_files_closed, 1);
	}

	return close(fd);
}

