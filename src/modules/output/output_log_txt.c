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


#include "output_log_txt.h"

#include <pom-ng/ptype_string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



int output_log_txt_init(struct output *o) {

	struct output_log_txt_priv *priv = malloc(sizeof(struct output_log_txt_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_log_txt_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct output_log_txt_priv));
	o->priv = priv;

	priv->fd = -1;

	priv->p_filename = ptype_alloc("string");
	priv->p_source = ptype_alloc("string");
	priv->p_format = ptype_alloc("string");
	if (!priv->p_filename || !priv->p_source || !priv->p_format)
		goto err;

	struct registry_param *p = registry_new_param("filename", "log.txt", priv->p_filename, "Log file", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;
	
	p = registry_new_param("source", "", priv->p_source, "Define the type of event being logged", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("format", "", priv->p_format, "Format of each log line", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;


	return POM_OK;
err:

	output_log_txt_cleanup(o);
	return POM_ERR;
}

int output_log_txt_cleanup(struct output *o) {

	struct output_log_txt_priv *priv = o->priv;
	if (priv) {
		if (priv->fd != -1)
			close(priv->fd);
		if (priv->p_filename)
			ptype_cleanup(priv->p_filename);
		if (priv->p_source)
			ptype_cleanup(priv->p_source);
		if (priv->p_format)
			ptype_cleanup(priv->p_format);
		free(priv);
	}

	return POM_OK;
}

int output_log_txt_open(struct output *o) {

	struct output_log_txt_priv *priv = o->priv;
	struct output_log_parsed_field *fields = NULL;

	if (priv->fd != -1) {
		pomlog(POMLOG_ERR "Output already started");
		return POM_ERR;
	}

	char *src_name = PTYPE_STRING_GETVAL(priv->p_source);
	if (!strlen(src_name)) {
		pomlog(POMLOG_ERR "You need to specify a source for this output");
		return POM_ERR;
	}

	priv->evt = event_find(src_name);

	if (!priv->evt) {
		pomlog(POMLOG_ERR "Source \"%s\" does not exists", src_name);
		return POM_ERR;
	}

	// Parse the format
	char *format = PTYPE_STRING_GETVAL(priv->p_format);

	if (!strlen(format)) {
		pomlog(POMLOG_ERR "You must specify the format of the logs");
		goto err;
	}

	unsigned int field_count = 0;
	char *sep = NULL, *cur = format;
	while ((sep = strchr(cur, '$'))) {
		unsigned int start_off = sep - format;
		sep++;
		cur = sep;
		while ((*cur >= '0' && *cur <= '9') || (*cur >= 'a' && *cur <= 'z') || *cur == '_')
			cur++;
		unsigned int end_off = cur - format;
		char name[256];
		memset(name, 0, sizeof(name));
		strncpy(name, sep, end_off - start_off - 1);
		
		struct event_data_reg *dreg = priv->evt->info->data_reg;
		int i;
		for (i = 0; i < priv->evt->info->data_count && strcmp(dreg[i].name, name); i++);

		if (!dreg[i].name) {
			pomlog(POMLOG_WARN "Field %s not found in data source %s", name, src_name);
			sep = cur + 1;
			continue;
		}
		// TODO add support for arrays

		field_count++;
		fields = realloc(fields, sizeof(struct output_log_parsed_field) * (field_count + 1));
		if (!fields) {
			pom_oom(sizeof(struct output_log_parsed_field *) * (field_count + 1));
			goto err;
		}
		memset(&fields[field_count - 1], 0, sizeof(struct output_log_parsed_field) * 2);
		struct output_log_parsed_field *field = &fields[field_count - 1];
		field->id = i;
		field->start_off = start_off;
		field->end_off = end_off;
		
	}

	if (!fields) {
		pomlog(POMLOG_ERR "No field found in format string : \"%s\"", format);
		goto err;
	}

	priv->field_count = field_count;
	priv->parsed_fields = fields;


	char *filename = PTYPE_STRING_GETVAL(priv->p_filename);
	if (!strlen(filename)) {
		pomlog(POMLOG_ERR "You must specify a filename where to log the output");
		goto err;
	}

	priv->fd = open(filename, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
	if (priv->fd == -1) {
		pomlog(POMLOG_ERR "Error while opening log file \"%s\" : %s", filename, pom_strerror(errno));
		goto err;
	}

	// Register this input as a listener for the right event
	static struct event_listener listener;
	memset(&listener, 0, sizeof(struct event_listener));
	listener.obj = o;
	listener.process_end = output_log_txt_process;
		
	if (event_listener_register(priv->evt, &listener) != POM_OK)
		goto err;

	return POM_OK;

err:
	if (fields)
		free(fields);

	if (priv->fd != -1) {
		close(priv->fd);
		priv->fd = -1;
	}

	priv->field_count = 0;
	priv->parsed_fields = NULL;
	priv->evt = NULL;

	return POM_ERR;
}

int output_log_txt_close(struct output *o) {
	
	struct output_log_txt_priv *priv = o->priv;
	
	if (priv->fd == -1) {
		pomlog(POMLOG_ERR "Output already stopped");
		return POM_ERR;
	}

	if (priv->parsed_fields) {
		free(priv->parsed_fields);
		priv->field_count = 0;
	}

	event_listener_unregister(priv->evt, o);

	if (close(priv->fd)) {
		pomlog(POMLOG_ERR "Error while closing log file : %s", pom_strerror(errno));
		return POM_ERR;
	}

	return POM_OK;
}	

int output_log_txt_process(struct event *evt, void *obj) {

	struct output *o = obj;
	struct output_log_txt_priv *priv = o->priv;

	char *format = PTYPE_STRING_GETVAL(priv->p_format);

	int i;
	unsigned int pos = 0, format_pos = 0;
	char buff[4096];

	for (i = 0; i < priv->field_count && pos < sizeof(buff) - 2; i++) {
	
		struct output_log_parsed_field *field = &priv->parsed_fields[i];
		if (format_pos < field->start_off) {
			unsigned int len = field->start_off - format_pos;
			if (len > sizeof(buff) - 2 - pos)
				len = sizeof(buff) - 2 - pos;
			strncpy(buff + pos, format + format_pos, len);
			pos += len;
		}

		format_pos = field->end_off;

		if (evt->data[field->id].value) {
			pos += ptype_print_val(evt->data[field->id].value, buff + pos, sizeof(buff) - pos - 1);
		} else {
			buff[pos] = '-'; pos++;
		}
	}

	if (i == priv->field_count && pos < sizeof(buff) - 2) {
		if (format_pos < strlen(format)) {
			unsigned int len = strlen(format) - format_pos;
			if (len > sizeof(buff) - 2 - pos)
				len = sizeof(buff) - 2 - pos;
			strncpy(buff + pos, format + format_pos, len);
			pos += len;
		}
	}

	buff[pos] = '\n'; pos++;

	if (pom_write(priv->fd, buff, pos) != POM_OK) {
		pomlog(POMLOG_ERR "Error while writing to log file : %s", pom_strerror(errno));
		return POM_ERR;
	}

	return POM_OK;
}
