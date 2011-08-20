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


#include "output_log_xml.h"

#include <pom-ng/ptype_string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int output_log_xml_init(struct output *o) {


	struct output_log_xml_priv *priv = malloc(sizeof(struct output_log_xml_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_log_xml_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct output_log_xml_priv));
	o->priv = priv;

	priv->fd = -1;
	
	priv->p_filename = ptype_alloc("string");
	priv->p_source = ptype_alloc("string");

	if (!priv->p_filename || !priv->p_source)
		goto err;

	struct registry_param *p = registry_new_param("filename", "log.xml", priv->p_filename, "XML log file", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("source", "", priv->p_source, "Define the type of event being logged", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;

	return POM_OK;

err:
	output_log_xml_cleanup(o);
	return POM_ERR;

}


int output_log_xml_cleanup(struct output *o) {
	
	struct output_log_xml_priv *priv = o->priv;
	if (priv) {
		if (priv->fd != -1)
			close(priv->fd);
		if (priv->p_filename)
			ptype_cleanup(priv->p_filename);
		if (priv->p_source)
			ptype_cleanup(priv->p_source);
		free(priv);
	}

	return POM_OK;
}


int output_log_xml_open(struct output *o) {

	struct output_log_xml_priv *priv = o->priv;

	if (priv->fd != -1) {
		pomlog(POMLOG_ERR "Output already started");
		return POM_ERR;
	}

	char *src_name = PTYPE_STRING_GETVAL(priv->p_source);
	if (!strlen(src_name)) {
		pomlog(POMLOG_ERR "You need to specify a source for this output");
		return POM_ERR;
	}

	priv->evt = analyzer_event_get(src_name);

	if (!priv->evt) {
		pomlog(POMLOG_ERR "Source \"%s\" does not exists", src_name);
		return POM_ERR;
	}

	char *filename = PTYPE_STRING_GETVAL(priv->p_filename);
	if (!strlen(filename)) {
		pomlog(POMLOG_ERR "You must specify a filename where to log the output");
		return POM_ERR;
	}

	priv->fd = open(filename, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
	if (!priv->fd == -1) {
		pomlog(POMLOG_ERR "Error while opening log file \"%s\" : %s", filename, pom_strerror(errno));
		return POM_ERR;
	}

	// Listen on the right event
	static struct analyzer_event_listener listener;
	listener.name = o->name;
	listener.obj = o;
	listener.process = output_log_xml_process;

	if (analyzer_event_register_listener(priv->evt, &listener) != POM_OK)
		goto err;

	return POM_OK;

err:
	if (priv->fd != -1) {
		close(priv->fd);
		priv->fd = -1;
	}

	priv->evt = NULL;


	return POM_ERR;

}


int output_log_xml_close(struct output *o) {

	struct output_log_xml_priv *priv = o->priv;

	if (priv->fd == -1) {
		pomlog(POMLOG_ERR "Output already stopped");
		return POM_ERR;
	}

	analyzer_event_unregister_listener(priv->evt, o->name);

	if (close(priv->fd)) {
		pomlog(POMLOG_ERR "Error while closing log file : %s", pom_strerror(errno));
		return POM_ERR;
	}

	return POM_OK;
}


int output_log_xml_process(void *obj, struct analyzer_event *evt) {

	// TODO/FIXME MUST HTML ENCODE THE VALUES !!!!

	struct output *o = obj;
	struct output_log_xml_priv *priv = o->priv;

	const unsigned int buff_size = 4096;
	char buffer[buff_size + 1];

	// <event name="event_name">\n
	strcpy(buffer, "<event name=\"");
	strncat(buffer, evt->info->name, buff_size - strlen(buffer));
	strncat(buffer, "\">\n", buff_size - strlen(buffer));
	if (pom_write(priv->fd, buffer, strlen(buffer)) != POM_OK)
		return POM_ERR;

	unsigned int i;
	for (i = 0; evt->info->data[i].name; i++) {
		if (evt->info->data[i].flags & ANALYZER_DATA_FLAG_LIST) {
			// Got a param_list
		
			if (!evt->data[i].items)
				continue;

			// <param_list name="param_name">
			strcpy(buffer, "\t<param_list name=\"");
			strncat(buffer, evt->info->data[i].name, buff_size - strlen(buffer));
			strncat(buffer, "\">\n", buff_size - strlen(buffer));

			if (pom_write(priv->fd, buffer, strlen(buffer)) != POM_OK)
				return POM_ERR;

			// <value key="key1">value1</value>
			analyzer_data_item_t *itm = evt->data[i].items;
			for (; itm; itm = itm->next) {
				strcpy(buffer, "\t\t<value key=\"");
				strncat(buffer, itm->key, buff_size - strlen(buffer));
				strncat(buffer, "\">", buff_size - strlen(buffer));

				if (pom_write(priv->fd, buffer, strlen(buffer)) != POM_OK)
					return POM_ERR;

				if (ptype_print_val(itm->value, buffer, buff_size) < 0)
					return POM_ERR;

				if (pom_write(priv->fd, buffer, strlen(buffer)) != POM_OK)
					return POM_ERR;

				if (pom_write(priv->fd, "</value>\n", strlen("</value>\n")) != POM_OK)
					return POM_ERR;

			}

			if (pom_write(priv->fd, "\t</param_list>\n", strlen("\t</param_list>\n")) != POM_OK)
				return POM_ERR;


		} else {

			// Got a single param
			
			if (!evt->data[i].value)
				continue;

			
			// <param name="param_name">value</param>
			strcpy(buffer, "\t<param name=\"");
			strncat(buffer, evt->info->data[i].name, buff_size - strlen(buffer));
			strncat(buffer, "\">", buff_size - strlen(buffer));
			if (pom_write(priv->fd, buffer, strlen(buffer)) != POM_OK)
				return POM_ERR;

			if (ptype_print_val(evt->data[i].value, buffer, buff_size) < 0)
				return POM_ERR;

			if (pom_write(priv->fd, buffer, strlen(buffer)) != POM_OK)
				return POM_ERR;

			if (pom_write(priv->fd, "</param>\n", strlen("</param>\n")) != POM_OK)
				return POM_ERR;
		}
	}

	if (pom_write(priv->fd, "</event>\n\n", strlen("</event>\n\n")) != POM_OK)
		return POM_ERR;

	return POM_OK;

}
