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

#include "analyzer.h"
#include "output.h"
#include "mod.h"
#include "input_server.h"

static struct analyzer_reg *analyzer_head = NULL;
static struct analyzer_data_source *analyzer_source_head = NULL;
static pthread_mutex_t analyzer_lock = PTHREAD_MUTEX_INITIALIZER;

int analyzer_register(struct analyzer_reg_info *reg_info) {

	if (reg_info->api_ver != ANALYZER_API_VER) {
		pomlog(POMLOG_ERR "Cannot register analyzer as API version differ : expected %u got %u", ANALYZER_API_VER, reg_info->api_ver);
		return POM_ERR;
	}

	if (input_server_is_current_process()) {
		pomlog(POMLOG_DEBUG "Not loading analyzer %s in the input process", reg_info->name);
		return POM_OK;
	}

	pom_mutex_lock(&analyzer_lock);

	// Allocate the analyzer
	struct analyzer_reg *analyzer = malloc(sizeof(struct analyzer_reg));
	if (!analyzer) {
		pom_mutex_unlock(&analyzer_lock);
		pom_oom(sizeof(struct analyzer_reg));
		return POM_ERR;
	}
	memset(analyzer, 0, sizeof(struct analyzer_reg));
	analyzer->info = reg_info;

	if (reg_info->init) {
		if (reg_info->init(analyzer) != POM_OK) {
			pom_mutex_unlock(&analyzer_lock);
			free(analyzer);
			pomlog(POMLOG_ERR "Error while initializing analyzer %s", reg_info->name);
			return POM_ERR;
		}
	}

	analyzer->next = analyzer_head;
	if (analyzer->next)
		analyzer->next->prev = analyzer;
	analyzer_head = analyzer;
	pom_mutex_unlock(&analyzer_lock);
	
	mod_refcount_inc(reg_info->mod);

	return POM_OK;
}

int analyzer_unregister(char *name) {

	pom_mutex_lock(&analyzer_lock);
	struct analyzer_reg *tmp;
	for (tmp = analyzer_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp) {
		pom_mutex_unlock(&analyzer_lock);
		pomlog(POMLOG_DEBUG "Analyzer %s is not registered, cannot unregister it", name);
		return POM_OK;
	}

	if (tmp->info->cleanup) {
		if (tmp->info->cleanup(tmp) != POM_OK) {
			pomlog(POMLOG_ERR "Error while cleaning up analyzer %s", name);
			return POM_ERR;
		}
	}

	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		analyzer_head = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	mod_refcount_dec(tmp->info->mod);
	
	free(tmp);

	pom_mutex_unlock(&analyzer_lock);

	return POM_OK;
}

int analyzer_cleanup() {
	
	pom_mutex_lock(&analyzer_lock);

	while (analyzer_source_head)  {
		struct analyzer_data_source *tmp = analyzer_source_head;
		analyzer_source_head = tmp->next;
		if (tmp->outs) {
			pomlog(POMLOG_WARN "Warning, some output are still attached to this analyzer");
			conntrack_con_unregister_analyzer(tmp->proto->proto, tmp->analyzer);
		}

		proto_remove_dependency(tmp->proto);
		free(tmp->name);
		free(tmp);

	}

	while (analyzer_head) {

		struct analyzer_reg *tmp = analyzer_head;
		analyzer_head = tmp->next;

		if (tmp->info->cleanup) {
			if (tmp->info->cleanup(tmp))
				pomlog(POMLOG_WARN "Error while cleaning up analyzer %s", tmp->info->name);
		}

		mod_refcount_dec(tmp->info->mod);

		free(tmp);
	}

	pom_mutex_unlock(&analyzer_lock);

	return POM_OK;

}

struct analyzer_data_source *analyzer_register_data_conntrack_source(struct analyzer_reg *analyzer, char *name, struct analyzer_data_reg *datas, char *proto, int (*process) (struct analyzer_reg *analyzer, struct proto_process_stack *stack, unsigned int stack_index)) {

	struct analyzer_data_source *res = malloc(sizeof(struct analyzer_data_source));
	if (!res) {
		pom_oom(sizeof(struct analyzer_data_source));
		return NULL;
	}
	memset(res, 0, sizeof(struct analyzer_data_source));

	res->name = strdup(name);
	if (!res->name) {
		free(res);
		pom_oom(strlen(name));
		return NULL;
	}

	res->proto = proto_add_dependency(proto);
	if (!res->proto) {
		free(res->name);
		free(res);
		return NULL;
	}

	res->analyzer = analyzer;
	res->data_reg = datas;
	res->process = process;

	res->next = analyzer_source_head;
	analyzer_source_head = res;

	return res;
}

struct analyzer_data_source *analyzer_data_source_get(char *source) {

	struct analyzer_data_source *src = analyzer_source_head;
	for (; src && strcmp(src->name, source); src  = src->next);

	return src;

}

int analyzer_data_source_register_output(struct analyzer_data_source *src, struct output *o) {

	if (!src->outs) {
		// No output yet, we need to register the data source to the conntrack_con_info
		if (conntrack_con_register_analyzer(src->proto->proto, src->analyzer, src->process) != POM_OK) {
			pomlog(POMLOG_ERR "Error while registering analyzer data source %s to conntrack connection info %s", src->name, src->proto->name);
			return POM_ERR;
		}

	}

	struct analyzer_output_list *output_list = malloc(sizeof(struct analyzer_output_list));
	if (!output_list) {
		pom_oom(sizeof(struct analyzer_output_list));
		return POM_ERR;
	}
	memset(output_list, 0, sizeof(struct analyzer_output_list));

	output_list->o = o;
	output_list->next = src->outs;
	if (output_list->next)
		output_list->next->prev = output_list;
	src->outs = output_list;

	return POM_OK;
}

int analyzer_data_source_unregister_output(struct analyzer_data_source *src, struct output *o) {

	struct analyzer_output_list *tmp = src->outs;

	for (; tmp && tmp->o != o; tmp = tmp->next);

	if (!tmp) {
		pomlog(POMLOG_ERR "Output %s is not registered to data source %s", o->name, src->name);
		return POM_ERR;
	}

	if (tmp->next)
		tmp->next->prev = tmp->prev;
	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		src->outs = tmp->next;
	
	free(tmp);

	if (!src->outs) {
		// No output registered to this analyzer, unregister from the conntrack then
		if (conntrack_con_unregister_analyzer(src->proto->proto, src->analyzer) != POM_OK)
			return POM_ERR;
	}

	return POM_OK;
}

int analyzer_data_source_process(struct analyzer_data_source *src, struct analyzer_data *data) {

	struct analyzer_output_list *tmp = src->outs;
	while (tmp) {
		if (tmp->o->info->reg_info->process(tmp->o, data) != POM_OK) {
			pomlog(POMLOG_ERR "Error while processing data_source %s for output %s", src->name, tmp->o->name);
			return POM_ERR;
		}
		tmp = tmp->next;
	}

	return POM_OK;

}
