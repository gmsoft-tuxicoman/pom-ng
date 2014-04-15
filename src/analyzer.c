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

#include "analyzer.h"
#include "mod.h"
#include "common.h"
#include "registry.h"



static struct analyzer *analyzer_head = NULL;

static struct registry_class *analyzer_registry_class = NULL;



int analyzer_init() {


	analyzer_registry_class = registry_add_class(ANALYZER_REGISTRY);
	if (!analyzer_registry_class)
		return POM_ERR;

	return POM_OK;

}

int analyzer_register(struct analyzer_reg *reg_info) {

	// Allocate the analyzer
	struct analyzer *analyzer = malloc(sizeof(struct analyzer));
	if (!analyzer) {
		pom_oom(sizeof(struct analyzer));
		return POM_ERR;
	}
	memset(analyzer, 0, sizeof(struct analyzer));
	analyzer->info = reg_info;

	analyzer->reg_instance = registry_add_instance(analyzer_registry_class, reg_info->name);
	if (!analyzer->reg_instance) {
		free(analyzer);
		return POM_ERR;
	}

	if (reg_info->init) {
		if (reg_info->init(analyzer) != POM_OK) {
			registry_remove_instance(analyzer->reg_instance);
			free(analyzer);
			pomlog(POMLOG_ERR "Error while initializing analyzer %s", reg_info->name);
			return POM_ERR;
		}
	}

	analyzer->next = analyzer_head;
	if (analyzer->next)
		analyzer->next->prev = analyzer;
	analyzer_head = analyzer;
	
	mod_refcount_inc(reg_info->mod);

	pomlog(POMLOG_DEBUG "Analyzer %s registered", reg_info->name);

	return POM_OK;
}

int analyzer_unregister(char *name) {

	struct analyzer *tmp;
	for (tmp = analyzer_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp)
		return POM_OK;

	if (tmp->info->cleanup) {
		if (tmp->info->cleanup(tmp) != POM_OK) {
			pomlog(POMLOG_ERR "Error while cleaning up analyzer %s", name);
			return POM_ERR;
		}
	}

	registry_remove_instance(tmp->reg_instance);

	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		analyzer_head = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	mod_refcount_dec(tmp->info->mod);
	
	free(tmp);

	return POM_OK;
}

int analyzer_cleanup() {
	
	while (analyzer_head) {

		struct analyzer *tmp = analyzer_head;
		analyzer_head = tmp->next;

		if (tmp->info->cleanup) {
			if (tmp->info->cleanup(tmp))
				pomlog(POMLOG_WARN "Error while cleaning up analyzer %s", tmp->info->name);
		}

		mod_refcount_dec(tmp->info->mod);

		free(tmp);
	}

	registry_remove_class(analyzer_registry_class);
	analyzer_registry_class = NULL;

	return POM_OK;

}

int analyzer_finish() {

	struct analyzer *tmp;
	for (tmp = analyzer_head; tmp; tmp = tmp->next) {
		if (tmp->info->finish && tmp->info->finish(tmp) != POM_OK)
			pomlog(POMLOG_WARN "Error while running the finish() function of analyzer %s", tmp->info->name);
	}

	return POM_OK;
}


