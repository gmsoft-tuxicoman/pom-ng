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
#include <pom-ng/param.h>

int param_list_add_entry(struct param_list **list_head, char *name, struct ptype *value, char *default_value, char *description) {

	if (!list_head || !name || !value || !default_value) 
		return POM_ERR;

	if (ptype_parse_val(value, default_value) == POM_ERR) {
		pomlog(POMLOG_ERR "Unable to parse default value \"%s\" for parameter %s", default_value, name);
		return POM_ERR;
	}

	struct param_entry *entry = malloc(sizeof(struct param_entry));
	if (!entry) {
		pomlog(POMLOG_ERR "Not enough memory to allocate struct param_entry");
		return POM_ERR;
	}
	memset(entry, 0, sizeof(struct param_entry));
	entry->name = name;
	entry->value = value;
	entry->default_value = default_value;
	entry->description = description;

	return param_list_add_entry2(list_head, entry);

};

int param_list_add_entry2(struct param_list **list_head, struct param_entry *entry) {

	struct param_list *tmp;
	for (tmp = *list_head; tmp && tmp->entry != entry; tmp = tmp->next);
	if (tmp) {
		pomlog(POMLOG_WARN "Entry %s already added", entry->name);
		return POM_ERR;
	}

	tmp = malloc(sizeof(struct param_list));
	if (!tmp) {
		pomlog(POMLOG_ERR "Not enough memory to allocate struct param_list");
		return POM_ERR;
	}
	memset(tmp, 0, sizeof(struct param_list));
	tmp->entry = entry;
	tmp->next = *list_head;
	if (tmp->next)
		tmp->next->prev = tmp;
	*list_head = tmp;

	return POM_OK;
}

int param_list_cleanup(struct param_list **list_head) {

	struct param_list *tmp = *list_head;

	while (*list_head) {
		tmp = *list_head;
		*list_head = (*list_head)->next;
		free(tmp->entry);
		free(tmp);
	}

	return POM_OK;
}
