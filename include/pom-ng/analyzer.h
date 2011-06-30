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


#ifndef __POM_NG_ANALYZER_H__
#define __POM_NG_ANALYZER_H__

#include <pom-ng/base.h>
#include <pom-ng/proto.h>
#include <pom-ng/conntrack.h>
#include <pom-ng/output.h>

// Current analyzer API version
#define ANALYZER_API_VER 1

struct analyzer_reg {

	struct analyzer_reg_info *info;
	void *priv;

	struct analyzer_reg *prev, *next;

};

struct analyzer_event_reg {

	char *name;
	struct analyzer_data_reg *data;
	unsigned int data_count;


	struct analyzer_reg *analyzer;
	int (*listeners_notify) (struct analyzer_reg *analyzer, struct analyzer_event_reg *event, int has_listeners);

	struct analyzer_event_listener_list *listeners;

};

struct analyzer_reg_info {

	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;

	int (*init) (struct analyzer_reg *analyzer);
	int (*cleanup) (struct analyzer_reg *analyzer);

	struct analyzer_event_reg *events;

};


struct analyzer_event {
	struct analyzer_event_reg *info;
	struct analyzer_data *data;
};

struct analyzer_event_listener {
	void *obj;
	char *name;
	int (*process) (void *listener_obj, struct analyzer_event *evt);
};

typedef struct proto_event_data_item analyzer_data_item_t;

struct analyzer_data {
	
	union {
		struct ptype *value;
		analyzer_data_item_t *items;
	};
};


struct analyzer_data_reg {
	int flags;
	char *name;
};

int analyzer_register(struct analyzer_reg_info *reg_info);
int analyzer_unregister(char *name);
struct analyzer_event_reg *analyzer_event_get(char *name);
int analyzer_event_process(struct analyzer_event *evt);

int analyzer_event_register_listener(struct analyzer_event_reg *evt, struct analyzer_event_listener *listener);
int analyzer_event_unregister_listener(struct analyzer_event_reg *evt, char *listener_name);

#endif
