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

struct analyzer_reg_info {

	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;

	int (*init) (struct analyzer_reg *analyzer);
	int (*cleanup) (struct analyzer_reg *analyzer);

};

struct analyzer_conntrack_reg_info {

	char *proto;
//	int (*conntrack_process) (struct proto_process_stack *s, unsigned int stack_index);

};

struct analyzer_data_source {

	char *name;
	struct analyzer_reg *analyzer;
	struct analyzer_data_reg *data_reg;
	struct analyzer_output_list *outs;

	struct proto_dependency *proto;
	
	// Process function of the analyzer
	int (*process) (struct analyzer_reg *analyzer, struct proto_process_stack *stack, unsigned int stack_index);

	struct analyzer_data_source *next;

};

struct analyzer_data {
	
	union {
		struct ptype *value;
		struct conntrack_con_info_lst *lst;
	};
};

struct analyzer_output_list {
	struct output *o;
	int (*process) (struct output *output, struct analyzer_data *data);
	struct analyzer_output_list *prev, *next;
};

struct analyzer_data_reg {
	int flags;
	char *name;
};

int analyzer_register(struct analyzer_reg_info *reg_info);
int analyzer_unregister(char *name);
struct analyzer_data_source *analyzer_register_data_conntrack_source(struct analyzer_reg *analyzer, char *name, struct analyzer_data_reg *datas, char *proto, int (*process) (struct analyzer_reg *analyzer, struct proto_process_stack *stack, unsigned int stack_index));
int analyzer_data_source_register_output(struct analyzer_data_source *src, struct output *o);
int analyzer_data_source_unregister_output(struct analyzer_data_source *src, struct output *o);
struct analyzer_data_source *analyzer_data_source_get(char *source);
int analyzer_data_source_process(struct analyzer_data_source *src, struct analyzer_data *data);

#endif
