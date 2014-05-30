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


#ifndef __POM_NG_ANALYZER_H__
#define __POM_NG_ANALYZER_H__

#include <pom-ng/registry.h>

struct analyzer {

	struct analyzer_reg *info;
	void *priv;
	struct registry_instance *reg_instance;

	struct analyzer *prev, *next;

};

struct analyzer_reg {

	char *name;
	struct mod_reg *mod;

	int (*init) (struct analyzer *analyzer);
	int (*cleanup) (struct analyzer *analyzer);
	int (*finish) (struct analyzer *analyzer);

};


int analyzer_register(struct analyzer_reg *reg_info);
int analyzer_unregister(char *name);
int analyzer_add_param(struct analyzer *a, struct registry_param *p);

#endif
