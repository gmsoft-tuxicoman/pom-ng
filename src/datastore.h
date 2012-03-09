/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __DATASTORE_H__
#define __DATASTORE_H__

#include <pom-ng/datastore.h>

#define DATASTORE_REGISTRY "datastore"

/// Name of the table containing the datasets
#define DATASTORE_DATASET_TABLE "datasets"

/// Name of the table containing the schema of the datasets
#define DATASTORE_DATASET_SCHEMA_TABLE "dataset_schema"

struct datastore_reg {

	struct datastore_reg_info *info;
	struct mod_reg *module;
	unsigned int refcount;

	struct datastore_reg *next, *prev;

};


int datastore_init();
int datastore_cleanup();

int datastore_instance_add(char *type, char *name);
int datastore_instance_remove(struct registry_instance *ri);

int datastore_open(struct datastore *d);
int datastore_close(struct datastore *d);

struct dataset *datastore_dataset_alloc(struct datastore *d, struct datavalue_template *dt, char *name);
struct dataset *datastore_dataset_open(struct datastore *d, char *name, struct datavalue_template *dt, struct datastore_connection *dc);
int datastore_dataset_cleanup(struct dataset *ds);
int datastore_dataset_create(struct dataset *ds, struct datastore_connection *dc);


#endif
