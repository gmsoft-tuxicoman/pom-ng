/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __DNS_H__
#define __DNS_H__

#define DNS_TABLE_DEFAULT_SIZE 16384

#define DNS_GARBAGE_COLLECTOR_TIMEOUT 60

// Maximum lookup depth
#define DNS_MAX_LOOKUP_DEPTH	16

// Restrict maximum caching time to one day
#define DNS_TTL_MAX (60 * 60 * 24)

#include <pom-ng/ptype.h>
#include <pom-ng/event.h>

struct dns_entry_list {

	struct dns_entry *entry;
	struct dns_entry_list *prev, *next;

};

struct dns_entry {

	char *record;
	ptime expiry;

	// Query for which this record is a value
	struct dns_entry_list *query;

	// Values for which this record is a query
	struct dns_entry_list *values;

	// Cache stuff
	unsigned int cache_queue;
	struct dns_entry *cache_prev, *cache_next;

	// Prev/Next values in the hash table
	struct dns_entry *prev, *next;

};

int dns_init();
int dns_core_init();
int dns_core_cleanup();

int dns_gc(void *priv, ptime now);
int dns_process_event(struct event *evt, void *obj);


#endif
