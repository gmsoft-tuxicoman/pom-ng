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

#include "common.h"
#include "dns.h"
#include "core.h"
#include "jhash.h"

#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/timer.h>

#include <pom-ng/analyzer_dns.h>
#include <arpa/nameser.h>

#define INITVAL 0x4fb9a21b // random value

#undef DEBUG_DNS

#ifdef DEBUG_DNS
#define debug_dns(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_dns(x ...)
#define dns_check_cache()
#endif

static struct ptype_reg *ptype_string = NULL;

static pthread_mutex_t dns_table_lock = PTHREAD_MUTEX_INITIALIZER;

static struct event_reg *dns_record_evt = NULL;
static struct dns_entry **dns_table;

static struct timer *dns_gc_run = NULL;

static int dns_enabled = 0;

#define DNS_CACHE_QUEUE_COUNT	10

#define DNS_ADDITIONAL_TIMEOUT	300

static uint32_t dns_cache_queues_time[DNS_CACHE_QUEUE_COUNT] = {
	// Based on distribution observed in real life
	// See https://00f.net/2012/05/10/distribution-of-dns-ttls/
	60 + DNS_ADDITIONAL_TIMEOUT, // 1 min
	(2 * 60) + DNS_ADDITIONAL_TIMEOUT, // 2 min
	(5 * 60) + DNS_ADDITIONAL_TIMEOUT, // 5 min
	(30 * 60) + DNS_ADDITIONAL_TIMEOUT, // 30 min
	(60 * 60) + DNS_ADDITIONAL_TIMEOUT, // 1 hour
	(2 * 60 * 60) + DNS_ADDITIONAL_TIMEOUT, // 2 hours
	(4 * 60 * 60) + DNS_ADDITIONAL_TIMEOUT, // 4 hours
	(8 * 60 * 60) + DNS_ADDITIONAL_TIMEOUT, // 8 hours
	(12 * 60 * 60) + DNS_ADDITIONAL_TIMEOUT, // 12 hours
	(24 * 60 * 60) + DNS_ADDITIONAL_TIMEOUT // 1 day (capped max value)
};

static struct dns_entry *dns_cache_queues_head[DNS_CACHE_QUEUE_COUNT] = { 0 };
static struct dns_entry *dns_cache_queues_tail[DNS_CACHE_QUEUE_COUNT] = { 0 };
static struct registry_perf *dns_perf_cached_records = NULL;


#ifdef DEBUG_DNS

static int dns_check_cache() {

	unsigned count = 0, i;
	uint32_t expiry;
	struct dns_entry *tmp;
	for (i = 0; i < DNS_CACHE_QUEUE_COUNT; i++) {
		unsigned int queue_count = 0;
		expiry = 0;
		if ( (!dns_cache_queues_head[i] && dns_cache_queues_tail[i]) ||
			(dns_cache_queues_head[i] && !dns_cache_queues_tail[i])) {
			pomlog(POMLOG_ERR "Head/Tail missmatch");
			goto err;
		}

		for (tmp = dns_cache_queues_head[i]; tmp; tmp = tmp->cache_next) {
			if (!tmp->cache_next && dns_cache_queues_tail[i] != tmp) {
				pomlog(POMLOG_ERR "Tail doesn't match");
				goto err;
			}
			if (expiry > tmp->expiry) {
				pomlog(POMLOG_ERR "Expiry not growing");
				goto err;
			}
			queue_count++;
			count++;
			expiry = tmp->expiry;
		}
		debug_dns("Queue %u size is %u", i, queue_count);
	}

	return POM_OK;
err:
	return POM_ERR;

}
#endif

int dns_init() {
	dns_perf_cached_records = core_add_perf("dns_cached_records", registry_perf_type_gauge, "Number of cached DNS records", "records");
	if (!dns_perf_cached_records)
		return POM_ERR;
	return POM_OK;
}

int dns_core_init() {

	if (!ptype_string)
		ptype_string = ptype_get_type("string");

	if (!ptype_string)
		return POM_ERR;

	size_t dns_table_size = sizeof(struct dns_entry*) * DNS_TABLE_DEFAULT_SIZE;

	dns_table = malloc(dns_table_size);
	if (!dns_table) {
		pom_oom(dns_table_size);
		return POM_ERR;
	}
	memset(dns_table, 0, dns_table_size);
	
	dns_gc_run = timer_alloc(NULL, dns_gc);
	if (!dns_gc_run)
		goto err;

	dns_record_evt = event_find("dns_record");
	if (!dns_record_evt) {
		pomlog(POMLOG_ERR "Event dns_record not found. Is analyzer_dns registered ?");
		goto err;
	}

	if (event_listener_register(dns_record_evt, dns_table, NULL, dns_process_event, NULL) != POM_OK) {
		pomlog(POMLOG_ERR "Unable to listen to event dns_record");
		goto err;
	}

	timer_queue(dns_gc_run, DNS_GARBAGE_COLLECTOR_TIMEOUT);

	dns_enabled = 1;

	return POM_OK;

err:
	free(dns_table);

	if (dns_gc_run)
		timer_cleanup(dns_gc_run);
	return POM_ERR;
}


int dns_core_cleanup() {

	if (!dns_record_evt)
		return POM_OK;

	event_listener_unregister(dns_record_evt, dns_table);

	unsigned int i;
	for (i = 0; i < DNS_TABLE_DEFAULT_SIZE; i++) {
		while (dns_table[i]) {
			struct dns_entry *tmp = dns_table[i];

			while (tmp->query) {
				struct dns_entry_list *lst = tmp->query;
				tmp->query = lst->next;
				free(lst);
			}

			while (tmp->values) {
				struct dns_entry_list *lst = tmp->values;
				tmp->values = lst->next;
				free(lst);
			}

			dns_table[i] = tmp->next;
			free(tmp->record);
			free(tmp);
			registry_perf_dec(dns_perf_cached_records, 1);
		}
	}

	for (i = 0; i < DNS_CACHE_QUEUE_COUNT; i++) {
		dns_cache_queues_head[i] = NULL;
		dns_cache_queues_tail[i] = NULL;
	}
	free(dns_table);

	timer_cleanup(dns_gc_run);

	dns_enabled = 0;

	return POM_OK;
}


uint32_t dns_record_hash(const char *record) {
	return jhash(record, strlen(record), INITVAL) % DNS_TABLE_DEFAULT_SIZE;
}

int dns_gc(void *priv, ptime now) {

	pom_mutex_lock(&dns_table_lock);

	int i;
	for (i = 0; i < DNS_CACHE_QUEUE_COUNT; i++) {

		while (dns_cache_queues_head[i] && dns_cache_queues_head[i]->expiry < now) {

			// Remove the entry from the cache
			struct dns_entry *entry = dns_cache_queues_head[i];
			dns_cache_queues_head[i] = entry->cache_next;
			if (dns_cache_queues_head[i]) {
				dns_cache_queues_head[i]->cache_prev = NULL;
			} else {
				dns_cache_queues_tail[i] = NULL;
			}

			debug_dns("Clearing entry %s. Expiry %"PRIu64" < now %"PRIu64, entry->record, entry->expiry, now);

			while (entry->query) {
			
				struct dns_entry *query = entry->query->entry;

				// Remove references to this value from the queries
				struct dns_entry_list *tmp_value;
				for (tmp_value = query->values; tmp_value && tmp_value->entry != entry; tmp_value = tmp_value->next);
				if (!tmp_value) {
					pom_mutex_unlock(&dns_table_lock);
					pomlog(POMLOG_ERR "Value of the query not found");
					return POM_ERR;
				}

				if (tmp_value->next)
					tmp_value->next->prev = tmp_value->prev;
				
				if (tmp_value->prev)
					tmp_value->prev->next = tmp_value->next;
				else
					query->values = tmp_value->next;

				free(tmp_value);


				struct dns_entry_list *tmp = entry->query;
				entry->query = tmp->next;
				free(tmp);
			}

			while (entry->values) {
			
				struct dns_entry *value = entry->values->entry;

				// Remove references to this query from the values
				struct dns_entry_list *tmp_query;
				for (tmp_query = value->query; tmp_query && tmp_query->entry != entry; tmp_query = tmp_query->next);
				if (!tmp_query) {
					pom_mutex_unlock(&dns_table_lock);
					pomlog(POMLOG_ERR "Query of the value not found");
					return POM_ERR;
				}

				if (tmp_query->next)
					tmp_query->next->prev = tmp_query->prev;
				
				if (tmp_query->prev)
					tmp_query->prev->next = tmp_query->next;
				else
					value->query = tmp_query->next;

				free(tmp_query);


				struct dns_entry_list *tmp = entry->values;
				entry->values = tmp->next;
				free(tmp);
			}

			// Remove the entry from the hash table
			if (entry->next)
				entry->next->prev = entry->prev;
		
			if (entry->prev) {
				entry->prev->next = entry->next;
			} else {
				uint32_t hash = dns_record_hash(entry->record);
				dns_table[hash] = entry->next;
			}

			// Now cleanup the entry itself
			free(entry->record);
			free(entry);

			registry_perf_dec(dns_perf_cached_records, 1);
		}

	}

	dns_check_cache();

	pom_mutex_unlock(&dns_table_lock);

	// Requeue the timer
	timer_queue(dns_gc_run, DNS_GARBAGE_COLLECTOR_TIMEOUT);

	return POM_OK;
}

struct dns_entry *dns_find_or_add_entry(struct ptype *record_pt) {

	char *record = NULL;
	char buff[40] = { 0 };
	if (record_pt->type == ptype_string) {
		record = PTYPE_STRING_GETVAL(record_pt);
	} else {
		// 40 is the max size of an ipv6 address
		ptype_print_val(record_pt, buff, sizeof(buff), NULL);
		record = buff;
	}
	uint32_t hash = dns_record_hash(record);

	struct dns_entry *entry;

	for (entry = dns_table[hash]; entry; entry = entry->next) {
		if (!strcmp(entry->record, record))
			break;
	}

	if (entry)
		return entry;

	entry = malloc(sizeof(struct dns_entry));
	if (!entry) {
		pom_oom(sizeof(struct dns_entry));
		return NULL;
	}
	memset(entry, 0, sizeof(struct dns_entry));

	entry->record = strdup(record);
	if (!entry->record) {
		free(entry);
		pom_oom(strlen(record) + 1);
		return NULL;
	}
	entry->next = dns_table[hash];
	if (entry->next)
		entry->next->prev = entry;
	dns_table[hash] = entry;

	registry_perf_inc(dns_perf_cached_records, 1);

	return entry;
}

static int dns_update_expiry(struct dns_entry *a, struct dns_entry *b, uint32_t ttl) {

	ptime now = core_get_clock();

	ptime expiry = now + ((ttl + DNS_ADDITIONAL_TIMEOUT) * 1000000UL);

	if (a->expiry >= expiry) {
		a = NULL;
	}

	if (b->expiry >= expiry) {
		b = NULL;
	} else if (!a) {
		a = b;
		b = NULL;
	}

	// Find if there is actually something to do
	if (!a)
		return POM_OK;

	// Remove a from the cache
	if (a->expiry) {
		if (a->cache_prev) {
			a->cache_prev->cache_next = a->cache_next;
		} else {
			dns_cache_queues_head[a->cache_queue] = a->cache_next;
		}

		if (a->cache_next) {
			a->cache_next->cache_prev = a->cache_prev;
		} else {
			dns_cache_queues_tail[a->cache_queue] = a->cache_prev;
		}
		a->cache_prev = NULL;
		a->cache_next = NULL;
	}

	// Remove b from the cache
	if (b && b->expiry) {
		if (b->cache_prev) {
			b->cache_prev->cache_next = b->cache_next;
		} else {
			dns_cache_queues_head[b->cache_queue] = b->cache_next;
		}

		if (b->cache_next) {
			b->cache_next->cache_prev = b->cache_prev;
		} else {
			dns_cache_queues_tail[b->cache_queue] = b->cache_prev;
		}
		b->cache_prev = NULL;
		b->cache_next= NULL;
	}

	// Find in which queue this goes
	unsigned int q;
	for (q = 0; q < (DNS_CACHE_QUEUE_COUNT - 1) && dns_cache_queues_time[q] <= ttl; q++);

	// Find where it goes in the queue
	if (!dns_cache_queues_head[q]) {
		dns_cache_queues_head[q] = a;
		dns_cache_queues_tail[q] = a;
	} else {
		struct dns_entry *tmp;
		for (tmp = dns_cache_queues_tail[q]; tmp && (tmp->expiry > expiry); tmp = tmp->cache_prev);

		if (!tmp) { // Reached the begining
			a->cache_next = dns_cache_queues_head[q];
			if (a->cache_next)
				a->cache_next->cache_prev = a;
			dns_cache_queues_head[q] = a;
		} else { // Stopped somewhere in the list
			a->cache_prev = tmp;
			a->cache_next = tmp->cache_next;
			tmp->cache_next = a;
			if (a->cache_next)
				a->cache_next->cache_prev = a;
			else
				dns_cache_queues_tail[q] = a;
		}
	}
	a->cache_queue = q;
	a->expiry = expiry;

	if (b) {
		// Add b after a
		b->cache_prev = a;
		b->cache_next = a->cache_next;
		a->cache_next = b;
		
		if (b->cache_next) {
			b->cache_next->cache_prev = b;
		} else {
			dns_cache_queues_tail[q] = b;
		}
		b->cache_queue = q;
		b->expiry = expiry;
	}


	return POM_OK;
}

int dns_process_event(struct event *evt, void *obj) {

	struct data *evt_data = event_get_data(evt);

	// We need to save only a few record from the IN class

	// Check for IN class
	uint16_t cls = *PTYPE_UINT16_GETVAL(evt_data[analyzer_dns_record_class].value);
	if (cls != ns_c_in)
		return POM_OK;

	// Check for A, CNAME, AAAA, PTR
	uint16_t type = *PTYPE_UINT16_GETVAL(evt_data[analyzer_dns_record_type].value);
	if (type != ns_t_a && type != ns_t_cname && type != ns_t_aaaa && type != ns_t_ptr)
		return POM_OK;

	struct ptype *record = evt_data[analyzer_dns_record_values].items->value;

	if (!record) {
		pomlog(POMLOG_WARN "Record not found in DNS record event");
		return POM_OK;
	}

	uint32_t ttl = *PTYPE_UINT32_GETVAL(evt_data[analyzer_dns_record_ttl].value);

	if (ttl > DNS_TTL_MAX) // Restrict TTL to a maximum value
		ttl = DNS_TTL_MAX;

	pom_mutex_lock(&dns_table_lock);

	struct dns_entry *query = dns_find_or_add_entry(evt_data[analyzer_dns_record_name].value);
	if (!query) {
		pom_mutex_unlock(&dns_table_lock);
		return POM_ERR;
	}

	struct dns_entry *response = dns_find_or_add_entry(record);
	if (!response) {
		pom_mutex_unlock(&dns_table_lock);
		return POM_ERR;
	}

	// Update expiration queues with those entries
	if (dns_update_expiry(query, response, ttl) != POM_OK)
		return POM_ERR;
		
	dns_check_cache();

	// Check if the response already has this entry
	
	struct dns_entry_list *lst;
	for (lst = response->query; lst; lst = lst->next) {
		if (!strcmp(lst->entry->record, query->record))
			break;
	}

	if (lst) { // The response is already associated with the query
		pom_mutex_unlock(&dns_table_lock);
		return POM_OK;
	}
	
	debug_dns("Linking %s to %s", query->record, response->record);

	// Link the query and the response
	struct dns_entry_list *fwd = NULL, *rev = NULL;
	fwd = malloc(sizeof(struct dns_entry_list));
	if (!fwd) {
		pom_mutex_unlock(&dns_table_lock);
		pom_oom(sizeof(struct dns_entry_list));
		return POM_ERR;
	}
	memset(fwd, 0, sizeof(struct dns_entry_list));

	rev = malloc(sizeof(struct dns_entry_list));
	if (!rev) {
		pom_mutex_unlock(&dns_table_lock);
		free(fwd);
		pom_oom(sizeof(struct dns_entry_list));
		return POM_ERR;
	}
	memset(rev, 0, sizeof(struct dns_entry_list));

	fwd->entry = response;
	fwd->next = query->values;
	if (fwd->next)
		fwd->next->prev = fwd;
	query->values = fwd;

	rev->entry = query;
	rev->next = response->query;
	if (rev->next)
		rev->next->prev = rev;
	response->query = rev;

	pom_mutex_unlock(&dns_table_lock);
	
	return POM_OK;
}

static struct dns_entry *dns_find_entry(const char *record) {

	uint32_t hash = dns_record_hash(record);

	struct dns_entry *entry = dns_table[hash];
	
	for (entry = dns_table[hash]; entry; entry = entry->next) {
		if (!strcmp(entry->record, record))
			break;
	}

	debug_dns("Entry for %s is %p", record, entry);

	return entry;

}

char* dns_forward_lookup(const char *record) {

	if (!dns_enabled)
		return NULL;

	pom_mutex_lock(&dns_table_lock);
	
	struct dns_entry *entry = dns_find_entry(record);
	
	if (!entry) {
		pom_mutex_unlock(&dns_table_lock);
		return NULL;
	}

	int i;
	for (i = 0; entry && entry->values && i < DNS_MAX_LOOKUP_DEPTH; i++, entry = entry->values->entry);

	char *res = NULL;
	if (entry)
		res = strdup(entry->record);

	pom_mutex_unlock(&dns_table_lock);

	return res;
}
char* dns_reverse_lookup(const char *record) {

	if (!dns_enabled)
		return NULL;

	pom_mutex_lock(&dns_table_lock);

	struct dns_entry *entry = dns_find_entry(record);
	
	if (!entry) {
		pom_mutex_unlock(&dns_table_lock);
		return NULL;
	}

	int i;
	for (i = 0; entry && entry->query && i < DNS_MAX_LOOKUP_DEPTH; i++, entry = entry->query->entry);

	char *res = NULL;
	if (entry)
		res = strdup(entry->record);

	pom_mutex_unlock(&dns_table_lock);

	return res;
}

char *dns_forward_lookup_ptype(struct ptype *record_pt) {

	if (!dns_enabled)
		return NULL;

	// 40 is the max size of an ipv6 address
	char buff[40] = { 0 };
	char *record = NULL;
	if (record_pt->type == ptype_string) {
		record = PTYPE_STRING_GETVAL(record_pt);
	} else {
		ptype_print_val(record_pt, buff, sizeof(buff), NULL);
		record = buff;
	}
	return dns_forward_lookup(record);
}

char *dns_reverse_lookup_ptype(struct ptype *record_pt) {

	if (!dns_enabled)
		return NULL;

	// 40 is the max size of an ipv6 address
	char buff[40] = { 0 };
	char *record = NULL;
	if (record_pt->type == ptype_string) {
		record = PTYPE_STRING_GETVAL(record_pt);
	} else {
		ptype_print_val(record_pt, buff, sizeof(buff), NULL);
		record = buff;
	}
	return dns_reverse_lookup(record);
}
