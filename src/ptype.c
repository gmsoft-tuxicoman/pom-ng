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


#include <pom-ng/ptype.h>

#include "ptype.h"

#include <pthread.h>
#include <string.h>

static pthread_rwlock_t ptype_reg_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct ptype_reg *ptype_reg_head = NULL;

int ptype_register(struct ptype_reg_info *reg_info, struct mod_reg *mod) {

	pomlog("Registering ptype %s", reg_info->name);

	if (reg_info->api_ver != PTYPE_API_VER) {
		pomlog(POMLOG_ERR "API version of ptype %s does not match : expected %u got %u", PTYPE_API_VER, reg_info->api_ver);
		return POM_ERR;
	}

	struct ptype_reg *reg = malloc(sizeof(struct ptype_reg));
	if (!reg) {
		pomlog(POMLOG_ERR "Not enough memory to allocate struct ptype_reg");
		return POM_ERR;
	}
	memset(reg, 0, sizeof(struct ptype_reg));

	ptype_reg_lock(1);

	reg->info = reg_info;
	reg->module = mod;

	reg->next = ptype_reg_head;
	ptype_reg_head = reg;
	if (reg->next)
		reg->next->prev = reg;
	ptype_reg_unlock();

	return POM_OK;
}


void ptype_reg_lock(int write) {
	
	int res = 0;
	
	if (write)
		res = pthread_rwlock_wrlock(&ptype_reg_rwlock);
	else
		res = pthread_rwlock_rdlock(&ptype_reg_rwlock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking the ptype_reg lock");
		abort();
	}

}

void ptype_reg_unlock() {

	if (pthread_rwlock_unlock(&ptype_reg_rwlock)) {
		pomlog(POMLOG_ERR "Error while unlokcing the ptype_reg lock");
		abort();
	}

}
