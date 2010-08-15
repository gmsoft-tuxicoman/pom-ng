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

#ifndef __POM_NG_PTYPE_IPV4_H__
#define __POM_NG_PTYPE_IPV4_H__

#include <pom-ng/ptype.h>


#define __USE_BSD 1 // We use BSD favor of the ip header
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>


struct ptype_ipv4_val {
	struct in_addr addr;
	unsigned char mask;
};


/// x is the struct ptype
#define PTYPE_IPV4_GETADDR(x) \
	((struct ptype_ipv4_val*) x)->addr

/// x is the struct ptype, y the ipv4
#define PTYPE_IPV4_SETADDR(x, y) { \
	struct ptype_ipv4_val *v = (x)->value; \
	memcpy(&v->addr, &y, sizeof(struct in_addr)); \
}

#endif
