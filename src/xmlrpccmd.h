/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __XMLRPCCMD_H__
#define __XMLRPCCMD_H__

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>
#include <pom-ng/ptype.h>

#define XMLRPCCMD_POLL_TIMEOUT 180

int xmlrpccmd_init();

int xmlrpccmd_cleanup();

int xmlrpccmd_register_all();

void xmlrcpcmd_serial_inc();

xmlrpc_value *xmlrpccmd_ptype_to_val(xmlrpc_env* const envP, struct ptype* p);
xmlrpc_value *xmlrpccmd_core_get_version(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_core_serial_poll(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_core_serial_poll2(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_core_get_log(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_core_poll_log(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);

#endif

