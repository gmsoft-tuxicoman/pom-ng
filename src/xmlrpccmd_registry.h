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


#ifndef __XMLRPCCMD_REGISTRY_H__
#define __XMLRPCCMD_REGISTRY_H__


int xmlrpccmd_registry_register_all();
xmlrpc_value *xmlrpccmd_registry_list(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_registry_add_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_registry_remove_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_registry_get_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_registry_set_instance_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_registry_instance_function(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);

#endif

