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



#ifndef __XMLRPCSRV_H__
#define __XMLRPCSRV_H__

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>

#define XMLRPCSRV_URI "/RPC2"

struct xmlrpcsrv_command {
	char *name;
	xmlrpc_value* (*callback_func) (xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
	char *signature;
	char *help;
};

int xmlrpcsrv_init();
int xmlrpcsrv_process(char *data, size_t size, char **response, size_t *reslen);
int xmlrpcsrv_stop();
int xmlrpcsrv_cleanup();

int xmlrpcsrv_register_command(struct xmlrpcsrv_command *cmd);

void xmlrpcsrv_shutdown(xmlrpc_env * const faultP, void * const context, const char * const comment, void * const callInfo);


#endif
