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



#ifndef __INPUT_SERVER_H__
#define __INPUT_SERVER_H__

#include "input_ipc.h"

int input_server_main(key_t ipc_key, uid_t main_uid, gid_t main_gid);
int input_server_is_current_process();

int input_server_cmd_mod_load(struct input_ipc_raw_cmd *cmd);
int input_server_cmd_mod_unload(struct input_ipc_raw_cmd *cmd);
int input_server_cmd_add(struct input_ipc_raw_cmd *cmd, uid_t uid, gid_t gid);
int input_server_cmd_get_param(struct input_ipc_raw_cmd *cmd);
int input_server_cmd_set_param(struct input_ipc_raw_cmd *cmd);
int input_server_cmd_remove(struct input_ipc_raw_cmd *cmd);
int input_server_cmd_start(struct input_ipc_raw_cmd *cmd);
int input_server_cmd_stop(struct input_ipc_raw_cmd *cmd);
int input_server_cmd_halt(struct input_ipc_raw_cmd *cmd);

void input_server_list_lock(int write);
void input_server_list_unlock();

#endif
