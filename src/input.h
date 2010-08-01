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



#ifndef __INPUT_H__
#define __INPUT_H__

#include <pom-ng/input.h>

#define INPUT_NAME_MAX 16

#define INPUT_SHM_BUFF_SIZE 2 * 1024 * 1024

struct input_reg {

	struct input_reg_info *info;
	struct mod_reg *module;
	unsigned int refcount;

	struct input_reg *next, *prev;

};

struct input_list {
	unsigned int id;
	struct input *i;
	struct input_list *prev, *next;

};

struct input_packet {
	struct timeval ts;
	size_t len;
	struct input_packet *next;
	// unsigned char buff[];
};

struct input_buff {
	struct input_packet *head;
	struct input_packet *tail;

	// void *buff;
};

int input_current_process();
int input_main(key_t ipc_key, uid_t main_uid, gid_t main_gid);

int input_register(struct input_reg_info *reg_info, struct mod_reg *mod);
struct input* input_alloc(const char* type, int input_ipc_key);
int input_open(struct input *i);
int input_cleanup(struct input *i);
int input_list_cleanup();

void *input_process_thread(void *param);


void input_reg_lock(int write);
void input_reg_unlock();

void input_list_lock(int write);
void input_list_unlock();

void input_instance_lock(struct input *i, int write);
void input_instance_unlock(struct input *i);

#endif
