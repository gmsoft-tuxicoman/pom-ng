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

#define INPUT_PARAM_NAME_MAX 16
#define INPUT_PARAM_VALUE_MAX 255
#define INPUT_PARAM_DEFVAL_MAX 16
#define INPUT_PARAM_DESCRIPTION_MAX 16
#define INPUT_PARAM_TYPE_MAX 8
#define INPUT_PARAM_COUNT_MAX 8

#define INPUT_SHM_BUFF_SIZE 2 * 1024 * 1024

#define INPUT_FLAG_ATTACHED	0x1 ///< the parent process has attached the buffer
#define INPUT_FLAG_EOF		0x2 ///< the input reached EOF

struct input_packet {

	// Used by input buffer
	int inpkt_prev_offset, inpkt_next_offset;
	int buff_offset;

	// Packet description
	struct timeval ts;
	size_t len;
};

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


struct input_param {
	char *name;
	struct ptype *value;
	char *default_value;
	char *description;
	unsigned int flags;

	struct input_param *next;
};

struct input_buff {
	int inpkt_head_offset; ///< Offset of the first packet in the buffer
	int inpkt_process_head_offset; ///< Offset of the next packet to process in the buffer
	int inpkt_tail_offset; ///< Last packet in the buffer
	unsigned int flags;

	pthread_mutex_t lock;
	pthread_cond_t underrun_cond, overrun_cond;

	unsigned int buff_start_offset;
	unsigned int buff_end_offset;
};

int input_register(struct input_reg_info *reg_info, struct mod_reg *mod);
struct input* input_alloc(const char* type, int input_ipc_key, uid_t uid, gid_t gid);
int input_open(struct input *i, struct input_caps *ic);
int input_cleanup(struct input *i);

void *input_process_thread(void *param);


void input_reg_lock(int write);
void input_reg_unlock();

void input_instance_lock(struct input *i, int write);
void input_instance_unlock(struct input *i);

#endif
