/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __POM_NG_INPUT_H__
#define __POM_NG_INPUT_H__

#include <pom-ng/base.h>
#include <pom-ng/mod.h>
#include <pom-ng/ptype.h>
#include <pthread.h>
#include <sys/time.h>

// Current input API version
#define INPUT_API_VER	1


// Define that the input is capturing live packets
#define INPUT_REG_FLAG_LIVE	0x1

struct input {

	char *name;
	struct input_reg* reg;
	struct registry_instance *reg_instance;
	struct registry_param *reg_param_running;
	int running;

	void *priv;

	pthread_mutex_t lock;
	pthread_t thread;

	struct input *prev, *next;
};

struct input_caps {

	char *datalink;
	unsigned int align_offset;
	unsigned int is_live;
};

struct input_reg_info {

	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;
	unsigned int flags;

	/// Pointer to the initialization function of the input
	/**
	 * The init function is called to create a new input
	 * @param i The input structure to init
	 * @return POM_OK on nuccess and POM_ERR on failure.
	 **/
	int (*init) (struct input *i);

	/// Pointer to the open function of the input
	/**
	 * The open function is called when starting the input.
	 * @param i The input to init
	 * @return POM_OK on success and POM_ERR on failure.
	 **/
	int (*open) (struct input *i);

	/// Pointer to the close fonction
	/**
	 * Called when stopping the input.
	 * @param i The input to close
	 * @return POM_OK on success, POM_ERR on failure.
	 **/
	int (*close) (struct input *i);

	/// Pointer to the cleanup function
	/**
	 * Cleanup the input once we don't need it anymore.
	 * @param i The input to cleanup
	 * @return POM_OK on success and POM_ERR on failure.
	 **/
	int (*cleanup) (struct input *i);

	/// Pointer to the read function
	/**
	 *  Reads a packet and send it to the core queue.
	 *  @param i The input to read from
	 *  @param f The frame to fill with read packet
	 *  @return POM_OK or POM_ERR in case of fatal error.
	 **/
	int (*read) (struct input *i);

	/// Pointer to interrupt that should be called when interrupting the current read
	/**
	 * This function is actually a signal handler. Make sure it only calls signal safe functions.
	 * @param sig Signal that was delivered
	 * @return POM_OK on success and POM_ERR on failure.
	 */
	int (*interrupt) (struct input *i);
};

// Full decl is private
struct input_reg;

int input_register(struct input_reg_info *reg_info);
int input_unregister(char *name);


#endif
