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


#ifndef __POM_NG_INPUT_H__
#define __POM_NG_INPUT_H__

#include <pom-ng/base.h>
#include <pom-ng/mod.h>
#include <pom-ng/ptype.h>
#include <pthread.h>
#include <sys/time.h>

// Current input API version
#define INPUT_API_VER	1

struct input_buff;
struct input_param;

struct input {
	struct input_reg* type; ///< Type of the input
	int opened;
	struct input_param *params;
	void *priv;

	int shm_key;
	int shm_id;
	struct input_buff *shm_buff;
	size_t shm_buff_size;

	pthread_t thread;
	pthread_rwlock_t op_lock;
};

struct input_caps {

	char *datalink;
	unsigned int align_offset;
	unsigned int is_live;
};

struct input_reg_info {

	unsigned int api_ver;
	char *name;

	/// Pointer to the allocate function of the input
	/**
	 * The allloc function is called to create a new input
	 * @param i The input structure to init
	 * @return POM_OK on nuccess and POM_ERR on failure.
	 **/
	int (*alloc) (struct input *i);

	/// Pointer to the open function of the input
	/**
	 * The open function is called when opening the input.
	 * @param i The input to init
	 * @return POM_OK on success and POM_ERR on failure.
	 **/
	int (*open) (struct input *i);

	/// Pointer to the read function
	/**
	 *  Reads a packet and store it in the shared buffer.
	 *  @param i The input to read from
	 *  @param f The frame to fill with read packet
	 *  @return POM_OK or POM_ERR in case of fatal error.
	 **/
	int (*read) (struct input *i);

	/// Pointer to the close fonction
	/**
	 * Close the input.
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

	/// Pointer to the fonction to provide the capabilities of an input
	/**
	 * Fills the struct input_caps with the capabilities of the input.
	 * The input must be opened or POM_ERR will be returned.
	 * @param i The input we need capabilities from
	 * @param ic The struct input_caps that needs to be filled
	 * @return POM_OK on success and POM_ERR on failure.
	 **/
	int (*get_caps) (struct input *i, struct input_caps *ic);

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

/// Register a new input.
int input_register(struct input_reg_info *reg, struct mod_reg *mod);

/// Stops an input
int input_close(struct input *i);

/// Unregister a input
int input_unregister(char *name);

// Add a packet in the input kernel ring buffer
int input_add_processed_packet(struct input *i, size_t pkt_size, unsigned char *pkt_data, struct timeval *ts, unsigned int drop_if_full);

// Called by an input module to register a parameter
int input_register_param(struct input *i, char *name, struct ptype *value, char *default_value, char *description, unsigned int flags);

#endif
