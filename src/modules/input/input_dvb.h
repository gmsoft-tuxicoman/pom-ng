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

#ifndef __INPUT_DVB_H__
#define __INPUT_DVB_H__


enum input_dvb_type {
	input_dvb_type_c,
	input_dvb_type_s, // TODO
	input_dvb_type_t, // TODO
};

struct input_dvb_c_priv {
	
	struct ptype *modulation;
};

struct input_dvb_priv {
	
	enum input_dvb_type type;

	// Some common params
	struct ptype *adapter, *frontend, *freq, *symbol_rate, *tuning_timeout;

	int frontend_fd, demux_fd, dvr_fd;

	union {
		struct input_dvb_c_priv c;
	} tpriv;

};

struct mod_reg_info* input_dvb_reg_info();
static int input_dvb_mod_register(struct mod_reg *mod);
static int input_dvb_mod_unregister();
static int input_dvb_c_alloc(struct input *i);
static int input_dvb_open(struct input *i);
static int input_dvb_tune(struct input_dvb_priv *p, uint32_t frequency, uint32_t symbol_rate, fe_modulation_t modulation);
static int input_dvb_read(struct input *i);
static int input_dvb_get_caps(struct input *i, struct input_caps *ic);
static int input_dvb_close(struct input *i);
static int input_dvb_cleanup(struct input *i);

#endif

