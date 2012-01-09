/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __OUTPUT_FILE_H__
#define __OUTPUT_FILE_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/output.h>


struct output_file_priv {

	struct ptype *p_path;
	struct ptype *p_filter;

};

struct output_file_pload_priv {
	int fd;
	char *filename;
};

struct mod_reg_info* output_file_reg_info();
int output_file_mod_register(struct mod_reg *mod);
int output_file_mod_unregister();

int output_file_init(struct output *o);
int output_file_cleanup(struct output *o);
int output_file_close(struct output *o);

int output_file_pload_open(struct analyzer_pload_output_list *po);
int output_file_pload_write(struct analyzer_pload_output_list *po, void *data, size_t len);
int output_file_pload_close(struct analyzer_pload_output_list *po);



#endif
