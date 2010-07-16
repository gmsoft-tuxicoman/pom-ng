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

#include <pom-ng/input.h>

#include "pcap.h"
#include <string.h>

struct mod_reg_info* input_pcap_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_pcap_mod_register;
	reg_info.unregister_func = input_pcap_mod_unregister;

	return &reg_info;
}


int input_pcap_mod_register(struct mod_reg *mod) {

	static struct input_reg_info in_pcap_file;
	in_pcap_file.name = "pcap_file";
	in_pcap_file.api_ver = INPUT_API_VER;

	input_register(&in_pcap_file, mod);
	return POM_OK;

}

int input_pcap_mod_unregister() {

	return input_unregister("pcap_file");
}
