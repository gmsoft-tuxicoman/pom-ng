/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#include "output_log.h"

#include "output_log_txt.h"
#include "output_log_xml.h"


struct mod_reg_info* output_log_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = output_log_mod_register;
	reg_info.unregister_func = output_log_mod_unregister;
	reg_info.dependencies = "ptype_string";

	return &reg_info;

}

int output_log_mod_register(struct mod_reg *mod) {


	static struct output_reg_info output_log_txt = { 0 };
	output_log_txt.name = "log_txt";
	output_log_txt.description = "Log events in text files based on templates";
	output_log_txt.mod = mod;

	output_log_txt.init = output_log_txt_init;
	output_log_txt.open = output_log_txt_open;
	output_log_txt.close = output_log_txt_close;
	output_log_txt.cleanup = output_log_txt_cleanup;

	static struct addon_plugin_event_reg addon_log_txt = { 0 };
	addon_log_txt.name = "log_txt";
	addon_log_txt.mod = mod;

	addon_log_txt.init = addon_log_txt_init;
	addon_log_txt.open = addon_log_txt_open;
	addon_log_txt.close = addon_log_txt_close;
	addon_log_txt.cleanup = addon_log_txt_cleanup;

	addon_log_txt.event_end = addon_log_txt_process;

	static struct output_reg_info output_log_xml = { 0 };
	output_log_xml.name = "log_xml";
	output_log_xml.description = "Log specified events in XML format";
	output_log_xml.mod = mod;

	output_log_xml.init = output_log_xml_init;
	output_log_xml.open = output_log_xml_open;
	output_log_xml.close = output_log_xml_close;
	output_log_xml.cleanup = output_log_xml_cleanup;

	static struct addon_plugin_event_reg addon_log_xml = { 0 };
	addon_log_xml.name = "log_xml";
	addon_log_xml.mod = mod;
	
	addon_log_xml.init = addon_log_xml_init;
	addon_log_xml.open = addon_log_xml_open;
	addon_log_xml.close = addon_log_xml_close;
	addon_log_xml.cleanup = output_log_xml_cleanup;

	addon_log_xml.event_end = output_log_xml_process;

	if (output_register(&output_log_txt) != POM_OK ||
		addon_plugin_event_register(&addon_log_txt) != POM_OK ||
		output_register(&output_log_xml) != POM_OK ||
		addon_plugin_event_register(&addon_log_xml)) {
		output_log_mod_unregister();
		return POM_ERR;
	}

	return POM_OK;
}

int output_log_mod_unregister() {

	int res = POM_OK;

	res += output_unregister("log_txt");
	res += addon_plugin_unregister("log_txt");
	res += output_unregister("log_xml");
	res += addon_plugin_unregister("log_xml");

	return res;
}

