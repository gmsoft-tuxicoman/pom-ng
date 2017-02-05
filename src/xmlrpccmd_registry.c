/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#include "common.h"
#include "xmlrpcsrv.h"
#include "xmlrpccmd_registry.h"
#include <pom-ng/ptype.h>

#include "registry.h"
#include "core.h"

#define XMLRPCCMD_REGISTRY_NUM 16
static struct xmlrpcsrv_command xmlrpccmd_registry_commands[XMLRPCCMD_REGISTRY_NUM] = {

	{
		.name = "registry.list",
		.callback_func = xmlrpccmd_registry_list,
		.signature = "A:",
		.help = "List all the classes and their instances",
	},

	{
		.name = "registry.setClassParam",
		.callback_func = xmlrpccmd_registry_set_class_param,
		.signature = "i:sss",
		.help = "Set the value of a class parameter. Arguments are : class, parameter, value",
	},

	{
		.name = "registry.addInstance",
		.callback_func = xmlrpccmd_registry_add_instance,
		.signature = "i:sss",
		.help = "Add an instance of a certain class. Arguments are : class, instance_name, instance_type",
	},

	{
		.name = "registry.removeInstance",
		.callback_func = xmlrpccmd_registry_remove_instance,
		.signature = "i:ss",
		.help = "Remove an instance from a certain class, Arguments are : class, instance",
	},

	{
		.name = "registry.getInstance",
		.callback_func = xmlrpccmd_registry_get_instance,
		.signature = "A:ss",
		.help = "Get the details of an instance. Arguments are : class, instance",
	},

	{
		.name = "registry.setInstanceParam",
		.callback_func = xmlrpccmd_registry_set_instance_param,
		.signature = "i:ssss",
		.help = "Set the value of an instance parameter. Arguments are : class, instance, parameter, value",
	},

	{
		.name = "registry.instanceFunction",
		.callback_func = xmlrpccmd_registry_instance_function,
		.signature = "i:sss",
		.help = "Execute an instance function. Arguments are : class, instance, function",
	},

	{
		.name = "registry.save",
		.callback_func = xmlrpccmd_registry_save,
		.signature = "i:s",
		.help = "Save the registry configuration in the system datastore",

	},

	{
		.name = "registry.reset",
		.callback_func = xmlrpccmd_registry_reset,
		.signature = "i:",
		.help = "Reset the registry to it's initial state",
	},

	{
		.name = "registry.load",
		.callback_func = xmlrpccmd_registry_load,
		.signature = "i:s",
		.help = "Load a saved configuration",
	},

	{
		.name = "registry.delete_config",
		.callback_func = xmlrpccmd_registry_delete,
		.signature = "i:s",
		.help = "Delete a saved configuration",
	},

	{
		.name = "registry.getPerfs",
		.callback_func = xmlrpccmd_registry_get_perfs,
		.signature = "A:S",
		.help = "Fetch a set of performance objects"
	},

	{
		.name = "registry.resetAllPerfs",
		.callback_func = xmlrpccmd_registry_reset_all_perfs,
		.signature = "i:",
		.help = "Reset all performance objects"
	},

	{
		.name = "registry.resetClassPerfs",
		.callback_func = xmlrpccmd_registry_reset_class_perfs,
		.signature = "i:s",
		.help = "Reset the performances objects of a class"
	},

	{
		.name = "registry.resetInstancePerfs",
		.callback_func = xmlrpccmd_registry_reset_instance_perfs,
		.signature = "i:ss",
		.help = "Reset the performances objects of an instance"
	},

	{
		.name = "registry.poll",
		.callback_func = xmlrpccmd_registry_poll,
		.signature = "i:i",
		.help = "Poll the registry for changes"
	}
};

int xmlrpccmd_registry_register_all() {

	int i;

	for (i = 0; i < XMLRPCCMD_REGISTRY_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpccmd_registry_commands[i]) == POM_ERR)
			return POM_ERR;
	}

	return POM_OK;

}

static xmlrpc_value *xmlrpccmd_registry_build_params(xmlrpc_env * const envP, struct registry_param *param_head) {

	xmlrpc_value *params = xmlrpc_struct_new(envP);

	struct registry_param *p;
	for (p = param_head; p; p = p->next) {
		char *value = ptype_print_val_alloc(p->value, NULL);
		if (!value) {
			xmlrpc_faultf(envP, "Error while getting parameter value of parameter %s", p->name);
			continue;
		}
		xmlrpc_value *param = NULL;
		
		if (p->flags & REGISTRY_PARAM_FLAG_IMMUTABLE) {
			// Don't provide a default value for immutable parameters
			param = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s}",
							"name", p->name,
							"value", value,
							"type", ptype_get_name(p->value),
							"description", p->description);
		} else {
			param = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s,s:s}",
							"name", p->name,
							"value", value,
							"type", ptype_get_name(p->value),
							"default_value", p->default_value,
							"description", p->description);
		}

		if (p->value->unit) {
			xmlrpc_value *unit = xmlrpc_string_new(envP, p->value->unit);
			xmlrpc_struct_set_value(envP, param, "unit", unit);
			xmlrpc_DECREF(unit);
		}

		free(value);

		int suggestion = p->flags & REGISTRY_PARAM_FLAG_INFO_SUGGESTION;
		xmlrpc_value *info = NULL;
		if (p->info_type == registry_param_info_type_min_max) {
			info = xmlrpc_build_value(envP, "{s:i,s:i,s:b}", "min", p->info.mm.min, "max", p->info.mm.max, "suggestion", suggestion);
		} else if (p->info_type == registry_param_info_type_value) {
			xmlrpc_value *values = xmlrpc_array_new(envP);
			struct registry_param_info_value *v;
			for (v = p->info.v; v; v = v->next) {
				xmlrpc_value *value = xmlrpc_string_new(envP, v->value);
				xmlrpc_array_append_item(envP, values, value);
				xmlrpc_DECREF(value);
			}

			info = xmlrpc_build_value(envP, "{s:A,s:b}", "values", values, "suggestion", suggestion);
			xmlrpc_DECREF(values);
		}

		if (info) {
			xmlrpc_struct_set_value(envP, param, "info", info);
			xmlrpc_DECREF(info);
		}

		xmlrpc_struct_set_value(envP, params, p->name, param);
		xmlrpc_DECREF(param);

	}
	return params;
}

static xmlrpc_value *xmlrpccmd_registry_build_perfs(xmlrpc_env * const envP, struct registry_perf *perf_head) {

	xmlrpc_value *perfs = xmlrpc_struct_new(envP);

	struct registry_perf *p;
	for (p = perf_head; p; p = p->next) {
	
		char *type_str = "unknown";
		switch (p->type) {
			case registry_perf_type_counter:
				type_str = "counter";
				break;
			case registry_perf_type_gauge:
				type_str = "gauge";
				break;
			case registry_perf_type_timeticks:
				type_str = "timeticks";
				break;
		}
		
		xmlrpc_value *perf = NULL;
		perf = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s}",
							"name", p->name,
							"type", type_str,
							"unit", p->unit,
							"description", p->description);

		xmlrpc_struct_set_value(envP, perfs, p->name, perf);
		xmlrpc_DECREF(perf);

	}

	return perfs;
}

xmlrpc_value *xmlrpccmd_registry_list(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *classes = xmlrpc_struct_new(envP);
	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_class *c;

	for (c = registry_get(); c; c = c->next) {

		xmlrpc_value *types = xmlrpc_array_new(envP);
		struct registry_instance_type *t;
		for (t = c->types; t; t = t->next) {
			xmlrpc_value *type = xmlrpc_build_value(envP, "{s:s,s:s}",
								"name", t->name,
								"description", t->description);
			xmlrpc_array_append_item(envP, types, type);
			xmlrpc_DECREF(type);

		}

		xmlrpc_value *instances = xmlrpc_struct_new(envP);
		
		struct registry_instance *i;
		for (i = c->instances; i; i = i->next) {
			xmlrpc_value *inst = xmlrpc_build_value(envP, "{s:s,s:i}",
								"name", i->name,
								"serial", i->serial);
			xmlrpc_struct_set_value(envP, instances, i->name, inst);
			xmlrpc_DECREF(inst);
		}

		xmlrpc_value *params = xmlrpccmd_registry_build_params(envP, c->global_params);

		xmlrpc_value *perfs = xmlrpccmd_registry_build_perfs(envP, c->perfs);

		xmlrpc_value *cls = xmlrpc_build_value(envP, "{s:s,s:i,s:A,s:S,s:S,s:S}",
							"name", c->name,
							"serial", c->serial,
							"available_types", types,
							"instances", instances,
							"performances", perfs,
							"parameters", params);

		xmlrpc_DECREF(types);
		xmlrpc_DECREF(instances);
		xmlrpc_DECREF(perfs);
		xmlrpc_DECREF(params);
		xmlrpc_struct_set_value(envP, classes, c->name, cls);
		xmlrpc_DECREF(cls);

	}

	xmlrpc_value *configs = xmlrpc_struct_new(envP);

	struct registry_config_entry *config_list = registry_config_list();
	if (config_list) {
		ssize_t i;

		for (i = 0; *config_list[i].name; i++) {
			xmlrpc_value *entry = xmlrpc_build_value(envP, "{s:s,s:t}",
								"name", config_list[i].name,
								"timestamp", (time_t)pom_ptime_sec(config_list[i].ts));
			xmlrpc_struct_set_value(envP, configs, config_list[i].name, entry);
			xmlrpc_DECREF(entry);
		}

		free(config_list);
	}


	xmlrpc_value *res = xmlrpc_build_value(envP, "{s:i,s:S,s:i,s:S}",
					"classes_serial", registry_classes_serial_get(),
					"classes", classes,
					"configs_serial", registry_config_serial_get(),
					"configs", configs);
	xmlrpc_DECREF(classes);
	xmlrpc_DECREF(configs);
	registry_unlock();

	return res;

}

xmlrpc_value *xmlrpccmd_registry_set_class_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *param = NULL, *value = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &param, &value);

	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_class *c = registry_find_class(cls);
	if (!c) {
		xmlrpc_faultf(envP, "Class %s not found", cls);
		goto err;
	}

	struct registry_param *p = c->global_params;
	for (; p && strcmp(p->name, param); p = p->next);

	if (!p) {
		xmlrpc_faultf(envP, "Parameter %s not found", param);
		goto err;
	}

	free(cls);
	free(param);

	if (p->flags & REGISTRY_PARAM_FLAG_IMMUTABLE) {
		registry_unlock();
		free(value);
		xmlrpc_faultf(envP, "Parameter %s cannot be modified as it is immutable", p->name);
		return NULL;
	}


	if (registry_set_param_value(p, value) != POM_OK) {
		registry_unlock();
		xmlrpc_faultf(envP, "Unable to set parameter value to \"%s\"", value);
		free(value);
		return NULL;
	}
	free(value);
	
	c->serial++;
	registry_classes_serial_inc();
	
	registry_unlock();

	return xmlrpc_int_new(envP, 0);

err:
	registry_unlock();

	free(cls);
	free(param);
	free(value);
	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_add_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *type = NULL, *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &name, &type);

	if (envP->fault_occurred)
		goto err_decompose;

	int i;
	for (i = 0; i < strlen(name); i++) {
		char c = name[i];
		if ( !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && (c != '_') && (c != '-') && (c != '.') ) {
			xmlrpc_faultf(envP, "Only alpha numeric character and '_' '-' '.' are allowed for instance names");
			goto err_decompose;
		}
			
	}

	registry_lock();

	if (registry_find_instance(cls, name)) {
		xmlrpc_faultf(envP, "Instance already exists");
		goto err;
	}

	struct registry_class *c = registry_find_class(cls);
	if (!c) {
		xmlrpc_faultf(envP, "Class not found");
		goto err;
	}
	free(cls);
	cls = NULL;
	
	if (!c->instance_add) {
		xmlrpc_faultf(envP, "This class doesn't support adding instances");
		goto err;
	}

	if (c->instance_add(type, name) != POM_OK) {
		xmlrpc_faultf(envP, "Error while adding the instance");
		goto err;
	}

	registry_unlock();

	free(type);
	free(name);

	return xmlrpc_int_new(envP, 0);

err:
	registry_unlock();
err_decompose:

	if (cls)
		free(cls);
	free(type);
	free(name);

	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_remove_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &cls, &instance);

	if (envP->fault_occurred)
		goto err;

	registry_lock();

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		registry_unlock();
		xmlrpc_faultf(envP, "Class or instance not found");
		goto err;
	}
	free(cls);
	free(instance);
	
	if (!i->parent->instance_remove) {
		registry_unlock();
		xmlrpc_faultf(envP, "This class doesn't support removing instances");
		return NULL;
	}

	if (registry_remove_instance(i) != POM_OK) {
		registry_unlock();
		xmlrpc_faultf(envP, "Error while removing the instance");
		return NULL;
	}
	
	registry_unlock();

	return xmlrpc_int_new(envP, 0);

err:
	free(cls);
	free(instance);

	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_get_instance(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &cls, &instance);

	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		xmlrpc_faultf(envP, "Class or instance not found");
		free(cls);
		free(instance);
		goto err;
	}

	free(cls);
	free(instance);


	xmlrpc_value *funcs = xmlrpc_array_new(envP);

	struct registry_function *f;
	for (f = i->funcs; f; f = f->next) {
		xmlrpc_value *func = xmlrpc_build_value(envP, "{s:s,s:s}",
						"name", f->name,
						"description", f->description);
		xmlrpc_array_append_item(envP, funcs, func);
		xmlrpc_DECREF(func);

	}

	xmlrpc_value *params = xmlrpccmd_registry_build_params(envP, i->params);

	xmlrpc_value *perfs = xmlrpccmd_registry_build_perfs(envP, i->perfs);

	xmlrpc_value *res = xmlrpc_build_value(envP, "{s:s,s:i,s:S,s:S,s:A}",
				"name", i->name,
				"serial", i->serial,
				"parameters", params,
				"performances", perfs,
				"functions", funcs);

	registry_unlock();

	xmlrpc_DECREF(params);
	xmlrpc_DECREF(perfs);
	xmlrpc_DECREF(funcs);

	return res;

err:
	registry_unlock();

	return NULL;


}

xmlrpc_value *xmlrpccmd_registry_set_instance_param(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL, *param = NULL, *value = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ssss)", &cls, &instance, &param, &value);

	if (envP->fault_occurred)
		return NULL;

	registry_lock();

	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		xmlrpc_faultf(envP, "Class or instance not found");
		goto err;
	}

	struct registry_param *p = i->params;
	for (; p && strcmp(p->name, param); p = p->next);

	if (!p) {
		xmlrpc_faultf(envP, "Parameter %s not found", param);
		goto err;
	}

	free(cls);
	free(instance);
	free(param);

	if (p->flags & REGISTRY_PARAM_FLAG_IMMUTABLE) {
		registry_unlock();
		free(value);
		xmlrpc_faultf(envP, "Parameter %s cannot be modified as it is immutable", p->name);
		return NULL;
	}


	if (registry_set_param_value(p, value) != POM_OK) {
		registry_unlock();
		xmlrpc_faultf(envP, "Unable to set parameter value to \"%s\"", value);
		free(value);
		return NULL;
	}
	free(value);
	
	i->serial++;
	i->parent->serial++;
	registry_classes_serial_inc();
	
	registry_unlock();

	return xmlrpc_int_new(envP, 0);

err:
	registry_unlock();

	free(cls);
	free(instance);
	free(param);
	free(value);
	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_instance_function(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL, *function = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &cls, &instance, &function);

	if (envP->fault_occurred)
		goto err;

	registry_lock();
	struct registry_instance *i = registry_find_instance(cls, instance);

	if (!i) {
		xmlrpc_faultf(envP, "Class or instance doesn't exists");
		goto err;
	}

	free(cls);
	cls = NULL;
	free(instance);
	instance = NULL;

	struct registry_function *f = i->funcs;

	for (; f && strcmp(f->name, function); f = f->next);

	if (!f) {
		xmlrpc_faultf(envP, "Function not found");
		goto err;
	}

	if (f->handler(i) != POM_OK) {
		xmlrpc_faultf(envP, "An error occurred");
		goto err;
	}

	i->serial++;
	i->parent->serial++;
	registry_classes_serial_inc();

	registry_unlock();

	free(function);

	return xmlrpc_int_new(envP, 0);

err:
	
	registry_unlock();

	if (cls)
		free(cls);
	if (instance)
		free(instance);
	free(function);

	return NULL;
}

xmlrpc_value *xmlrpccmd_registry_save(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	if (registry_config_save(name) != POM_OK) {
		free(name);
		xmlrpc_faultf(envP, "Error while saving the registry");
		return NULL;
	}
	
	free(name);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_reset(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	if (registry_config_reset() != POM_OK) {
		xmlrpc_faultf(envP, "Error while resetting the registry");
		return NULL;
	}

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_load(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	if (registry_config_load(name) != POM_OK) {
		free(name);
		xmlrpc_faultf(envP, "Error while loading the registry");
		return NULL;
	}
	
	free(name);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_delete(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	if (registry_config_delete(name) != POM_OK) {
		free(name);
		xmlrpc_faultf(envP, "Error while deleting the registry config");
		return NULL;
	}
	
	free(name);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_get_perfs(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	struct perf_entry {
		char *cls_name;
		struct registry_class *cls;
		char *inst_name;
		struct registry_instance *inst;
		char *perf_name;
		struct registry_perf *perf;
		xmlrpc_value *value;
	};


	xmlrpc_value *array;
	xmlrpc_decompose_value(envP, paramArrayP, "(A)", &array);

	if (envP->fault_occurred || !array)
		return NULL;

	unsigned int perf_array_count = xmlrpc_array_size(envP, array);
	size_t perf_array_size = sizeof(struct perf_entry) * perf_array_count;
	struct perf_entry *perf_array = malloc(perf_array_size);
	if (!perf_array) {
		xmlrpc_DECREF(array);
		pom_oom(perf_array_size);
		return NULL;
	}
	memset(perf_array, 0, perf_array_size);

	xmlrpc_value *res = xmlrpc_struct_new(envP);

	// Fetch each entry in the array
	unsigned int i;
	for (i = 0; i < perf_array_count; i++) {
		xmlrpc_value *item = NULL;
		xmlrpc_array_read_item(envP, array, i, &item);
		if (envP->fault_occurred) {
			xmlrpc_DECREF(array);
			goto err;
		}

		// Fetch each structure, get the class, instance and perf
		xmlrpc_decompose_value(envP, item, "{s:s,s:s,*}",
						"class", &perf_array[i].cls_name,
						"perf", &perf_array[i].perf_name
						);
		if (envP->fault_occurred) {
			perf_array[i].cls_name = NULL;
			perf_array[i].perf_name = NULL;
			xmlrpc_DECREF(item);
			xmlrpc_DECREF(array);
			goto err;
		}

		xmlrpc_value *inst_nameP = NULL;
		xmlrpc_struct_find_value(envP, item, "instance", &inst_nameP);
		if (inst_nameP) {
			xmlrpc_read_string(envP, inst_nameP, (const char ** const) &perf_array[i].inst_name);
			xmlrpc_DECREF(inst_nameP);
		}
		xmlrpc_DECREF(item);

		if (envP->fault_occurred) {
			xmlrpc_DECREF(array);
			goto err;
		}

	}
	xmlrpc_DECREF(array);

	registry_lock();
	for (i = 0; i < perf_array_count; i++) {
		if (!perf_array[i].cls) {
			perf_array[i].cls = registry_find_class(perf_array[i].cls_name);
			if (!perf_array[i].cls) {
				xmlrpc_faultf(envP, "Class %s not found", perf_array[i].cls_name);
				registry_unlock();
				goto err;
			}
			unsigned int j;

			for (j = i + 1; j < perf_array_count; j++) {
				if (!strcmp(perf_array[j].cls_name, perf_array[i].cls_name))
					perf_array[j].cls = perf_array[i].cls;
			}

		}

		if (!perf_array[i].inst && perf_array[i].inst_name) {
			struct registry_instance *inst;
			for (inst = perf_array[i].cls->instances; inst && strcmp(inst->name, perf_array[i].inst_name); inst = inst->next);
			if (!inst) {
				xmlrpc_faultf(envP, "Instance %s of class %s does not exists", perf_array[i].inst_name, perf_array[i].cls_name);
				registry_unlock();
				goto err;
			}
			perf_array[i].inst = inst;
			
			unsigned int j;
			for (j = i + 1; j < perf_array_count; j++) {
				if (perf_array[j].cls == perf_array[i].cls && perf_array[j].inst_name && !strcmp(perf_array[j].inst_name, perf_array[i].inst_name))
					perf_array[j].inst = perf_array[i].inst;
			}
		}

		if (!perf_array[i].perf) {
			struct registry_perf *perf;
			for (perf = (perf_array[i].inst ? perf_array[i].inst->perfs : perf_array[i].cls->perfs); perf && strcmp(perf->name, perf_array[i].perf_name); perf = perf->next);
			if (!perf) {
				if (perf_array[i].inst_name) {
					xmlrpc_faultf(envP, "Perf %s of instance %s of class %s does not exists", perf_array[i].perf_name, perf_array[i].inst_name, perf_array[i].cls_name);
				} else {
					xmlrpc_faultf(envP, "Perf %s of class %s does not exists", perf_array[i].perf_name, perf_array[i].cls_name);
				}
				registry_unlock();
				goto err;
			}
			perf_array[i].perf = perf;

			unsigned int j;
			for (j = i + 1; j < perf_array_count; j++) {
				if (perf_array[j].inst == perf_array[i].inst && !strcmp(perf_array[j].perf_name, perf_array[i].perf_name))
					perf_array[j].perf = perf_array[i].perf;
			}
		}

		// Fetch the perf value and the time as close as possible
		uint64_t value = registry_perf_getval(perf_array[i].perf);
		struct timeval time_sys;
		gettimeofday(&time_sys, NULL);
		ptime time_pkt = core_get_clock();

		xmlrpc_value *sys_time = xmlrpc_build_value(envP, "{s:i,s:i}", "sec", time_sys.tv_sec, "usec", time_sys.tv_usec);

		// Add the value to the result
		xmlrpc_value *item = NULL;
		item = xmlrpc_build_value(envP, "{s:s,s:s,s:I,s:S}",
						"class", perf_array[i].cls_name,
						"perf", perf_array[i].perf_name,
						"value", value,
						"sys_time", sys_time);
		xmlrpc_DECREF(sys_time);

		if (perf_array[i].inst_name) {
			xmlrpc_value *inst_name = xmlrpc_string_new(envP, perf_array[i].inst_name);
			xmlrpc_struct_set_value(envP, item, "instance", inst_name);
			xmlrpc_DECREF(inst_name);
		}

		if (time_pkt > 0) {
			xmlrpc_value *pkt_time = xmlrpc_build_value(envP, "{s:i,s:i}", "sec", pom_ptime_sec(time_pkt), "usec", pom_ptime_usec(time_pkt));
			xmlrpc_struct_set_value(envP, item, "pkt_time", pkt_time);
			xmlrpc_DECREF(pkt_time);
		}
			
		xmlrpc_struct_set_value(envP, res, perf_array[i].perf_name, item);
		xmlrpc_DECREF(item);
	}
	registry_unlock();
	
	for (i = 0; i < perf_array_count; i++) {
		if (perf_array[i].cls_name)
			free(perf_array[i].cls_name);
		if (perf_array[i].inst_name)
			free(perf_array[i].inst_name);
		if (perf_array[i].perf_name)
			free(perf_array[i].perf_name);
	}

	free(perf_array);

	return res;

err:

	for (i = 0; i < perf_array_count; i++) {
		if (perf_array[i].cls_name)
			free(perf_array[i].cls_name);
		if (perf_array[i].inst_name)
			free(perf_array[i].inst_name);
		if (perf_array[i].perf_name)
			free(perf_array[i].perf_name);
	}
	free(perf_array);

	xmlrpc_DECREF(res);

	return NULL;
}


xmlrpc_value *xmlrpccmd_registry_reset_all_perfs(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	registry_perf_reset_all();
	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_reset_class_perfs(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &cls);

	if (envP->fault_occurred)
		return NULL;

	registry_lock();
	
	struct registry_class *c = registry_find_class(cls);
	if (!c) {
		registry_unlock();
		xmlrpc_faultf(envP, "Class %s does not exists", cls);
		return NULL;
	}

	struct registry_perf *p;
	for (p = c->perfs; p; p = p->next) {
		if (p->type == registry_perf_type_counter)
			registry_perf_reset(p);
	}

	struct registry_instance *inst;
	for (inst = c->instances; inst; inst = inst->next) {
		for (p = inst->perfs; p; p = p->next) {
			if (p->type == registry_perf_type_counter)
				registry_perf_reset(p);
		}
	}

	registry_unlock();
	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_reset_instance_perfs(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *cls = NULL, *instance = NULL;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &cls, &instance);

	if (envP->fault_occurred)
		return NULL;

	registry_lock();
	
	struct registry_instance *i = registry_find_instance(cls, instance);
	if (!i) {
		registry_unlock();
		xmlrpc_faultf(envP, "Instance %s of class %s does not exists", instance, cls);
		return NULL;
	}

	struct registry_perf *p;
	for (p = i->perfs; p; p = p->next) {
		if (p->type == registry_perf_type_counter)
			registry_perf_reset(p);
	}

	registry_unlock();

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_registry_poll(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t last_serial;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &last_serial);

	if (envP->fault_occurred)
		return NULL;

	struct timeval now;
	gettimeofday(&now, NULL);
	struct timespec then = { 0 };
	then.tv_sec = now.tv_sec + XMLRPCSRV_POLL_TIMEOUT;

	
	uint32_t new_serial = registry_serial_poll(last_serial, &then);

	return xmlrpc_int_new(envP, new_serial);
}

