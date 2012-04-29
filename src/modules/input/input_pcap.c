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

#include <pom-ng/input.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_bool.h>

#include <pom-ng/registry.h>

#include <pom-ng/packet.h>
#include <pom-ng/core.h>

#include "input_pcap.h"
#include <string.h>

#include <sys/types.h>
#include <dirent.h>
#include <regex.h>
#include <stddef.h>

// FIXME change this define when this value gets upstream
#define DLT_MPEGTS DLT_USER0

struct mod_reg_info* input_pcap_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_pcap_mod_register;
	reg_info.unregister_func = input_pcap_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_bool";

	return &reg_info;
}


static int input_pcap_mod_register(struct mod_reg *mod) {

	int res = POM_OK;

	static struct input_reg_info in_pcap_interface;
	memset(&in_pcap_interface, 0, sizeof(struct input_reg_info));
	in_pcap_interface.name = "pcap_interface";
	in_pcap_interface.api_ver = INPUT_API_VER;
	in_pcap_interface.flags = INPUT_REG_FLAG_LIVE;
	in_pcap_interface.mod = mod;
	in_pcap_interface.init = input_pcap_interface_init;
	in_pcap_interface.open = input_pcap_interface_open;
	in_pcap_interface.read = input_pcap_read;
	in_pcap_interface.close = input_pcap_close;
	in_pcap_interface.cleanup = input_pcap_cleanup;
	res += input_register(&in_pcap_interface);


	static struct input_reg_info in_pcap_file;
	memset(&in_pcap_file, 0, sizeof(struct input_reg_info));
	in_pcap_file.name = "pcap_file";
	in_pcap_file.api_ver = INPUT_API_VER;
	in_pcap_file.mod = mod;
	in_pcap_file.init = input_pcap_file_init;
	in_pcap_file.open = input_pcap_file_open;
	in_pcap_file.read = input_pcap_read;
	in_pcap_file.close = input_pcap_close;
	in_pcap_file.cleanup = input_pcap_cleanup;
	res += input_register(&in_pcap_file);

	static struct input_reg_info in_pcap_dir;
	memset(&in_pcap_dir, 0, sizeof(struct input_reg_info));
	in_pcap_dir.name = "pcap_dir";
	in_pcap_dir.api_ver = INPUT_API_VER;
	in_pcap_dir.mod = mod;
	in_pcap_dir.init = input_pcap_dir_init;
	in_pcap_dir.open = input_pcap_dir_open;
	in_pcap_dir.read = input_pcap_read;
	in_pcap_dir.close = input_pcap_close;
	in_pcap_dir.cleanup = input_pcap_cleanup;
	res += input_register(&in_pcap_dir);

	return res;

}

static int input_pcap_mod_unregister() {

	int res = POM_OK;
	res += input_unregister("pcap_file");
	res += input_unregister("pcap_interface");
	return res;
}

static int input_pcap_common_open(struct input *i) {

	struct input_pcap_priv *priv = i->priv;

	if (!priv || !priv->p)
		return POM_ERR;

	char *datalink = "undefined";

	priv->datalink_type = pcap_datalink(priv->p);
	switch (priv->datalink_type) {
		case DLT_EN10MB:
			datalink = "ethernet";
			// Ethernet is 14 bytes long
			priv->align_offset = 2;
			break;

		case DLT_DOCSIS:
			datalink = "docsis";
			break;

		case DLT_LINUX_SLL:
			datalink = "linux_cooked";
			break;

		case DLT_RAW:
			datalink = "ipv4";
			break;

		case DLT_MPEGTS: // FIXME update this when upstream add it
			datalink = "mpeg_ts";
			break;
	}

	priv->datalink_proto = proto_add_dependency(datalink);

	if (!priv->datalink_proto || !priv->datalink_proto->proto) {
		pomlog(POMLOG_ERR "Cannot open input pcap : protocol %s not registered", datalink);
		input_pcap_close(i);
		return POM_ERR;
	}

	return POM_OK;

}

/*
 * input pcap type interface
 */

static int input_pcap_interface_init(struct input *i) {

	struct input_pcap_priv *priv;
	priv = malloc(sizeof(struct input_pcap_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_pcap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_pcap_priv));
	
	struct registry_param *p = NULL;

	priv->tpriv.iface.p_interface = ptype_alloc("string");
	priv->tpriv.iface.p_promisc = ptype_alloc("bool");
	if (!priv->tpriv.iface.p_interface || !priv->tpriv.iface.p_promisc)
		goto err;

	char err[PCAP_ERRBUF_SIZE] = { 0 };
	char *dev = pcap_lookupdev(err);
	if (!dev) {
		pomlog(POMLOG_WARN "Warning, could not find a suitable interface to sniff packets from : %s", err);
		dev = "none";
	}

	p = registry_new_param("interface", dev, priv->tpriv.iface.p_interface, "Interface to capture packets from", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("promisc", "no", priv->tpriv.iface.p_promisc, "Promiscious mode", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_pcap_type_interface;

	i->priv = priv;

	return POM_OK;

err:

	if (priv->tpriv.iface.p_interface)
		ptype_cleanup(priv->tpriv.iface.p_interface);

	if (priv->tpriv.iface.p_promisc)
		ptype_cleanup(priv->tpriv.iface.p_promisc);

	if (p)
		registry_cleanup_param(p);

	free(priv);

	return POM_ERR;

}

static int input_pcap_interface_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };

	char *interface = PTYPE_STRING_GETVAL(p->tpriv.iface.p_interface);
	char *promisc = PTYPE_BOOL_GETVAL(p->tpriv.iface.p_promisc);

	p->p = pcap_open_live(interface, INPUT_PCAP_SNAPLEN_MAX, *promisc, 0,errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening interface %s : %s", interface, errbuf);
		return POM_ERR;
	}

	return input_pcap_common_open(i);

}

/*
 * input pcap type file
 */

static int input_pcap_file_init(struct input *i) {

	struct input_pcap_priv *priv;
	priv = malloc(sizeof(struct input_pcap_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_pcap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_pcap_priv));

	struct registry_param *p = NULL;

	priv->tpriv.file.p_file = ptype_alloc("string");
	if (!priv->tpriv.file.p_file)
		goto err;

	p = registry_new_param("filename", "dump.cap", priv->tpriv.file.p_file, "File in PCAP format", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_pcap_type_file;

	i->priv = priv;

	return POM_OK;

err:

	if (priv->tpriv.file.p_file)
		ptype_cleanup(priv->tpriv.file.p_file);

	if (p)
		registry_cleanup_param(p);

	free(priv);

	return POM_ERR;
}

static int input_pcap_file_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };

	char *filename = PTYPE_STRING_GETVAL(p->tpriv.file.p_file);
	p->p = pcap_open_offline(filename, errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening file %s for reading : %s", filename, errbuf);
		return POM_ERR;
	}

	return input_pcap_common_open(i);

}

/*
 * input pcap type dir
 */

static int input_pcap_dir_init(struct input *i) {

	struct input_pcap_priv *priv;
	priv = malloc(sizeof(struct input_pcap_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_pcap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_pcap_priv));

	struct registry_param *p = NULL;
	priv->tpriv.dir.p_dir = ptype_alloc("string");
	priv->tpriv.dir.p_match = ptype_alloc("string");
	if (!priv->tpriv.dir.p_dir || !priv->tpriv.dir.p_match)
		goto err;

	p = registry_new_param("directory", "/tmp", priv->tpriv.dir.p_dir, "Directory containing pcap files", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("match", "\\.p\\?cap[0-9]*$", priv->tpriv.dir.p_match, "Match files with the specific pattern (regex)", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_pcap_type_dir;
	
	i->priv = priv;

	return POM_OK;

err:
	
	if (priv->tpriv.dir.p_dir)
		ptype_cleanup(priv->tpriv.dir.p_dir);

	if (p)
		registry_cleanup_param(p);

	free(priv); 

	return POM_ERR;
}

static int input_pcap_dir_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;

	if (input_pcap_dir_browse(p) != POM_OK)
		return POM_ERR;
	
	struct input_pcap_dir_priv *dp = &p->tpriv.dir;

	dp->cur_file = dp->files;

	// Skip files which were not read
	while (dp->cur_file && !dp->cur_file->first_pkt.tv_sec)
		dp->cur_file = dp->cur_file->next;

	if (!dp->cur_file) {
		pomlog(POMLOG_ERR "No useable file found");
		return POM_ERR;
	}

	char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };
	p->p = pcap_open_offline(dp->cur_file->full_path, errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening %s for reading", dp->cur_file->full_path);
		return POM_ERR;
	}

	pomlog("Reading file %s", dp->cur_file->filename);

	return input_pcap_common_open(i);
}

static int input_pcap_dir_browse(struct input_pcap_priv *priv) {

	// Open the directory
	char *path = PTYPE_STRING_GETVAL(priv->tpriv.dir.p_dir);

	DIR *dir = opendir(path);
	if (!dir) {
		pomlog(POMLOG_ERR "Error while opening directory %s : %s", path, pom_strerror(errno));
		return POM_ERR;
	}

	// Compile the regex used to match files
	char *match = PTYPE_STRING_GETVAL(priv->tpriv.dir.p_match);
	regex_t preg;
	int errcode = regcomp(&preg, match, REG_NOSUB);

	if (errcode) {
		char errbuf[256] = { 0 };
		regerror(errcode, &preg, errbuf, sizeof(errbuf) - 1);
		pomlog(POMLOG_ERR "Error while compiling regex \"%s\" : %s", match, errbuf);
		return POM_ERR;
	}


	// Browse the given directory
	struct dirent *buf, *de;
	size_t len = offsetof(struct dirent, d_name) + pathconf(path, _PC_NAME_MAX) + 1;
	buf = malloc(len);

	do {
		int res = readdir_r(dir, buf, &de);
		if (res) {
			pomlog(POMLOG_ERR "Error while reading directory entry : %s", pom_strerror(errno));
			regfree(&preg);
			free(buf);
			closedir(dir);
			return POM_ERR;
		}

		if (!de)
			break;

		// Match our file against regex
		if (regexec(&preg, buf->d_name, 1, NULL, 0)) {
			pomlog(POMLOG_DEBUG "Discarding file %s, regular expression not matched", buf->d_name);
			continue;
		}

		// Check if we already know about that file
		struct input_pcap_dir_file *tmp = priv->tpriv.dir.files;
		int found = 0;
		while (tmp) {
			if (!strcmp(tmp->filename, buf->d_name)) {
				found = 1;
				break;
			}
			tmp = tmp->next;
		}
		if (found)
			continue;


		// We don't know about this file, parse it
		char errbuf[PCAP_ERRBUF_SIZE + 1];

		// Alloc the new file
		struct input_pcap_dir_file *cur = malloc(sizeof(struct input_pcap_dir_file));
		if (!cur) {
			free(cur->full_path);
			regfree(&preg);
			pom_oom(sizeof(struct input_pcap_dir_file));
			return POM_ERR;
		}
		memset(cur, 0, sizeof(struct input_pcap_dir_file));

		cur->full_path = malloc(strlen(path) + strlen(buf->d_name) + 2);
		if (!cur->full_path) {
			regfree(&preg);
			pom_oom(strlen(path) + strlen(buf->d_name) + 2);
			return POM_ERR;
		}
		strcpy(cur->full_path, path);
		if (*cur->full_path && cur->full_path[strlen(cur->full_path) - 1] != '/')
			strcat(cur->full_path, "/");
		cur->filename = cur->full_path + strlen(cur->full_path);
		strcat(cur->full_path, buf->d_name);

		// Get the time of the first packet
		pcap_t *p = pcap_open_offline(cur->full_path, errbuf);
		if (!p) {
			cur->next = priv->tpriv.dir.files;
			priv->tpriv.dir.files = cur; // Add at the begning in order not to process it again
			pomlog(POMLOG_WARN "Unable to open file %s : %s", cur->full_path, errbuf);
			continue;
		}
		
		const u_char *next_pkt;
		struct pcap_pkthdr *phdr;

		int result = pcap_next_ex(p, &phdr, &next_pkt);

		if (result <= 0 ) {
			cur->next = priv->tpriv.dir.files;
			priv->tpriv.dir.files = cur; // Add at the begning in order not to process it again
			pomlog(POMLOG_WARN "Could not read first packet from file %s", cur->full_path);
			free(cur->full_path);
			pcap_close(p);
			continue;
		}

		memcpy(&cur->first_pkt, &phdr->ts, sizeof(struct timeval));
		pcap_close(p);

		// Add the packet at the right position
		tmp = priv->tpriv.dir.files;

		if (!tmp || (tmp && timercmp(&cur->first_pkt, &tmp->first_pkt, <))) {
			// Add at the begining
			cur->next = priv->tpriv.dir.files;
			priv->tpriv.dir.files = cur;

		} else {
			while (tmp->next) {
				if (timercmp(&cur->first_pkt, &tmp->next->first_pkt, <)) {
					// Add in the middle
					cur->next = tmp->next;
					tmp->next = cur;
					break;
				}
				tmp = tmp->next;
			}

			if (!tmp->next) {
				// Add at the end
				tmp->next = cur;
			}
		}


		pomlog(POMLOG_DEBUG "Added file %s to the list", cur->full_path);

	} while (de);

	regfree(&preg);
	free(buf);

	closedir(dir);

	return POM_OK;

}

static int input_pcap_dir_open_next(struct input_pcap_priv *p) {

	struct input_pcap_dir_priv *dp = &p->tpriv.dir;

	do {
		dp->cur_file = dp->cur_file->next;

		if (!dp->cur_file) // No more file
			return POM_OK;

		char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };
		p->p = pcap_open_offline(dp->cur_file->full_path, errbuf);
		if (!p->p) {
			pomlog(POMLOG_ERR "Error while opening next file %s in the directory : %s. Skipping", dp->cur_file->filename, errbuf);
			continue;
		}

		// Make sure this file has the same datalink as the previous one
		if (pcap_datalink(p->p) == p->datalink_type)
			break;

		pcap_close(p->p);
		p->p = NULL;
		pomlog(POMLOG_WARN "Skipping file %s as it doesn't have the same datalink type as the previous ones", dp->cur_file->filename);

	} while (1);

	pomlog("Reading file %s", dp->cur_file->filename);

	return POM_OK;
}

/*
 * common input pcap functions
 */

static int input_pcap_read(struct input *i) {

	struct input_pcap_priv *p = i->priv;

	struct pcap_pkthdr *phdr;
	
	const u_char *data;
	int result = pcap_next_ex(p->p, &phdr, &data);
	if (phdr->len > phdr->caplen) 
		pomlog(POMLOG_WARN "Warning, some packets were truncated at capture time");

	if (result < 0) { // End of file or error 

		if (p->type == input_pcap_type_dir) {
			pcap_close(p->p);
			p->p = NULL;

			if (result != -2)
				pomlog(POMLOG_WARN "Error while reading packet from file %s. Moving on the next file ...", p->tpriv.dir.cur_file->filename);

			// Rescan the directory for possible new files
			if (input_pcap_dir_browse(p) != POM_OK)
				return POM_ERR;

			
			if (input_pcap_dir_open_next(p) != POM_OK)
				return POM_ERR;

			if (!p->tpriv.dir.cur_file) {
				// No more file
				// FIXME, tell core we are done in a nice way
				return POM_ERR;
			}

			result = pcap_next_ex(p->p, &phdr, &data);
			if (result < 0) {
				pomlog(POMLOG_ERR "Error while reading first packet of new file");
				return POM_ERR;
			}
		} else {
			return POM_ERR;
		}
	}

	if (result == 0) // Timeout
		return POM_OK;

	struct packet *pkt = packet_pool_get();
	if (!pkt)
		return POM_ERR;

	if (packet_buffer_pool_get(pkt, phdr->caplen, p->align_offset)) {
		packet_pool_release(pkt);
		return POM_ERR;
	}

	pkt->input = i;
	pkt->datalink = p->datalink_proto->proto;
	memcpy(&pkt->ts, &phdr->ts, sizeof(struct timeval));
	memcpy(pkt->buff, data, phdr->caplen);

	unsigned int flags = 0, affinity = 0;

	if (p->datalink_type == DLT_MPEGTS) {
		// MPEG2 TS has thread affinity based on the PID
		flags |= CORE_QUEUE_HAS_THREAD_AFFINITY;
		affinity = ((((char*)pkt->buff)[1] & 0x1F) << 8) | ((char *)pkt->buff)[2];
	}

	return core_queue_packet(pkt, flags, affinity);
}

static int input_pcap_close(struct input *i) {

	struct input_pcap_priv *priv = i->priv;

	if (priv->p) {
		pcap_close(priv->p);
		priv->p = NULL;
	}

	proto_remove_dependency(priv->datalink_proto);
	priv->datalink_proto = NULL;
	priv->align_offset = 0;

	if (priv->type == input_pcap_type_dir) {
		struct input_pcap_dir_priv *dp = &priv->tpriv.dir;
		while (dp->files) {
			struct input_pcap_dir_file *tmp = dp->files;
			dp->files = tmp->next;
			free(tmp->full_path);
			free(tmp);
		}
	}

	return POM_OK;
}

static int input_pcap_cleanup(struct input *i) {

	struct input_pcap_priv *priv;
	priv = i->priv;
	if (priv->p)
		pcap_close(priv->p);
	switch (priv->type) {
		case input_pcap_type_interface:
			ptype_cleanup(priv->tpriv.iface.p_interface);
			ptype_cleanup(priv->tpriv.iface.p_promisc);
			break;
		case input_pcap_type_file:
			ptype_cleanup(priv->tpriv.file.p_file);
			break;
		case input_pcap_type_dir:
			ptype_cleanup(priv->tpriv.dir.p_dir);
			ptype_cleanup(priv->tpriv.dir.p_match);
			break;

	}
	free(priv);

	return POM_OK;

}

