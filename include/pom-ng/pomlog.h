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



#ifndef __POM_NG_POMLOG_H__
#define __POM_NG_POMLOG_H__

/// Prepend value to log string to indicate log level
#define POMLOG_ERR	"\1"
#define POMLOG_WARN	"\2"
#define POMLOG_INFO	"\3"
#define POMLOG_DEBUG	"\4"

/// Size of the log buffer
#define POMLOG_BUFFER_SIZE	500
#define POMLOG_LINE_SIZE	2048
#define POMLOG_FILENAME_SIZE	16
/// Log entry

#define pomlog(args ...) pomlog_internal(__FILE__, args)

void pomlog_internal(char *file, const char *format, ...);

#endif
