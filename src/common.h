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


#ifndef __COMMON_H__
#define __COMMON_H__

// Default return values
#define POM_OK 0
#define POM_ERR -1

#include "../config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

#include "pomlog.h"

#define POM_STRERROR_BUFF_SIZE 128

// Some OS don't define this (taken from GNU C)
#ifndef timercmp
#define timercmp(a, b, CMP) 						\
	(((a)->tv_sec == (b)->tv_sec) ? 				\
	((a)->tv_usec CMP (b)->tv_usec) : 				\
	((a)->tv_sec CMP (b)->tv_sec))
#endif

#ifndef timeradd
#define timeradd(a, b, result)						\
	(result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			\
	(result)->tv_usec = (a)->tv_usec + (b)->tv_usec;		\
	if ((result)->tv_usec >= 1000000) {				\
		++(result)->tv_sec;					\
		(result)->tv_usec -= 1000000;				\
	}
#endif

#ifndef timersub
#define timersub(a, b, result)						\
	(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			\
	(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
	if ((result)->tv_usec < 0) {					\
		--(result)->tv_sec;					\
		(result)->tv_usec += 1000000;				\
	}
#endif

// Thread safe version of strerror()
char *pom_strerror(int err);


#endif
