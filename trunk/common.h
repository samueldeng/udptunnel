/*
 * Project: udptunnel
 * File: common.h
 *
 * Copyright (C) 2009 Daniel Meekins
 * Contact: dmeekins - gmail
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>

#define DEBUG 0
#define ERR_DEBUG 1

#define PERROR_GOTO(cond,err,label){     \
        if(cond)                         \
        {                                \
            if(ERR_DEBUG) perror(err) ;  \
            goto label;                  \
        }}

#define ERROR_GOTO(cond,str,label){                  \
        if(cond)                                     \
        {                                            \
            if(ERR_DEBUG)                            \
                fprintf(stderr, "Error: %s\n", str); \
            goto label;                              \
        }}

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#ifdef SOLARIS
/* Copied from sys/time.h on linux system since solaris system that tried to
 * compile on didn't have timeradd macro. */
#define timeradd(a, b, result)                                               \
    do {                                                                      \
        (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                         \
        (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                      \
        if ((result)->tv_usec >= 1000000)                                     \
        {                                                                     \
            ++(result)->tv_sec;                                               \
            (result)->tv_usec -= 1000000;                                     \
        }                                                                     \
    } while (0)
#endif /* SOLARIS */

#endif /* COMMON_H */
