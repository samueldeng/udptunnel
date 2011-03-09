/*
 * Project: udptunnel
 * File: acl.h
 *
 * Copyright (C) 2011 Daniel Meekins
 * Contact: dmeekins - gmail
 *
 * Extended from Andreas Rottmann's (a.rottmann@gmx.at) work, which was
 * previously the "destination" module.
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

#ifndef ACL_H
#define ACL_H

#include "common.h"
#include "socket.h"

#define ACL_ACTION_NOMATCH 0
#define ACL_ACTION_DENY    1
#define ACL_ACTION_ALLOW   2

#define ACL_DEFAULT ((char *)"a=allow")

typedef struct acl {
    socket_t *src;
    socket_t *dst;
    int action;
} acl_t;

acl_t *acl_create(char *acl_entry, int ipver);
void acl_free(acl_t *acl);
int acl_action(acl_t *acl, char *src, uint16_t sport, char *dst, uint16_t dport);
void acl_print(acl_t *acl);

#define p_acl_free ((void (*)(void *))&acl_free)

#endif /* ACL_H */
