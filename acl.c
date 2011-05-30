/*
 * Project: udptunnel
 * File: acl.c
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

#include <stdlib.h>
#include <string.h>
#include "socket.h"
#include "acl.h"

#ifdef WIN32
#include "helpers/winhelpers.h"
#endif /*WIN32*/

extern int debug_level;
    
/*
 * Creates an ACL entry given the line of the following format:
 *   s=src,d=dst,dp=dport,a=allow|deny
 * Can only be one of either IPv4 or IPv6. Currently src port is ignored.
 */
acl_t *acl_create(char *acl_entry, int ipver)
{
    char *line = NULL;
    char *saveptr = NULL;
    char *tok;
    char *param, *arg;
    char *pdst = NULL;
    char *psrc = NULL;
    char *pdp = NULL;
    char *psp = NULL;
    int i;
    acl_t *acl = NULL;

    line = malloc(strlen(acl_entry) + 1);
    ERROR_GOTO(line == NULL, "Allocating memory error", error);

    acl = calloc(1, sizeof(*acl));
    ERROR_GOTO(acl == NULL, "Allocating memory error", error);

    acl->action = ACL_ACTION_ALLOW;
    strncpy(line, acl_entry, strlen(acl_entry) + 1);

    /* go through line, getting each param=arg separated by a ',' */
    for(tok = strtok_r(line, ",", &saveptr);
        tok != NULL;
        tok = strtok_r(NULL, ",", &saveptr))
    {
        param = tok;

        /* find the arg */
        for(i = 0; i < strlen(tok); i++)
        {
            if(tok[i] == '=')
                break;
        }

        ERROR_GOTO(i == strlen(tok), "Invalid acl entry", error);
        tok[i] = '\0';
        arg = &tok[i + 1];

        if(strcmp(param, "s") == 0)
        {
            ERROR_GOTO(psrc != NULL, "Source IP already specified", error);
            psrc = arg;
        }
        else if(strcmp(param, "d") == 0)
        {
            ERROR_GOTO(pdst != NULL, "Destination IP already specified", error);
            pdst = arg;
        }
        else if(strcmp(param, "sp") == 0)
        {
            ERROR_GOTO(psp != 0, "Source port already specified", error);
            ERROR_GOTO(!isnum(arg), "Invalid port format", error);
            psp = arg;
        }
        else if(strcmp(param, "dp") == 0)
        {
            ERROR_GOTO(pdp != 0, "Destination port already specified", error);
            ERROR_GOTO(!isnum(arg), "Invalid port format", error);
            pdp = arg;
        }
        else if(strcmp(param, "a") == 0)
        {
            for(i = 0; i < strlen(arg); i++)
                arg[i] = tolower((int)arg[i]);

            if(strcmp(arg, "allow") == 0)
                acl->action = ACL_ACTION_ALLOW;
            else if(strcmp(arg, "deny") == 0)
                acl->action = ACL_ACTION_DENY;
            else
                ERROR_GOTO(1, "Invalid ACL action", error);
        }
        else
        {
            ERROR_GOTO(1, "Invalid ACL parameter", error);
        }
    }

    acl->src = sock_create(psrc, psp, ipver, SOCK_TYPE_TCP, 1, 0);
    ERROR_GOTO(acl->src == NULL, "Couldn't create acl->src", error);

    acl->dst = sock_create(pdst, pdp, ipver, SOCK_TYPE_TCP, 1, 0);
    ERROR_GOTO(acl->dst == NULL, "Couldn't create acl->dst", error);
    
    free(line);

    return acl;
    
  error:
    if(line)
        free(line);
    if(acl)
        acl_free(acl);
    
    return NULL;
}

/*
 * Frees an acl struct
 */
void acl_free(acl_t *acl)
{
    if(acl->src)
        sock_free(acl->src);
    if(acl->dst)
        sock_free(acl->dst);
    free(acl);
}

/*
 * Returns the action if the arguments match the given ACL.
 */
int acl_action(acl_t *acl, char *src, uint16_t sport, char *dst, uint16_t dport)
{
    socket_t *s = NULL;
    socket_t *d = NULL;
    uint16_t p;
    int ret;

    ret = ACL_ACTION_NOMATCH;
    
    s = sock_create(src, NULL, sock_get_ipver(acl->src),
                    SOCK_TYPE(acl->src), 0, 0);
    if(s == NULL)
        goto done;

    d = sock_create(dst, NULL, sock_get_ipver(acl->dst),
                    SOCK_TYPE(acl->dst), 0, 0);
    if(d == NULL)
        goto done;

    p = sock_get_port(acl->src);
    if(p != 0 && p != sport)
        goto done;

    p = sock_get_port(acl->dst);
    if(p != 0 && p != dport)
        goto done;

    if(!sock_isaddrany(acl->src) && sock_ipaddr_cmp(acl->src, s) != 0)
        goto done;

    if(!sock_isaddrany(acl->dst) && sock_ipaddr_cmp(acl->dst, d) != 0)
        goto done;

    ret = acl->action;
    
  done:
    if(s)
        sock_free(s);
    if(d)
        sock_free(d);
    
    return ret;
}

/*
 * For debugging, prints the ACL in the same format as acl_create expects
 */
void acl_print(acl_t *acl)
{
    char addr_str[ADDRSTRLEN];
    int len;
    uint16_t port;
    
    len = sizeof(addr_str);

    if(!sock_isaddrany(acl->src))
    {
        sock_get_addrstr(acl->src, addr_str, len);
        printf("s=%s,", addr_str);
    }

    if((port = sock_get_port(acl->src)) != 0)
        printf("sp=%hu,", port);

    if(!sock_isaddrany(acl->dst))
    {
        sock_get_addrstr(acl->dst, addr_str, len);
        printf("d=%s,", addr_str);
    }

    if((port = sock_get_port(acl->dst)) != 0)
        printf("dp=%hu,", port);

    switch(acl->action)
    {
        case ACL_ACTION_ALLOW:
            printf("a=allow\n");
            break;

        case ACL_ACTION_DENY:
            printf("a=deny\n");
            break;

        default:
            printf("a=??\n");
            break;
    }
}
