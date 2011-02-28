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
#include "acl.h"
#include "socket.h"

extern int debug_level;

/*
 * Creates an ACL entry given the line of the following format:
 *   s=src,d=dst,dp=dport,a=allow|deny
 * Can only be one of either IPv4 or IPv6. Currently src port is ignored.
 */
acl_t *acl_create(char *acl_entry, int ipver)
{
    char *line = NULL;;
    char *saveptr = NULL;
    char *tok;
    char *param, *arg;
    int i, ret;

    acl_t *acl = NULL;

    line = malloc(strlen(acl_entry) + 1);
    ERROR_GOTO(line == NULL, "Allocating memory error", error);
    
    acl = calloc(1, sizeof(*acl));
    ERROR_GOTO(acl == NULL, "Allocating memory error", error);

    acl->action = ACL_ACTION_ALLOW;
    acl->sa_type = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
    strncpy(line, acl_entry, strlen(acl_entry));
    
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
            ERROR_GOTO(!isaddrzero(acl->src, sizeof(acl->src)),
                       "Source IP already specified", error);

            ret = inet_pton(acl->sa_type, arg, acl->src);
            ERROR_GOTO(ret != 1, "Couldn't convert IP", error);
        }
        else if(strcmp(param, "d") == 0)
        {
            ERROR_GOTO(!isaddrzero(acl->dst, sizeof(acl->dst)),
                       "Destination IP already specified", error);

            ret = inet_pton(acl->sa_type, arg, acl->dst);
            ERROR_GOTO(ret != 1, "Couldn't convert IP", error);
        }
        else if(strcmp(param, "sp") == 0)
        {
            ERROR_GOTO(acl->sport != 0, "Source port already specified",
                       error);
            ERROR_GOTO(!isnum(arg), "Invalid port format", error);

            ret = atoi(arg);
            ERROR_GOTO((ret & 0xffff0000) != 0, "Port out of range", error);

            acl->sport = (uint16_t)ret;
        }
        else if(strcmp(param, "dp") == 0)
        {
            ERROR_GOTO(acl->dport != 0, "Destination port already specified",
                       error);
            ERROR_GOTO(!isnum(arg), "Invalid port format", error);

            ret = atoi(arg);
            ERROR_GOTO((ret & 0xffff0000) != 0, "Port out of range", error);

            acl->dport = (uint16_t)ret;
        }
        else if(strcmp(param, "a") == 0)
        {
            for(i = 0; i < strlen(arg); i++)
                arg[i] = tolower(arg[i]);

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

    free(line);

    return acl;
    
  error:
    if(line)
        free(line);
    if(acl)
        free(acl);
    
    return NULL;
}

/*
 * Frees an acl struct
 */
void acl_free(acl_t *acl)
{
    free(acl);
}

/*
 * Returns the action if the arguments match the given ACL.
 */
int acl_action(acl_t *acl, char *src, uint16_t sport, char *dst, uint16_t dport)
{
    struct in6_addr addr;
    
    if(acl->sport != 0)
    {
        if(acl->sport != sport)
            return ACL_ACTION_NOMATCH;
    }

    if(acl->dport != 0)
    {
        if(acl->dport != dport)
            return ACL_ACTION_NOMATCH;
    }

    if(!isaddrzero(acl->src, sizeof(acl->src)))
    {
        memset(&addr, 0, sizeof(addr));

        if(inet_pton(acl->sa_type, src, &addr) != 1 ||
           memcmp(acl->src, &addr, sizeof(addr)) != 0)
            return ACL_ACTION_NOMATCH;
    }

    if(!isaddrzero(acl->dst, sizeof(acl->dst)))
    {
        memset(&addr, 0, sizeof(addr));

        if(inet_pton(acl->sa_type, dst, &addr) != 1 ||
           memcmp(acl->dst, &addr, sizeof(addr)) != 0)
            return ACL_ACTION_NOMATCH;
    }
    
    return acl->action;
}

/*
 * For debugging, prints the ACL in the same format as acl_create expects
 */
void acl_print(acl_t *acl)
{
    struct in6_addr zaddr = IN6ADDR_ANY_INIT;
    char addr_str[ADDRSTRLEN];
    
    if(memcmp(acl->src, &zaddr, sizeof(zaddr)) != 0)
    {
        inet_ntop(acl->sa_type, acl->src, addr_str, sizeof(addr_str));
        printf("s=%s,", addr_str);
    }

    if(acl->sport != 0)
        printf("sp=%hu,", acl->sport);
    
    if(memcmp(acl->dst, &zaddr, sizeof(zaddr)) != 0)
    {
        inet_ntop(acl->sa_type, acl->dst, addr_str, sizeof(addr_str));
        printf("d=%s,", addr_str);
    }

    if(acl->dport != 0)
        printf("dp=%hu,", acl->dport);

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
