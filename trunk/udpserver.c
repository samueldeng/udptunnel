/*
 * Project: udptunnel
 * File: udpserver.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#else
#include "helpers/winhelpers.h"
#endif

#include "common.h"
#include "list.h"
#include "client.h"
#include "message.h"
#include "socket.h"
#include "acl.h"

extern int debug_level;
extern int ipver;
static int running = 1;
static int next_client_id = 1;

/* internal functions */
static int handle_message(uint16_t id, uint8_t msg_type, char *data,
                          int data_len, socket_t *from, list_t *clients,
                          fd_set *client_fds,
                          list_t *acls);
static void disconnect_and_remove_client(uint16_t id, list_t *clients,
                                         fd_set *fds, int full_disconnect);
static void signal_handler(int sig);

/*
 * UDP Tunnel server main(). Handles program arguments, initializes everything,
 * and runs the main loop.
 */
int udpserver(int argc, char *argv[])
{
    char host_str[ADDRSTRLEN];
    char port_str[ADDRSTRLEN];
    char addrstr[ADDRSTRLEN];
    
    list_t *clients = NULL;
    list_t *acls = NULL;
    socket_t *udp_sock = NULL;
    socket_t *udp_from = NULL;
    char data[MSG_MAX_LEN];

    client_t *client;
    uint16_t tmp_id;
    uint8_t tmp_type;
    uint16_t tmp_len;
    acl_t *tmp_acl;
    
    struct timeval curr_time;
    struct timeval timeout;
    struct timeval check_time;
    struct timeval check_interval;
    fd_set client_fds;
    fd_set read_fds;
    int num_fds;

    int i;
    int ret;

    signal(SIGINT, &signal_handler);

    if(argc == 1) /* only port specified */
    {
        ERROR_GOTO(!isnum(argv[0]), "invalid port format", done);
        strncpy(port_str, argv[0], sizeof(port_str));
        port_str[sizeof(port_str)-1] = 0;
        host_str[0] = 0;
        argv++;
        argc--;
    }
    else
    {
        /* first arg will be host IP if it's not the port */
        if(!isnum(argv[0]))
        {
            ERROR_GOTO(!isipaddr(argv[0], ipver),
                       "invalid IP address format", done);
            strncpy(host_str, argv[0], sizeof(host_str));
            host_str[sizeof(host_str)-1] = 0;
            argv++;
            argc--;
        }
        else
        {
            host_str[0] = 0;
        }

        /* next arg will be the port */
        ERROR_GOTO(!isnum(argv[0]), "invalid port format", done);
        strncpy(port_str, argv[0], sizeof(port_str));
        port_str[sizeof(port_str)-1] = 0;
        argv++;
        argc--;
    }

    /* create empty unsorted acl list */
    acls = list_create(sizeof(acl_t), NULL, NULL, p_acl_free, 0);
    ERROR_GOTO(acls == NULL, "creating acl list", done);

    for(i = 0; i < argc; i++)
    {
        tmp_acl = acl_create(argv[i], ipver);
        ERROR_GOTO(tmp_acl == NULL, "creating acl", done);
        list_add(acls, tmp_acl, 0);

        if(debug_level >= DEBUG_LEVEL2)
        {
            printf("adding acl entry: ");
            acl_print(tmp_acl);
        }
    }

    /* add ALLOW ALL entry at end of list */
    tmp_acl = acl_create(ACL_DEFAULT, ipver);
    ERROR_GOTO(tmp_acl == NULL, "creating acl", done);
    list_add(acls, tmp_acl, 0);

    if(debug_level >= DEBUG_LEVEL2)
    {
        printf("adding acl entry: ");
        acl_print(tmp_acl);
    }
    
    /* Create an empty list for the clients */
    clients = list_create(sizeof(client_t), p_client_cmp, p_client_copy,
                          p_client_free, 1);
    if(!clients)
        goto done;

    /* Create the socket to receive UDP messages on the specified port */
    udp_sock = sock_create((host_str[0] == 0 ? NULL : host_str), port_str,
                           ipver, SOCK_TYPE_UDP, 1, 1);
    if(!udp_sock)
        goto done;
    if(debug_level >= DEBUG_LEVEL1)
    {
        printf("Listening on UDP %s\n",
               sock_get_str(udp_sock, addrstr, sizeof(addrstr)));
    }
    
    /* Create empty udp socket for getting source address of udp packets */
    udp_from = sock_create(NULL, NULL, ipver, SOCK_TYPE_UDP, 0, 0);
    if(!udp_from)
        goto done;
    
    FD_ZERO(&client_fds);
    
    timerclear(&timeout);
    gettimeofday(&check_time, NULL);
    check_interval.tv_sec = 0;
    check_interval.tv_usec = 500000;
    
    while(running)
    {
        if(!timerisset(&timeout))
            timeout.tv_usec = 50000;

        /* Reset the file desc. set */
        read_fds = client_fds;
        FD_SET(SOCK_FD(udp_sock), &read_fds);

        ret = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);
        PERROR_GOTO(ret < 0, "select", done);
        num_fds = ret;

        gettimeofday(&curr_time, NULL);

        /* Go through all the clients and check if didn't get an ACK for sent
           data during the timeout period */
        if(timercmp(&curr_time, &check_time, >))
        {
            for(i = 0; i < LIST_LEN(clients); i++)
            {
                client = list_get_at(clients, i);

                if(client_timed_out(client, curr_time))
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds, 1);
                    i--;
                    continue;
                }
                
                ret = client_check_and_resend(client, curr_time);
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds, 1);
                    i--;
                    continue;
                }
            }

            /* Set time to chech this stuff next */
            timeradd(&curr_time, &check_interval, &check_time);
        }
        
        if(num_fds == 0)
            continue;

        /* Get any data received on the UDP socket */
        if(FD_ISSET(SOCK_FD(udp_sock), &read_fds))
        {
            ret = msg_recv_msg(udp_sock, udp_from, data, sizeof(data),
                               &tmp_id, &tmp_type, &tmp_len);
            
            if(ret == 0)
                ret = handle_message(tmp_id, tmp_type, data, tmp_len,
                                     udp_from, clients, &client_fds, acls);
            if(ret < 0)
                disconnect_and_remove_client(tmp_id, clients, &client_fds, 1);

            num_fds--;
        }

        /* Go through all the clients and get any TCP data that is ready */
        for(i = 0; i < LIST_LEN(clients); i++)
        {
            client = list_get_at(clients, i);

            if(num_fds > 0 && client_tcp_fd_isset(client, &read_fds))
            {
                ret = client_recv_tcp_data(client);
                if(ret == -1)
                {
                    disconnect_and_remove_client(CLIENT_ID(client),
                                                 clients, &client_fds, 1);
                    i--; /* Since there will be one less element in list */
                    continue;
                }
                else if(ret == -2)
                {
                    client_mark_to_disconnect(client);
                    disconnect_and_remove_client(CLIENT_ID(client),
                                                 clients, &client_fds, 0);
                }

                num_fds--;
            }

            /* send any TCP data that was ready */
            ret = client_send_udp_data(client);
            if(ret < 0)
            {
                disconnect_and_remove_client(CLIENT_ID(client),
                                             clients, &client_fds, 1);
                i--; /* Since there will be one less element in list */
                continue;
            }
        }

        /* Finally, send any udp data that's still in the queue */
        for(i = 0; i < LIST_LEN(clients); i++)
        {
            client = list_get_at(clients, i);
            ret = client_send_udp_data(client);

            if(ret < 0 || client_ready_to_disconnect(client))
            {
                disconnect_and_remove_client(CLIENT_ID(client), clients,
                                             &client_fds, 1);
                i--;
                continue;
            }
        }
    }
    
  done:
    if(debug_level >= DEBUG_LEVEL1)
        printf("Cleaning up...\n");
    if(acls)
        list_free(acls);
    if(clients)
        list_free(clients);
    if(udp_sock)
    {
        sock_close(udp_sock);
        sock_free(udp_sock);
    }
    if(udp_from)
        sock_free(udp_from);
    if(debug_level >= DEBUG_LEVEL1)
        printf("Goodbye.\n");
    
    return 0;
}

/*
 * Closes the client's TCP socket (not UDP, since it is shared) and remove from
 * the fd set. If full_disconnect is set, remove the list.
 */
void disconnect_and_remove_client(uint16_t id, list_t *clients,
                                  fd_set *fds, int full_disconnect)
{
    client_t *c;

    if(id == 0)
        return;
    
    c = list_get(clients, &id);
    if(!c)
        return;

    /* ok to call multiple times since fd will be -1 after first disconnect */
    client_remove_tcp_fd_from_set(c, fds);
    client_disconnect_tcp(c);

    if(full_disconnect)
    {
        client_send_goodbye(c);

        if(debug_level >= DEBUG_LEVEL1)
            printf("Client %d disconnected.\n", CLIENT_ID(c));

        list_delete(clients, &id);
    }
}

/*
 * Handles the message received from the UDP tunnel. Returns 0 for success, -1
 * for some error that it handled, and -2 if the connection should be
 * disconnected.
 */
int handle_message(uint16_t id, uint8_t msg_type, char *data, int data_len,
                   socket_t *from, list_t *clients, fd_set *client_fds,
                   list_t *acls)
{
    client_t *c = NULL;
    client_t *c2 = NULL;
    socket_t *tcp_sock = NULL;
    int ret = 0;
    
    if(id != 0)
    {
        c = list_get(clients, &id);
        if(!c)
            return -1;
    }

    if(id == 0 && msg_type != MSG_TYPE_HELLO)
        return -2;
    
    switch(msg_type)
    {
        case MSG_TYPE_GOODBYE:
            ret = -2;
            break;
            
        /* Data in the hello message will be like "hostname port", possibly
           without the null terminator. This will look for the space and
           parse out the hostname or ip address and port number */
        case MSG_TYPE_HELLO:
        {
            int i;
            char port[6]; /* need this so port str can have null term. */
            char src_addrstr[ADDRSTRLEN];
            char dst_addrstr[ADDRSTRLEN];
            uint16_t sport, dport;
            uint16_t req_id;
            
            if(id != 0)
                break;

            req_id = ntohs(*((uint16_t*)data));
            data += sizeof(uint16_t);
            data_len -= sizeof(uint16_t);
            
            /* look for the space separating the host and port */
            for(i = 0; i < data_len; i++)
                if(data[i] == ' ')
                    break;
            if(i == data_len)
                break;

            /* null terminate the host and get the port number to the string */
            data[i++] = 0;
            strncpy(port, data+i, data_len-i);
            port[data_len-i] = 0;
            
            /* Create an unconnected TCP socket for the remote host, the
               client itself, add it to the list of clients */
            tcp_sock = sock_create(data, port, ipver, SOCK_TYPE_TCP, 0, 0);
            ERROR_GOTO(tcp_sock == NULL, "Error creating tcp socket", error);

            c = client_create(next_client_id++, tcp_sock, from, 0);
            sock_free(tcp_sock);
            ERROR_GOTO(c == NULL, "Error creating client", error);

            c2 = list_add(clients, c, 1);
            ERROR_GOTO(c2 == NULL, "Error adding client to list", error);

            sock_get_addrstr(CLIENT_UDP_SOCK(c2), src_addrstr,
                             sizeof(src_addrstr));
            sock_get_addrstr(CLIENT_TCP_SOCK(c2), dst_addrstr,
                             sizeof(dst_addrstr));
            sport = sock_get_port(CLIENT_UDP_SOCK(c2));
            dport = sock_get_port(CLIENT_TCP_SOCK(c2));

            for(i = 0; i < LIST_LEN(acls); i++)
            {
                ret = acl_action(list_get_at(acls, i), src_addrstr, sport,
                                 dst_addrstr, dport);

                if(ret == ACL_ACTION_ALLOW)
                {
                    if(debug_level >= DEBUG_LEVEL2)
                        printf("Connection %s:%hu -> %s:%hu allowed\n",
                               src_addrstr, sport, dst_addrstr, dport);
                    break;
                }
                else if(ret == ACL_ACTION_DENY)
                {
                    if(debug_level >= DEBUG_LEVEL2)
                        printf("Connection to %s:%hu -> %s:%hu denied\n",
                               src_addrstr, sport, dst_addrstr, dport);

                    msg_send_msg(from, next_client_id, MSG_TYPE_GOODBYE,
                                 NULL, 0);
                    client_free(c);
                    return -2;
                }
            }
            
            if(debug_level >= DEBUG_LEVEL1)
            {
                sock_get_str(CLIENT_UDP_SOCK(c2), src_addrstr,
                             sizeof(src_addrstr));
                sock_get_str(CLIENT_TCP_SOCK(c2), dst_addrstr,
                             sizeof(dst_addrstr));
                printf("New connection(%d): udp://%s -> tcp://%s\n",
                       CLIENT_ID(c2), src_addrstr, dst_addrstr);
            }
            
            /* Send the Hello ACK message if created client successfully */
            client_send_helloack(c2, req_id);
            client_reset_keepalive(c2);
            client_free(c);
            
            break;
        }

        /* Can connect to TCP connection once received the Hello ACK */
        case MSG_TYPE_HELLOACK:
            if(client_connect_tcp(c) != 0)
                return -2;
            client_got_helloack(c);
            client_add_tcp_fd_to_set(c, client_fds);
            break;

        /* Resets the timeout of the client's keep alive time */
        case MSG_TYPE_KEEPALIVE:
            client_reset_keepalive(c);
            break;

        /* Receives the data it got from the UDP tunnel and sends it to the
           TCP connection. */
        case MSG_TYPE_DATA0:
        case MSG_TYPE_DATA1:
            ret = client_got_udp_data(c, data, data_len, msg_type);
            if(ret == 0)
                ret = client_send_tcp_data(c);
            break;

        /* Receives the ACK from the UDP tunnel to set the internal client
           state. */
        case MSG_TYPE_ACK0:
        case MSG_TYPE_ACK1:
            client_got_ack(c, msg_type);
            break;

        default:
            ret = -1;
    }

    return ret;

  error:
    return -1;
}

void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
            running = 0;
    }
}
