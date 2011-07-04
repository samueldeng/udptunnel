/*
 * Project: udptunnel
 * File: udpclient.c
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
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#else
#include "helpers/winhelpers.h"
#endif

#include "common.h"
#include "message.h"
#include "socket.h"
#include "client.h"
#include "list.h"

extern int debug_level;
extern int ipver;
static int running = 1;
static uint16_t next_req_id;

/* internal functions */
static int handle_message(client_t *c, uint16_t id, uint8_t msg_type,
                          char *data, int data_len);
static void disconnect_and_remove_client(uint16_t id, list_t *clients,
                                         fd_set *fds, int full_disconnect);
static void signal_handler(int sig);

int udpclient(int argc, char *argv[])
{
    char *lhost, *lport, *phost, *pport, *rhost, *rport;
    list_t *clients = NULL;
    list_t *conn_clients;
    client_t *client;
    client_t *client2;
    socket_t *tcp_serv = NULL;
    socket_t *tcp_sock = NULL;
    socket_t *udp_sock = NULL;
    char data[MSG_MAX_LEN];
    char addrstr[ADDRSTRLEN];
    
    struct timeval curr_time;
    struct timeval check_time;
    struct timeval check_interval;
    struct timeval timeout;
    fd_set client_fds;
    fd_set read_fds;
    uint16_t tmp_id;
    uint8_t tmp_type;
    uint16_t tmp_len;
    uint16_t tmp_req_id;
    int num_fds;
    
    int ret;
    int i;
    
    signal(SIGINT, &signal_handler);

    i = 0;    
    lhost = (argc - i == 5) ? NULL : argv[i++];
    lport = argv[i++];
    phost = argv[i++];
    pport = argv[i++];
    rhost = argv[i++];
    rport = argv[i++];

    /* Check validity of ports (can't check ip's b/c might be host names) */
    ERROR_GOTO(!isnum(lport), "Invalid local port.", done);
    ERROR_GOTO(!isnum(pport), "Invalid proxy port.", done);
    ERROR_GOTO(!isnum(rport), "Invalid remote port.", done);
    
    srand(time(NULL));
    next_req_id = rand() % 0xffff;
    
    /* Create an empty list for the clients */
    clients = list_create(sizeof(client_t), p_client_cmp, p_client_copy,
                          p_client_free, 1);
    ERROR_GOTO(clients == NULL, "Error creating clients list.", done);

    /* Create and empty list for the connecting clients */
    conn_clients = list_create(sizeof(client_t), p_client_cmp, p_client_copy,
                               p_client_free, 1);
    ERROR_GOTO(conn_clients == NULL, "Error creating clients list.", done);

    /* Create a TCP server socket to listen for incoming connections */
    tcp_serv = sock_create(lhost, lport, ipver, SOCK_TYPE_TCP, 1, 1);
    ERROR_GOTO(tcp_serv == NULL, "Error creating TCP socket.", done);
    if(debug_level >= DEBUG_LEVEL1)
    {
        printf("Listening on TCP %s\n",
               sock_get_str(tcp_serv, addrstr, sizeof(addrstr)));
    }
    
    FD_ZERO(&client_fds);

    /* Initialize all the timers */
    timerclear(&timeout);
    check_interval.tv_sec = 0;
    check_interval.tv_usec = 500000;
    gettimeofday(&check_time, NULL);
    
    while(running)
    {
        if(!timerisset(&timeout))
            timeout.tv_usec = 50000;

        read_fds = client_fds;
        FD_SET(SOCK_FD(tcp_serv), &read_fds);

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

                ret = client_check_and_resend(client, curr_time);
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds, 1);
                    i--;
                    continue;
                }

                ret = client_check_and_send_keepalive(client, curr_time);
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds, 1);
                    i--;
                }
            }

            timeradd(&curr_time, &check_interval, &check_time);
        }
        
        if(num_fds == 0)
            continue;

        /* Check if pending TCP connection to accept and create a new client
           and UDP connection if one is ready */
        if(FD_ISSET(SOCK_FD(tcp_serv), &read_fds))
        {
            tcp_sock = sock_accept(tcp_serv);
            if(tcp_sock == NULL)
                continue;
            udp_sock = sock_create(phost, pport, ipver, SOCK_TYPE_UDP, 0, 1);
            if(udp_sock == NULL)
            {
                sock_close(tcp_sock);
                sock_free(tcp_sock);
                continue;
            }

            client = client_create(next_req_id++, tcp_sock, udp_sock, 1);
            if(!client || !tcp_sock || !udp_sock)
            {
                if(tcp_sock)
                    sock_close(tcp_sock);
                if(udp_sock)
                    sock_close(udp_sock);
            }
            else
            {
                client2 = list_add(conn_clients, client, 1);
                client_free(client);
                client = NULL;
                
                client_send_hello(client2, rhost, rport, CLIENT_ID(client2));
                client_add_tcp_fd_to_set(client2, &client_fds);
                client_add_udp_fd_to_set(client2, &client_fds);
            }
            
            sock_free(tcp_sock);
            sock_free(udp_sock);
            tcp_sock = NULL;
            udp_sock = NULL;

            num_fds--;
        }

        /* Check for pending handshakes from UDP connection */
        for(i = 0; i < LIST_LEN(conn_clients) && num_fds > 0; i++)
        {
            client = list_get_at(conn_clients, i);
            
            if(client_udp_fd_isset(client, &read_fds))
            {
                num_fds--;
                tmp_req_id = CLIENT_ID(client);

                ret = client_recv_udp_msg(client, data, sizeof(data),
                                          &tmp_id, &tmp_type, &tmp_len);
                if(ret == 0)
                    ret = handle_message(client, tmp_id, tmp_type,
                                         data, tmp_len);

                if(ret < 0)
                {
                    disconnect_and_remove_client(tmp_req_id, conn_clients,
                                                 &client_fds, 1);
                    i--;
                }
                else
                {
                    client = list_add(clients, client, 1);
                    list_delete_at(conn_clients, i);
                    client_remove_udp_fd_from_set(client, &read_fds);
                    i--;
                }
            }
        }

        /* Check if data is ready from any of the clients */
        for(i = 0; i < LIST_LEN(clients); i++)
        {
            client = list_get_at(clients, i);

            /* Check for UDP data */
            if(num_fds > 0 && client_udp_fd_isset(client, &read_fds))
            {
                num_fds--;

                ret = client_recv_udp_msg(client, data, sizeof(data),
                                          &tmp_id, &tmp_type, &tmp_len);
                if(ret == 0)
                    ret = handle_message(client, tmp_id, tmp_type,
                                         data, tmp_len);
                if(ret < 0)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds, 1);
                    i--;
                    continue; /* Don't go to check the TCP connection */
                }
            }

            /* Check for TCP data */
            if(num_fds > 0 && client_tcp_fd_isset(client, &read_fds))
            {
                ret = client_recv_tcp_data(client);
                if(ret == -1)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds, 1);
                    i--;
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
                disconnect_and_remove_client(CLIENT_ID(client), clients,
                                             &client_fds, 1);
                i--;
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
            }
        }
    }
    
  done:
    if(debug_level >= DEBUG_LEVEL1)
        printf("Cleaning up...\n");
    if(tcp_serv)
    {
        sock_close(tcp_serv);
        sock_free(tcp_serv);
    }
    if(udp_sock)
    {
        sock_close(udp_sock);
        sock_free(udp_sock);
    }
    if(clients)
        list_free(clients);
    if(conn_clients)
        list_free(conn_clients);
    if(debug_level >= DEBUG_LEVEL1)
        printf("Goodbye.\n");
    return 0;
}

/*
 * Closes the TCP and UDP connections for the client and remove its stuff from
 * the lists.
 */
void disconnect_and_remove_client(uint16_t id, list_t *clients,
                                  fd_set *fds, int full_disconnect)
{
    client_t *c;

    c = list_get(clients, &id);
    if(!c)
        return;

    client_remove_tcp_fd_from_set(c, fds);
    client_disconnect_tcp(c);

    if(full_disconnect)
    {
        client_send_goodbye(c);

        if(debug_level >= DEBUG_LEVEL1)
            printf("Client %d disconnected.\n", CLIENT_ID(c));

        client_remove_udp_fd_from_set(c, fds);
        client_disconnect_udp(c);
        list_delete(clients, &id);
    }
}

/*
 * Handles a message received from the UDP tunnel. Returns 0 if successful, -1
 * on some error it handled, or -2 if the client is to disconnect.
 */
int handle_message(client_t *c, uint16_t id, uint8_t msg_type,
                   char *data, int data_len)
{
    int ret = 0;
    char addrstr[ADDRSTRLEN];
    
    switch(msg_type)
    {
        case MSG_TYPE_GOODBYE:
            ret = -2;
            break;
            
        case MSG_TYPE_HELLOACK:
            client_got_helloack(c);
            CLIENT_ID(c) = id;
            ret = client_send_helloack(c, ntohs(*((uint16_t *)data)));

            if(debug_level >= DEBUG_LEVEL1)
            {
                sock_get_str(c->tcp_sock, addrstr, sizeof(addrstr));
                printf("New connection(%d): tcp://%s", CLIENT_ID(c), addrstr);
                sock_get_str(c->udp_sock, addrstr, sizeof(addrstr));
                printf(" -> udp://%s\n", addrstr);
            }
            break;
            
        case MSG_TYPE_DATA0:
        case MSG_TYPE_DATA1:
            ret = client_got_udp_data(c, data, data_len, msg_type);
            if(ret == 0)
                ret = client_send_tcp_data(c);
            break;
            
        case MSG_TYPE_ACK0:
        case MSG_TYPE_ACK1:
            ret = client_got_ack(c, msg_type);
            break;
            
        default:
            ret = -1;
            break;
    }

    return ret;
}

void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
            running = 0;
    }
}
