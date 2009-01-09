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
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/select.h>
#include "common.h"
#include "message.h"
#include "socket.h"
#include "client.h"
#include "list.h"

static int running = 1;

/* internal functions */
int handle_message(client_t *c, uint16_t id, uint8_t msg_type,
                   char *data, int data_len);
void disconnect_and_remove_client(uint16_t id, list_t *clients, fd_set *fds);
void usage(char *prog);
void signal_handler(int sig);

int main(int argc, char *argv[])
{
    char *lhost, *lport, *phost, *pport, *rhost, *rport;
    list_t *clients;
    client_t *client;
    client_t *client2;
    socket_t *tcp_serv = NULL;
    socket_t *tcp_sock = NULL;
    socket_t *udp_sock = NULL;
    char data[MSG_MAX_LEN];

    struct timeval curr_time;
    struct timeval check_time;
    struct timeval check_interval;
    struct timeval timeout;
    fd_set client_fds;
    fd_set read_fds;
    uint16_t tmp_id;
    uint8_t tmp_type;
    uint16_t tmp_len;
    int num_fds;
    
    int ret;
    int i;
    
    if(argc != 6 && argc != 7)
    {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT, &signal_handler);

    /* Set host and port string pointers to args from the command line */
    i = 1;
    lhost = (argc == 6) ? NULL : argv[i++];
    lport = argv[i++];
    phost = argv[i++];
    pport = argv[i++];
    rhost = argv[i++];
    rport = argv[i++];

    /* Create an empty list for the clients */
    clients = list_create(sizeof(client_t), p_client_cmp, p_client_copy,
                          p_client_free);
    ERROR_GOTO(clients == NULL, "Error creating clients list.", done);

    /* Create a TCP server socket to listen for incoming connections */
    tcp_serv = sock_create(lhost, lport, SOCK_IPV4, SOCK_TYPE_TCP, 1, 1);
    ERROR_GOTO(tcp_serv == NULL, "Error creating TCP socket.", done);

    FD_ZERO(&client_fds);

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
                ret = client_check_and_resend(client);
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
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
            udp_sock = sock_create(phost, pport, SOCK_IPV4,
                                   SOCK_TYPE_UDP, 0, 1);

            client = client_create(0, tcp_sock, udp_sock, 1);
            if(!client || !tcp_sock || !udp_sock)
            {
                if(tcp_sock)
                    sock_close(tcp_sock);
                if(udp_sock)
                    sock_close(udp_sock);
            }
            else
            {
                client2 = list_add(clients, client);
                client_free(client);
                client = NULL;
                
                client_send_hello(client2, rhost, rport);
                client_add_tcp_fd_to_set(client2, &client_fds);
                client_add_udp_fd_to_set(client2, &client_fds);
            }
            
            sock_free(tcp_sock);
            sock_free(udp_sock);
            tcp_sock = NULL;
            udp_sock = NULL;

            num_fds--;
        }

        /* Check if data is ready from any of the clients */
        for(i = 0; i < LIST_LEN(clients) && num_fds > 0; i++)
        {
            client = list_get_at(clients, i);

            /* Check for UDP data */
            if(client_udp_fd_isset(client, &read_fds))
            {
                num_fds--;

                ret = client_recv_udp_msg(client, data, sizeof(data),
                                          &tmp_id, &tmp_type, &tmp_len);
                if(ret == 0)
                    ret = handle_message(client, tmp_id, tmp_type,
                                         data, tmp_len);
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
                    i--;
                    continue; /* Don't go to check the TCP connection */
                }
            }

            /* Check for TCP data */
            if(client_tcp_fd_isset(client, &read_fds))
            {
                num_fds--;

                ret = client_recv_tcp_data(client);
                if(ret == 0)
                    ret = client_send_udp_data(client);
                else if(ret == 1)
                    usleep(1000);
                
                if(ret == -2)
                {
                    disconnect_and_remove_client(CLIENT_ID(client), clients,
                                                 &client_fds);
                    i--;
                }
            }
        }
    }
    
  done:
    if(DEBUG)
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
    if(DEBUG)
        printf("Goodbye.\n");
    return 0;
}

/*
 * Closes the TCP and UDP connections for the client and remove its stuff from
 * the lists.
 */
void disconnect_and_remove_client(uint16_t id, list_t *clients, fd_set *fds)
{
    client_t *c;

    c = list_get(clients, &id);
    if(!c)
        return;

    client_send_goodbye(c);
    
    client_remove_udp_fd_from_set(c, fds);
    client_remove_tcp_fd_from_set(c, fds);
    client_disconnect_tcp(c);
    client_disconnect_udp(c);
    list_delete(clients, &id);
}

/*
 * Handles a message received from the UDP tunnel. Returns 0 if successful, -1
 * on some error it handled, or -2 if the client is to disconnect.
 */
int handle_message(client_t *c, uint16_t id, uint8_t msg_type,
                   char *data, int data_len)
{
    int ret = 0;

    switch(msg_type)
    {
        case MSG_TYPE_GOODBYE:
            ret = -2;
            break;
            
        case MSG_TYPE_HELLOACK:
            client_got_helloack(c);
            if(CLIENT_ID(c) == 0)
                CLIENT_ID(c) = id;
            ret = client_send_helloack(c);
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

void usage(char *prog)
{
    printf("usage: %s [local host] <local port> <proxy host> <proxy port>"
           "\n            <remote host> <remote port>\n", prog);
}

void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
            running = 0;
    }
}
