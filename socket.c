/*
 * Project: udptunnel
 * File: socket.c
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
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif /* ~WIN32 */

#include "socket.h"
#include "common.h"

extern int debug_level;

void print_hexdump(char *data, int len);

/*
 * Allocates and returns a new socket structure.
 * host - string of host or address to listen on (can be NULL for servers)
 * port - string of port number or service (can be NULL for clients)
 * ipver - SOCK_IPV4 or SOCK_IPV6
 * sock_type - SOCK_TYPE_TCP or SOCK_TYPE_UDP
 * is_serv - 1 if is a server socket to bind and listen on port, 0 if client
 * conn - call socket(), bind(), and listen() if is_serv, or connect()
 *        if not is_serv. Doesn't call these if conn is 0.
 */
socket_t *sock_create(char *host, char *port, int ipver, int sock_type,
                      int is_serv, int conn)
{
    socket_t *sock = NULL;
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct sockaddr *paddr;
    int ret;
    
    sock = calloc(1, sizeof(*sock));
    if(!sock)
        return NULL;

    paddr = SOCK_PADDR(sock);
    sock->fd = -1;

    switch(sock_type)
    {
        case SOCK_TYPE_TCP:
            sock->type = SOCK_STREAM;
            break;
        case SOCK_TYPE_UDP:
            sock->type = SOCK_DGRAM;
            break;
        default:
            goto error;
    }

    /* If both host and port are null, then don't create any socket or
       address, but still set the AF. */
    if(host == NULL && port == NULL)
    {
        sock->addr.ss_family = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
        goto done;
    }
    
    /* Setup type of address to get */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = sock->type;
    hints.ai_flags = is_serv ? AI_PASSIVE : 0;

    /* Get address from the machine */
    ret = getaddrinfo(host, port, &hints, &info);
    PERROR_GOTO(ret != 0, "getaddrinfo", error);
    memcpy(paddr, info->ai_addr, info->ai_addrlen);
    sock->addr_len = info->ai_addrlen;

    if(conn)
    {
        if(sock_connect(sock, is_serv) != 0)
            goto error;
    }

  done:
    if(info)
        freeaddrinfo(info);
    
    return sock;
    
  error:
    if(sock)
        free(sock);
    if(info)
        freeaddrinfo(info);
    
    return NULL;
}

socket_t *sock_copy(socket_t *sock)
{
    socket_t *new;

    new = malloc(sizeof(*sock));
    if(!new)
        return NULL;

    memcpy(new, sock, sizeof(*sock));

    return new;
}

/*
 * If the socket is a server, start listening. If it's a client, connect to
 * to destination specified in sock_create(). Returns -1 on error or -2 if
 * the sockect is already connected.
 */
int sock_connect(socket_t *sock, int is_serv)
{
    struct sockaddr *paddr;
    int ret;

    if(sock->fd != -1)
        return -2;
        
    paddr = SOCK_PADDR(sock);
    
    /* Create socket file descriptor */
    sock->fd = socket(paddr->sa_family, sock->type, 0);
    PERROR_GOTO(sock->fd < 0, "socket", error);
    
    if(is_serv)
    {
        /* Bind socket to address and port */
        ret = bind(sock->fd, paddr, sock->addr_len);
        PERROR_GOTO(ret != 0, "bind", error);
        
        /* Start listening on the port if tcp */
        if(sock->type == SOCK_STREAM)
        {
            ret = listen(sock->fd, BACKLOG);
            PERROR_GOTO(ret != 0, "listen", error);
        }
    }
    else
    {
        /* Connect to the server if tcp */
        if(sock->type == SOCK_STREAM)
        {
            ret = connect(sock->fd, paddr, sock->addr_len);
            PERROR_GOTO(ret != 0, "connect", error);
        }
    }

    return 0;
    
  error:
    return -1;
}

/*
 * Accept a new connection and return a newly allocated socket representing
 * the remote connection.
 */
socket_t *sock_accept(socket_t *serv)
{
    socket_t *client;
    
    client = calloc(1, sizeof(*client));
    if(!client)
        goto error;

    client->type = serv->type;
    client->addr_len = sizeof(struct sockaddr_storage);
    client->fd = accept(serv->fd, SOCK_PADDR(client), &client->addr_len);
    PERROR_GOTO(SOCK_FD(client) < 0, "accept", error);
        
    return client;
    
  error:
    if(client)
        free(client);

    return NULL;
}

/*
 * Closes the file descriptor for the socket.
 */
void sock_close(socket_t *s)
{
    if(s->fd != -1)
    {
#ifdef WIN32
        closesocket(s->fd);
#else
        close(s->fd);
#endif
        s->fd = -1;
    }
}

/*
 * Frees the socket structure.
 */
void sock_free(socket_t *s)
{
    free(s);
}

/*
 * Returns non zero if IP addresses and ports are same, or 0 if not.
 */
int sock_addr_equal(socket_t *s1, socket_t *s2)
{
    if(s1->addr_len != s2->addr_len)
        return 0;
    
    return (memcmp(&s1->addr, &s2->addr, s1->addr_len) == 0);
}

/*
 * Compares only the IP address of two sockets
 */
int sock_ipaddr_cmp(socket_t *s1, socket_t *s2)
{
    char *a1;
    char *a2;
    int len;
    
    if(s1->addr.ss_family != s2->addr.ss_family)
        return s1->addr.ss_family - s2->addr.ss_family; /* ? */

    switch(s1->addr.ss_family)
    {
        case AF_INET:
            a1 = (char *)(&SIN(&s1->addr)->sin_addr);
            a2 = (char *)(&SIN(&s2->addr)->sin_addr);
            len = 4; /* 32 bits */
            break;
            
        case AF_INET6:
            a1 = (char *)(&SIN6(&s1->addr)->sin6_addr);
            a2 = (char *)(&SIN6(&s2->addr)->sin6_addr);
            len = 16; /* 128 bits */
            break;

        default:
            return 0; /* ? */
    }

    return memcmp(a1, a2, len);
}

/*
 * Compares only the ports of two sockets
 */
int sock_port_cmp(socket_t *s1, socket_t *s2)
{
    uint16_t p1;
    uint16_t p2;

    if(s1->addr.ss_family != s2->addr.ss_family)
        return s1->addr.ss_family - s2->addr.ss_family; /* ? */
    
    switch(s1->addr.ss_family)
    {
        case AF_INET:
            p1 = ntohs(SIN(&s1->addr)->sin_port);
            p2 = ntohs(SIN(&s2->addr)->sin_port);
            
        case AF_INET6:
            p1 = ntohs(SIN6(&s1->addr)->sin6_port);
            p2 = ntohs(SIN6(&s2->addr)->sin6_port);
            
        default:
            return 0; /* ? */
    }

    return p1 - p2;
}

/*
 * Returns 1 if the address in the socket is 0.0.0.0 or ::, and 0 if not.
 */
int sock_isaddrany(socket_t *s)
{
    struct in6_addr zaddr = IN6ADDR_ANY_INIT;

    switch(s->addr.ss_family)
    {
        case AF_INET:
            return (SIN(&s->addr)->sin_addr.s_addr == INADDR_ANY) ? 1 : 0;

        case AF_INET6:
            if(memcmp(&SIN6(&s->addr)->sin6_addr, &zaddr, sizeof(zaddr)) == 0)
                return 1;
            else
                return 0;

        default:
            return 1;
    }
}
/*
 * Gets the string representation of the IP address and port from addr. Will
 * store result in buf, which len must be at least INET6_ADDRLEN + 6. Returns a
 * pointer to buf. String will be in the form of "ip_address:port".
 */
#ifdef WIN32
char *sock_get_str(socket_t *s, char *buf, int len)
{
    DWORD plen = len;

    if(WSAAddressToString(SOCK_PADDR(s), SOCK_LEN(s), NULL, buf, &plen) != 0)
        return NULL;

    return buf;
}
#else
char *sock_get_str(socket_t *s, char *buf, int len)
{
    void *src_addr;
    char addr_str[INET6_ADDRSTRLEN];
    uint16_t port;
    
    switch(s->addr.ss_family)
    {
        case AF_INET:
            src_addr = (void *)&SIN(&s->addr)->sin_addr;
            port = ntohs(SIN(&s->addr)->sin_port);
            break;

        case AF_INET6:
            src_addr = (void *)&SIN6(&s->addr)->sin6_addr;
            port = ntohs(SIN6(&s->addr)->sin6_port);
            break;
            
        default:
            return NULL;
    }

    if(inet_ntop(s->addr.ss_family, src_addr,
                 addr_str, sizeof(addr_str)) == NULL)
        return NULL;

    snprintf(buf, len, (s->addr.ss_family == AF_INET6) ? "[%s]:%hu" : "%s:%hu",
             addr_str, port);

    return buf;
}
#endif /*WIN32*/

/*
 * Gets the string representation of the IP address and puts it in buf. Will
 * return the pointer to buf or NULL if there was an error.
 */
#ifdef WIN32
char *sock_get_addrstr(socket_t *s, char *buf, int len)
{
    socket_t *copy = NULL;
    
    if((copy = sock_copy(s)) == NULL)
        return NULL;
    
    switch(copy->addr.ss_family)
    {
        case AF_INET:
            SIN(&copy->addr)->sin_port = 0;
            break;

        case AF_INET6:
            SIN6(&copy->addr)->sin6_port = 0;
            break;

        default:
            return NULL;
    }

    /* Calls to this will put the port in the string, so seting the port to 0
     * will just return the IP address. */
    if(sock_get_str(copy, buf, len) == NULL)
        goto error;

    free(copy);    
    return buf;

  error:
    if(copy)
        free(copy);
    
    return NULL;
}
#else /*~WIN32*/
char *sock_get_addrstr(socket_t *s, char *buf, int len)
{
    void *src_addr;

    switch(s->addr.ss_family)
    {
        case AF_INET:
            src_addr = (void *)&SIN(&s->addr)->sin_addr;
            break;

        case AF_INET6:
            src_addr = (void *)&SIN6(&s->addr)->sin6_addr;
            break;
            
        default:
            return NULL;
    }

    if(inet_ntop(s->addr.ss_family, src_addr, buf, len) == NULL)
        return NULL;

    return buf;
}
#endif /*WIN32*/

/*
 * Returns the 16-bit port number in host byte order from the passed sockaddr.
 */
uint16_t sock_get_port(socket_t *s)
{
    switch(s->addr.ss_family)
    {
        case AF_INET:
            return (uint16_t)ntohs(SIN(&s->addr)->sin_port);

        case AF_INET6:
            return (uint16_t)ntohs(SIN6(&s->addr)->sin6_port);
    }

    return 0;
}

/*
 * Receives data from the socket. Calles recv() or recvfrom() depending on the
 * type of socket. Ignores the 'from' argument if type is for TCP, or puts
 * remove address in from socket for UDP. Reads up to len bytes and puts it in
 * data. Returns number of bytes sent, or 0 if remote host disconnected, or -1
 * on error.
 */
int sock_recv(socket_t *sock, socket_t *from, char *data, int len)
{
    int bytes_recv = 0;
    socket_t tmp;
    
    switch(sock->type)
    {
        case SOCK_STREAM:
            bytes_recv = recv(sock->fd, data, len, 0);
            break;

        case SOCK_DGRAM:
            if(!from)
                from = &tmp; /* In case caller wants to ignore from socket */
            from->fd = sock->fd;
            from->addr_len = sock->addr_len;
            bytes_recv = recvfrom(from->fd, data, len, 0,
                                  SOCK_PADDR(from), &SOCK_LEN(from));
            break;
    }
    
    PERROR_GOTO(bytes_recv < 0, "recv", error);
    ERROR_GOTO(bytes_recv == 0, "disconnect", disconnect);

    if(debug_level >= DEBUG_LEVEL3)
    {
        printf("sock_recv: type=%d, fd=%d, bytes=%d\n",
               sock->type, sock->fd, bytes_recv);
        print_hexdump(data, bytes_recv);
    }
    
    return bytes_recv;
    
  disconnect:
    return 0;
    
  error:
    return -1;
}

/*
 * Sends len bytes in data to the socket connection. Returns number of bytes
 * sent, or 0 on disconnect, or -1 on error.
 */
int sock_send(socket_t *to, char *data, int len)
{
    int bytes_sent = 0;
    int ret;
    
    switch(to->type)
    {
        case SOCK_STREAM:
            while(bytes_sent < len)
            {
                ret = send(to->fd, data + bytes_sent, len - bytes_sent, 0);
                PERROR_GOTO(ret < 0, "send", error);
                ERROR_GOTO(ret == 0, "disconnected", disconnect);
                bytes_sent += ret;
            }
            break;

        case SOCK_DGRAM:
            bytes_sent = sendto(to->fd, data, len, 0,
                                SOCK_PADDR(to), to->addr_len);
            PERROR_GOTO(bytes_sent < 0, "sendto", error);
            break;

        default:
            return 0;
    }

    if(debug_level >= DEBUG_LEVEL3)
    {
        printf("sock_send: type=%d, fd=%d, bytes=%d\n",
               to->type, to->fd, bytes_sent);
        print_hexdump(data, bytes_sent);
    }

    return bytes_sent;

  disconnect:
    return 0;
    
  error:
    return -1;
}

/*
 * Checks validity of an IP address string based on the version
 */
int isipaddr(char *ip, int ipver)
{
    char addr[sizeof(struct in6_addr)];
    int len;
    int af_type;

    af_type = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
    len = sizeof(addr);
    
#ifdef WIN32
    if(WSAStringToAddress(ip, af_type, NULL, PADDR(addr), &len) == 0)
        return 1;
#else /*~WIN32*/    
    if(inet_pton(af_type, ip, addr) == 1)
        return 1;
#endif /*WIN32*/

    return 0;
}

/*
 * Debugging function to print a hexdump of data with ascii, for example:
 * 00000000  74 68 69 73 20 69 73 20  61 20 74 65 73 74 20 6d  this is  a test m
 * 00000010  65 73 73 61 67 65 2e 20  62 6c 61 68 2e 00        essage.  blah..
 */
void print_hexdump(char *data, int len)
{
    int line;
    int max_lines = (len / 16) + (len % 16 == 0 ? 0 : 1);
    int i;
    
    for(line = 0; line < max_lines; line++)
    {
        printf("%08x  ", line * 16);

        /* print hex */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
                printf("%02x ", (uint8_t)data[i]);
            else
                printf("   ");
        }
        printf(" ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
                printf("%02x ", (uint8_t)data[i]);
            else
                printf("   ");
        }

        printf(" ");
        
        /* print ascii */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= data[i] && data[i] <= 126)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            else
                printf(" ");
        }
        printf(" ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= data[i] && data[i] <= 126)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            else
                printf(" ");
        }

        printf("\n");
    }
}
