/*
 * Code based off of Beej's Guide to Network Programming
 */

#include "tcp_sock.h"

#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/select.h>
#include <sys/ioctl.h>

#include "printer.h"

#define MAXPORTLEN (6)

int create_server_sock(const char* interface, const char* port, int backlog, int family, int reuse)
{
    struct addrinfo hints;
    struct addrinfo* res = 0;
    struct addrinfo* walker;
    int sockfd;
    int error;
    int yes = 1;
    char str_ip[INET6_ADDRSTRLEN]; //should fit ipv4 too
    char str_port[MAXPORTLEN];
    
    memset(&hints, 0, sizeof(hints));
    memset(str_ip, 0, sizeof(str_ip));
    
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    if ((error = getaddrinfo(interface, port, &hints, &res)) != 0)
    {
        write_out(PRINT_ERROR, "Error attempting to call getaddrinfo: %s", gai_strerror(error));
        return -1;
    }
    
    write_out(PRINT_INFO, "Searching for interface to listen on...");
    write_raise_level();
    
    for (walker = res; walker; walker = walker->ai_next)
    {
        if ((sockfd = socket(walker->ai_family, walker->ai_socktype, walker->ai_protocol)) == -1)
        {
            write_out(PRINT_WARNING, "Invalid interface: %s", strerror(errno));
            write_raise_level();
            write_out(PRINT_WARNING, "Domain: %d, Type: %d, Protocol: %d", walker->ai_family, walker->ai_socktype, walker->ai_protocol);
            write_lower_level();
            
            continue;
        }
        
        if (reuse)
            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
                write_out(PRINT_WARNING, "Unable to set SO_REUSEADDR on socket: %s", strerror(errno));
        
        if (bind(sockfd, walker->ai_addr, walker->ai_addrlen) == -1)
        {
            getnameinfo((struct sockaddr*)walker->ai_addr, walker->ai_addrlen, str_ip, sizeof(str_ip), str_port, sizeof(str_port), NI_NUMERICHOST | NI_NUMERICSERV);
            
            write_out(PRINT_WARNING, "Unable to bind to interface: %s", strerror(errno));
            write_raise_level();
            write_out(PRINT_WARNING, "Domain: %d, Type: %d, Protocol: %d, Address: %s, Port: %s", walker->ai_family, walker->ai_socktype, walker->ai_protocol, str_ip, str_port);
            write_lower_level();
            close(sockfd);
            
            continue;
        }
        
        break;
    }
    
    if (!walker)
    {
        sockfd = 0;
        write_out(PRINT_ERROR, "Unable to find valid interface.");
        
        freeaddrinfo(res);
        write_lower_level();
        return -1;
    }
    
    write_lower_level();
    
    getnameinfo((struct sockaddr*)walker->ai_addr, walker->ai_addrlen, str_ip, sizeof(str_ip), str_port, sizeof(str_port), NI_NUMERICHOST | NI_NUMERICSERV);
    
    freeaddrinfo(res);
    
    if (listen(sockfd, backlog) == -1)
    {
        write_out(PRINT_ERROR, "Unable to listen on interface %s on port %s.", str_ip, str_port);
        close(sockfd);
        return -1;
    }
    write_out(PRINT_INFO, "Listening on on interface %s on port %s.", str_ip, str_port);
    return sockfd;
}

int accept_connection(int sockfd, struct sockaddr_storage* out_opt_client_addr)
{
    struct sockaddr_storage client_addr;
    struct sockaddr_storage* ptr_to_client_addr;
    socklen_t addr_size;
    int newfd;
    char str_ip[INET6_ADDRSTRLEN]; //should fit ipv4 too
    char str_port[MAXPORTLEN];
    
    addr_size = sizeof(struct sockaddr_storage);
    if (out_opt_client_addr)
        ptr_to_client_addr = out_opt_client_addr;
    else
        ptr_to_client_addr = &client_addr;
    
    newfd = accept(sockfd, (struct sockaddr*)ptr_to_client_addr, &addr_size);
    if (newfd == -1)
        write_out(PRINT_WARNING, "Unable to accept client connection: %s", strerror(errno));
    else
    {
        getnameinfo((struct sockaddr*)ptr_to_client_addr, sizeof(struct sockaddr_storage), str_ip, sizeof(str_ip), str_port, sizeof(str_port), NI_NUMERICHOST | NI_NUMERICSERV);
        write_out(PRINT_INFO, "Accepted connection from remote client %s on port %s", str_ip, str_port);
    }
    
    return newfd;
}

int do_connect(const char* target, const char* port)
{
    int sockfd;
    struct addrinfo hints;
    struct addrinfo* res;
    struct addrinfo* walker;
    int error;
    char str_ip[INET6_ADDRSTRLEN]; //should fit ipv4 too
    char str_port[MAXPORTLEN];
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if ((error = getaddrinfo(target, port, &hints, &res)) != 0)
    {
        write_out(PRINT_ERROR, "Error attempting to call getaddrinfo: %s", gai_strerror(error));
        return -1;
    }
    
    write_out(PRINT_INFO, "Attempting to connect...");
    write_raise_level();
    
    for (walker = res; walker; walker = walker->ai_next)
    {
        if ((sockfd = socket(walker->ai_family, walker->ai_socktype, walker->ai_protocol)) == -1)
        {
            write_out(PRINT_WARNING, "Invalid socket: %s", gai_strerror(error));
            continue;
        }
        
        if (connect(sockfd, walker->ai_addr, walker->ai_addrlen) == -1)
        {
            write_out(PRINT_WARNING, "Unable to establish connection with socket: %s", gai_strerror(error));
            close(sockfd);
            continue;
        }
        
        break;
    }
    
    if (!walker)
    {
        write_out(PRINT_ERROR, "Failed to establish connection with server at %s on port %s.", target, port);
        return -1;
    }
    
    write_lower_level();
    
    getnameinfo((struct sockaddr*)walker->ai_addr, walker->ai_addrlen, str_ip, sizeof(str_ip), str_port, sizeof(str_port), NI_NUMERICHOST | NI_NUMERICSERV);
    write_out(PRINT_INFO, "Established connection to %s on port %s.", str_ip, str_port);
    
    freeaddrinfo(res);
    
    return sockfd;
}
