#ifndef __TCP_SOCK_H
#define __TCP_SOCK_H

#include <sys/socket.h>

//pass null to interface to listen on all interfaces
//returns -1 on failure
int create_server_sock(const char* interface, const char* port, int backlog, int family, int reuse);

//returns -1 on failure
int accept_connection(int sockfd, struct sockaddr_storage* opt_client_addr);

int do_connect(const char* target, const char* port);

#endif