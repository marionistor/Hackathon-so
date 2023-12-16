// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int sockfd;
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	DIE(sockfd == -1, "socket");
	return sockfd;
}

int connect_socket(int fd)
{
	/* TODO: Implement connect_socket(). */
	return -1;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	return -1;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	return -1;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
}
