// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "utils.h"

#include "ipc.h"

int create_socket(void)
{
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
	int send_id;
	send_id = send(fd, buf, len, 0);
	DIE(send_id == -1, "send_socket");
	return send_id;
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
