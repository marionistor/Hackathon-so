// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"
#include "utils/utils.h"

int create_socket(void)
{
	int sockfd;
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	DIE(sockfd == -1, "socket");
	return sockfd;
}

int connect_socket(int fd)
{
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);
	int rc;
	rc = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(rc < 0, "connect");
	return rc;
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
	int rc;
	rc = close(fd);
	DIE(rc < 0, "clozz`se");
}
