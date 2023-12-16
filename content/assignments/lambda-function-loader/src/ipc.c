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
	int sockfd;
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		fprintf(stderr, "failed socket\n");
		return -1;
	}
	return sockfd;
}

int connect_socket(int fd)
{
	// Create a socket address and connect to the server
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);
	int rc;
	rc = connect(fd, (struct sockaddr *) &addr, sizeof(addr));
	if (rc == -1) {
		fprintf(stderr, "failed connect\n");
		return -1;
	}

	return rc;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	ssize_t bytes_sent = send(fd, buf, len, 0);

	if (bytes_sent == -1) {
		fprintf(stderr, "failed send\n");
		return -1;
	}

	return bytes_sent;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	ssize_t bytes_recv = recv(fd, buf, len, 0);

	if (bytes_recv == -1) {
		fprintf(stderr, "failed recv\n");
		return -1;
	}

	return bytes_recv;
}

void close_socket(int fd)
{
	int rc;
	rc = close(fd);
	if (rc == -1) {
		fprintf(stderr, "failed close\n");
	}
}
