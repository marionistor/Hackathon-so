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
	int send_id = 0, counter = 0;

	// Write to the socket until the end of the buffer
	while (send_id < len) {
		counter = write(fd, buf + send_id, len - send_id);
		DIE(counter == -1, "send_socket");
		if (counter == 0)
			break;

		send_id += counter;
	}

	return send_id;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	int recv_id = 0, counter = 0;

	// Read from the socket until the end of the buffer
	while (recv_id < len) {
		counter = read(fd, buf + recv_id, len - recv_id);
		DIE(counter == -1, "recv_socket");
		if (counter == 0)
			break;
		recv_id += counter;
	}

	return recv_id;
}

void close_socket(int fd)
{
	int rc;
	rc = close(fd);
	DIE(rc < 0, "clozz`se");
}
