// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	lib->libname = calloc(BUFSIZE, sizeof(char));
	if (lib->libname == NULL)
		return -1;
	lib->funcname = calloc(BUFSIZE, sizeof(char));
	if (lib->funcname == NULL)
		return -1;
	lib->filename = calloc(BUFSIZE, sizeof(char));
	if (lib->filename == NULL)
		return -1;
	lib->outputfile = calloc(BUFSIZE, sizeof(char));
	if (lib->outputfile == NULL)
		return -1;

	strcpy(lib->outputfile, OUTPUT_TEMPLATE);
	int err = mkstemp(lib->outputfile);
	if (err == -1)
		return -1;

	return 0;
}

static int lib_load(struct lib *lib)
{
	lib->handle = dlopen(lib->filename, RTLD_LAZY);
	if (lib->handle == NULL)
		return -1;

	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	/* TODO: Implement server connection. */
	int ret;
	struct lib lib;
	struct sockaddr_un addr, raddr;
	socklen_t raddrlen;
	int listenfd, connectfd;
	char buf[BUFSIZE];

	remove(SOCKET_NAME);

	listenfd = create_socket();
	if (listenfd == -1) {
		fprintf(stderr, "unix socket");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(SOCKET_NAME), "%s", SOCKET_NAME);
	ret	= bind(listenfd, (struct sockaddr *) &addr, sizeof(addr));
	if (ret == -1) {
		fprintf(stderr, "bind unix socket");
		return -1;
	}

	ret = listen(listenfd, MAX_CLIENTS);
	if (ret == -1) {
		fprintf(stderr, "listen unix socket");
		return -1;
	}

	while (1) {
		/* TODO - get message from client */

		connectfd = accept(listenfd, (struct sockaddr *) &raddr, &raddrlen);
		if (connectfd == -1) {
			fprintf(stderr, "accept unix socket");
			return -1;
		}

		memset(buf, 0, BUFSIZE);
		ssize_t recv_id = recv_socket(connectfd, buf, BUFSIZE);
		if (recv_id == -1) {
			fprintf(stderr, "failed recv");
			return -1;
		}

		lib_prehooks(&lib);

		parse_command(buf, lib.libname, lib.funcname, lib.filename);

		// send_socket(connectfd, buf, BUFSIZE);

		// printf("%s\n", buf);

		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
		ret = lib_run(&lib);
		close_socket(connectfd);
	}

	close_socket(listenfd);

	return 0;
}
