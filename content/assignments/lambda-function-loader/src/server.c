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

int fd;

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

	return 0;
}

static int lib_load(struct lib *lib)
{
	int rc;

	strcpy(lib->outputfile, OUTPUT_TEMPLATE);
	fd = mkstemp(lib->outputfile);
	if (fd == -1)
		return -1;

	rc = dup2(fd, STDOUT_FILENO);
	if (rc == -1) {
		return -1;
	}

	lib->handle = dlopen(lib->libname, RTLD_LAZY);

	if (lib->handle == NULL) {
		if (!strlen(lib->funcname)) {
			printf("Error: %s could not be executed.\n", lib->libname);
		} else if (!strlen(lib->filename)) {
			printf("Error: %s %s could not be executed.\n", lib->libname, lib->funcname);
		} else {
			printf("Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		}
		return -1;
	}

	if (!strlen(lib->funcname)) {
		strcpy(lib->funcname, "run");
	}

	if (!strlen(lib->filename)) {
		lib->run = dlsym(lib->handle, lib->funcname);
		lib->p_run = NULL;
		if (lib->run == NULL) {
			printf("Error: %s could not be executed.\n", lib->libname);
			return -1;
		}
		return 0;
	}

	lib->p_run = dlsym(lib->handle, lib->funcname);
	lib->run = NULL;
	if (lib->p_run == NULL) {
		printf("Error: %s %s %s could not be executed.\n", lib->libname, lib->funcname, lib->filename);
		return -1;
	}
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	int rc;

	if (!strlen(lib->filename)) {
		lib->run();

		rc = close(fd);
		if (rc == -1)
			return -1;

		return 0;
	}

	lib->p_run(lib->filename);

	rc = close(fd);
	if (rc == -1)
		return -1;

	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	int rc;

	rc = dlclose(lib->handle);

	if (rc == -1)
		return -1;

	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	free(lib->filename);
	free(lib->funcname);
	free(lib->libname);
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

	setvbuf(stdout, NULL, _IONBF, 0);

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

		pid_t pid;

		pid = fork();

		switch (pid) {
			case -1:
				fprintf(stderr, "fork failed\n");
				break;
			case 0:
				daemon(1, 1);
				memset(buf, 0, BUFSIZE);
				ssize_t recv_id = recv_socket(connectfd, buf, BUFSIZE);
				if (recv_id == -1) {
					fprintf(stderr, "failed recv");
					return -1;
				}

				lib_prehooks(&lib);

				parse_command(buf, lib.libname, lib.funcname, lib.filename);

				/* TODO - parse message with parse_command and populate lib */
				/* TODO - handle request from client */
				ret = lib_run(&lib);
				send_socket(connectfd, lib.outputfile, strlen(lib.outputfile));
				free(lib.outputfile);
				break;
			default:
				break;
		}

		close_socket(connectfd);
	}

	close_socket(listenfd);

	return 0;
}
