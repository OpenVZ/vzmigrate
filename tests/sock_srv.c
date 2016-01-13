#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>

int main(int argc, char **argv, char **envp)
{
	int rc = 0;
	int sock;
	struct sockaddr_in saddr;
	struct sockaddr_in caddr;
	int caddr_len;
	unsigned short port = 1812;
	int fd;
//	char buf[10*1024*1024];
	char buf[16384];
	int i, s;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() err : %m\n");
		exit (1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		fprintf(stderr, "bind() : %m\n");
		rc = 1;
		goto cleanup;
	}

	if (listen(sock, SOMAXCONN)) {
		fprintf(stderr, "listen() err : %m\n");
		rc = 1;
		goto cleanup;
	}

//	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL)|O_NONBLOCK);
	caddr_len = sizeof(caddr);
	if ((fd = accept(sock, (struct sockaddr *)&caddr, &caddr_len)) < 0) {
		fprintf(stderr, "accept() err : %m\n");
		rc = 1;
		goto cleanup;
	}

//	fcntl(fd, F_SETFL, fcntl(sock, F_GETFL)|O_NONBLOCK);
	s = 0;
	while ((i = read(fd, buf, sizeof(buf)) > 0)) {
		s += i;
	}
	if (i < 0) {
		fprintf(stderr, "read() : %m\n");
		rc = 1;
		goto cleanup;
	}
	printf("%d bytes received\n", s);
	close(fd);
cleanup:
	close(sock);

	return rc;
}
