#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>

int main()
{
	int rc = 0;
	char buf[4096];
	size_t i, s;

	s = 0;
	while ((i = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		s += i;
	}
	if (i < 0) {
		fprintf(stderr, "read() : %m\n");
		rc = 1;
	}
	syslog(LOG_INFO, "%d bytes received\n", s);

	return rc;
}
