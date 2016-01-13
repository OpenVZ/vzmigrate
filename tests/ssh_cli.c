#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <getopt.h>
#include <libgen.h>

#include "util.h"

size_t bufsize = 4096;
char *password = NULL;

static void usage(const char * progname, int rc)
{
	fprintf(stderr,"Usage:\n");
	fprintf(stderr,"%s [-b bufsize] [-p password] host\n", progname);
	exit(rc);
}

/* command line parsing */
int parse_cmd_line(int argc, char *argv[])
{
	int c;
	char *p;
	struct option options[] =
	{
		{"bufsize", required_argument, NULL, 'b'},
		{"password", required_argument, NULL, 'p'},
		{ NULL, 0, NULL, 0 }
	};

	while (1)
	{
		c = getopt_long(argc, argv, "b:p:", options, NULL);
		if (c == -1)
			break;
		switch (c)
		{
		case 'b':
			if (optarg == NULL) {
				fprintf(stderr, "Bad bufsize value");
				return 1;
			}
			if (strlen(optarg) == 0) {
				fprintf(stderr, "Bad bufsize value");
				return 1;
			}
			for(p=optarg; *p; p++) {
				if (!isdigit(*p)) {
					fprintf(stderr, "Bad bufsize: %s", optarg);
					return 1;
				}
			}
			bufsize = strtol(optarg, NULL, 10);
			break;
		case 'p':
			if (optarg == NULL) {
				fprintf(stderr, "Bad password");
				return 1;
			}
			if (strlen(optarg) == 0) {
				fprintf(stderr, "Bad password");
				return 1;
			}
			if ((password = strdup(optarg)) == NULL) {
				fprintf(stderr, "strdup() : %m");
				return 1;
			}
			break;
		default :
			return 1;
		}
	}

	return 0;
}


int main(int argc, char **argv)
{
	int rc = 0;
	pid_t ssh_pid, pid;
	int status;
	int retcode;
	int in[2], out[2];
	int max_size = 813*1024*1024;
	int i, j;
	char *buf;
	struct string_list params;
	char **ssh_argv;

	if ( argc < 2 )
		usage(basename(argv[0]), 1);

	if (parse_cmd_line(argc, argv))
		return 1;

	if ((buf = malloc(bufsize)) == NULL) {
		fprintf(stderr, "malloc() : %m");
		return 1;
	}

	string_list_init(&params);
	string_list_add(&params, "ssh");
	string_list_add(&params, "-T");
//	string_list_add(&params, "-q");
	string_list_add(&params, "-c");
	string_list_add(&params, "arcfour");
	string_list_add(&params, "-o");
	string_list_add(&params, "StrictHostKeyChecking=no");
	string_list_add(&params, "-o");
	string_list_add(&params, "CheckHostIP=no");
	string_list_add(&params, "-o");
	string_list_add(&params, "UserKnownHostsFile=/dev/null");
	string_list_add(&params, "-o");
	string_list_add(&params,
		"PreferredAuthentications=publickey,password,keyboard-interactive");
	string_list_add(&params, argv[optind]);
	string_list_add(&params, "/root/vzmigrate/tests/ssh_reader");
	string_list_to_array(&params, &ssh_argv);
	string_list_clean(&params);

	if ((pipe(in) < 0) || (pipe(out) < 0)) {
		fprintf(stderr, "pipe() : %m\n");
		return 1;
	}

	ssh_pid = fork();
	if (ssh_pid < 0) {
		close(in[1]); close(out[0]);
		close(in[0]); close(out[1]);
		fprintf(stderr, "fork() : %m\n");
		return 1;
	} else if (ssh_pid == 0) {
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		/* redirect stdout to out and stdin to in */
		close(STDIN_FILENO); close(STDOUT_FILENO);
		close(in[1]); close(out[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		close(in[0]); close(out[1]);
		setsid();
		if (password) {
			/* if password is needs, create askpass file */
			int fd;
			FILE *fp;
			char path[PATH_MAX+1];

			snprintf(path, sizeof(path), "/tmp/askpass.XXXXXX");
			if ((fd = mkstemp(path)) == -1) {
				fprintf(stderr, "mkstemp() err : %m\n");
				return -1;
			}
			if ((fp = fdopen(fd, "w")) == NULL) {
				close(fd);
				unlink(path);
				fprintf(stderr, "fdopen(%s) : %m\n", path);
				return -1;
			}
			fprintf(fp, "#!/bin/sh\necho \"%s\"\nrm -f \"%s\"\n",
				password, path);
			fclose(fp);
			chmod(path, S_IRUSR|S_IXUSR);
			setenv("DISPLAY", "dummy", 0);
			setenv("SSH_ASKPASS", path, 1);
		}
		execvp(ssh_argv[0], (char *const *)ssh_argv);
		exit(-1);
	}
	close(in[0]); close(out[1]);

	i = 0;
	while (i < max_size) {
		for (j = 0; (j < bufsize) && (i < max_size); j++, i++) {
			buf[j] = (char) (255.0*rand()/(RAND_MAX+1.0));
		}
		if (write(in[1], buf, j) < 0) {
			fprintf(stderr, "write() : %m\n");
			break;
		}
	}
	printf("%d bytes wrote\n", i);
	close(in[1]); close(out[0]);

	rc = 0;
	while ((pid = waitpid(ssh_pid, &status, 0)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		fprintf(stderr, "waitpid() : %m\n");
		return 1;
	}

	if (WIFEXITED(status)) {
		if ((retcode = WEXITSTATUS(status))) {
			fprintf(stderr, "%s failed, exitcode=%d\n",
				ssh_argv[0], retcode);
			return 1;
		}
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "%s got signal %d\n",
			ssh_argv[0], WTERMSIG(status));
		return 1;
	} else {
		fprintf(stderr, "%s exited with status %d\n",
			ssh_argv[0], status);
		return 1;
	}

	for(i = 0; ssh_argv[i]; i++)
		free(ssh_argv[i]);
	free(ssh_argv);
	free(buf);

	return 0;
}
