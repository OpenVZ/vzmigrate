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
#include <getopt.h>
#include <linux/limits.h>

#define BIN_VZMDEST "/usr/sbin/vzmdest"
#define BIN_VZMDESTMPL "/usr/sbin/vzmdestmpl"
#define MAXARGS 1024

void show_usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options] CTID\n", name);
	fprintf(stderr, "Usage: %s -t|--template [options] template\n", name);
	fprintf(stderr, "\t-h, --help\n");
	fprintf(stderr, "\t-p, --port N        set port number\n");
	fprintf(stderr, "\t-b, --binary PATH   set path migrate binary\n");
	fprintf(stderr, "\t-o, --options OPTS  set vzmigrate options, separated by spaces\n");
}

static char *args[MAXARGS];
static int nargs = 0;

void add_arg(char *param)
{
	if (nargs + 1 >= MAXARGS) {
		fprintf(stderr, "Too many parameters : %d\n", nargs);
		exit(-1);
	}
	args[nargs] = param;
	args[nargs+1] = NULL;
	nargs++;
}

int main(int argc, char **argv, char **envp)
{
	int rc;
	int c;
	char *p, *opt;
	int sock;
	pid_t pid, wpid;
	int status;
	struct sockaddr_in saddr;
	struct sockaddr_in caddr;
	socklen_t caddr_len;
	unsigned short port = 1813;
	int cmd_sock, data_sock, tmpl_data_sock, swap_sock;
	char bin[PATH_MAX + 1];
	char str_cmd_sock[100];
	char str_data_sock[100];
	char str_tmpl_data_sock[100];
	char str_swap_sock[100];

	static char short_options[] = "hp:tb:o:";
	static struct option long_options[] =
	{
		{"help", no_argument, NULL, 'h'},
		{"port", required_argument, NULL, 'p'},
		{"template", no_argument, NULL, 't'},
		{"binary", required_argument, NULL, 'p'},
		{"options", required_argument, NULL, 'o'},
	};

	/* set default values */
	strncpy(bin, BIN_VZMDEST, sizeof(bin));
	add_arg(bin);
	add_arg("-ps");
	add_arg(str_cmd_sock);
	add_arg(str_data_sock);
	add_arg(str_tmpl_data_sock);
	add_arg(str_swap_sock);

	while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
	{
		switch (c) {
		case 'h':
			show_usage(argv[0]);
			exit(0);
		case 'p':
			port = strtoul(optarg, &p, 10);
			if (*p != '\0') {
				fprintf(stderr, "Invalid port number : %s\n", optarg);
				exit(1);
			}
			break;
		case 't':
			strncpy(bin, BIN_VZMDESTMPL, sizeof(bin));
			add_arg("-z");
			break;
		case 'b':
			strncpy(bin, optarg, sizeof(bin));
			break;
		case 'o':
		{
			char *delim = " \t";
			opt = strdup(optarg);
			for (p = strtok(opt, delim); p; p = strtok(NULL, delim))
				add_arg(p);
			break;
		}
		default:
			show_usage(argv[0]);
			exit(1);
		}
	}
	if (argc - optind < 1) {
		show_usage(argv[0]);
		exit(1);
	}
	add_arg("localhost");
	add_arg(argv[optind]);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() err : %m\n");
		exit(1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		fprintf(stderr, "bind() err : %m\n");
		exit(1);
	}

	if (listen(sock, SOMAXCONN)) {
		fprintf(stderr, "listen() err : %m\n");
		exit(1);
	}

	caddr_len = sizeof(caddr);
	if ((cmd_sock = accept(sock, (struct sockaddr *)&caddr, &caddr_len)) < 0) {
		fprintf(stderr, "accept() err : %m\n");
		exit(1);
	}
	snprintf(str_cmd_sock, sizeof(str_cmd_sock), "%d", cmd_sock);

	caddr_len = sizeof(caddr);
	if ((data_sock = accept(sock, (struct sockaddr *)&caddr, &caddr_len)) < 0) {
		fprintf(stderr, "accept() err : %m\n");
		exit(1);
	}
	snprintf(str_data_sock, sizeof(str_data_sock), "%d", data_sock);

	caddr_len = sizeof(caddr);
	if ((tmpl_data_sock = accept(sock, (struct sockaddr *)&caddr, &caddr_len)) < 0) {
		fprintf(stderr, "accept() err : %m\n");
		exit(1);
	}
	snprintf(str_tmpl_data_sock, sizeof(str_tmpl_data_sock), "%d", tmpl_data_sock);

	caddr_len = sizeof(caddr);
	if ((swap_sock = accept(sock, (struct sockaddr *)&caddr, &caddr_len)) < 0) {
		fprintf(stderr, "accept() err : %m\n");
		exit(1);
	}
	snprintf(str_swap_sock, sizeof(str_swap_sock), "%d", swap_sock);

	wpid = fork();
	if (wpid < 0) {
		fprintf(stderr, "fork() err: %m\n");
		exit(1);
	} else if (wpid == 0) {
		int i;
		for (i = 0; args[i]; i++)
			printf("%s ", args[i]);
		printf("\n");
		fflush(stdout);

		execvp(args[0], args);
		fprintf(stderr, "execve(%s) err: %m\n", args[0]);
		fflush(stderr);
		exit(-1);
	}
	close(sock);
	close(cmd_sock);
	close(data_sock);
	close(tmpl_data_sock);
	close(swap_sock);

	while ((pid = waitpid(wpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	if (pid < 0) {
		fprintf(stderr, "waitpid() : %m\n");
		exit(1);
	}

	if (WIFEXITED(status)) {
		if ((rc = WEXITSTATUS(status))) {
			fprintf(stderr, "%s failed, exitcode=%d\n", args[0], rc);
			exit(1);
		}
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "%s got signal %d\n", args[0], WTERMSIG(status));
		exit(1);
	} else {
		fprintf(stderr, "%s exited with status %d\n", args[0], status);
		exit(1);
	}

	return 0;
}
