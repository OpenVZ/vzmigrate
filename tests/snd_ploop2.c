#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <pthread.h>
#include <mntent.h>
#include <linux/types.h>
#include <linux/limits.h>

#include <vz/vzctl.h>
#include <vz/config.h>
#include <vz/vzerror.h>

#include "../bin/ploop.h"

#include "sendfile.h"

void show_usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options] hostname veid\n", name);
	fprintf(stderr, "\t-h, --help\n");
	fprintf(stderr, "\t-v, --verbose\n");
	fprintf(stderr, "\t-p, --port N        set port number\n");
	fprintf(stderr, "\t-t, --timeout N     set connection timeout in seconds\n");
}

/* from vzmigrate/bin/util.c */
static int get_ve_root(unsigned veid, char *root, size_t size)
{
	int rc = 0;
	char path[PATH_MAX + 1];
	vzctl_config_t * cfg;

	vzctl_get_env_conf_path(veid, path, sizeof(path));
	if ((cfg = vzctl_conf_open(path,
			VZCTL_CONF_SKIP_GLOBAL|VZCTL_CONF_BASE_SET)) == NULL) {
		fprintf(stderr, "vzctl_conf_open(%s) error: %s",
				path, vzctl_get_last_error());
		return -1;
	}

	if (vzctl_conf_parse(veid, cfg)) {
		vzctl_conf_close(cfg);
		fprintf(stderr, "vzctl_conf_parse() error: %s", vzctl_get_last_error());
		return -1;
	}
	if (cfg->env_data->fs->ve_root == NULL) {
		rc = -1;
		fprintf(stderr, "can't read VE_ROOT from CT#%u config", veid);
	} else {
		strncpy(root, cfg->env_data->fs->ve_root, size);
	}
	vzctl_conf_close(cfg);
	return rc;
}

int main(int argc, char **argv, char **envp)
{
	int rc = 0;
	int c;
	char *hostname;
	unsigned veid;
	char root[PATH_MAX+1];

	char *p;

	unsigned long addr;
	struct sockaddr_in saddr;
	unsigned short port = SENDFILE_TEST_PORT;

	int sock;
	int tmo = 600;
	int verbose = 0;

	struct ploop_online_copy_data data;

	static char short_options[] = "hvp:t:";
	static struct option long_options[] =
	{
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"port", required_argument, NULL, 'p'},
		{"timeout", required_argument, NULL, 't'},
	};

	while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
	{
		switch (c) {
		case 'h':
			show_usage(argv[0]);
			exit(0);
		case 'v':
			verbose = 1;
			break;
		case 'p':
			port = strtoul(optarg, &p, 10);
			if (*p != '\0') {
				fprintf(stderr, "Invalid port number : %s\n", optarg);
				exit(1);
			}
			break;
		case 't':
			tmo = strtoul(optarg, &p, 10);
			if (*p != '\0') {
				fprintf(stderr, "Invalid timeout : %s\n", optarg);
				exit(1);
			}
			break;
		default:
			show_usage(argv[0]);
			exit(1);
		}
	}
	if (argc - optind < 2) {
		show_usage(argv[0]);
		exit(1);
	}
	hostname = argv[optind];
	veid = strtoul(argv[optind+1], &p, 10);
	if (*p != '\0') {
		fprintf(stderr, "Invalid VEID : %s\n", argv[optind+1]);
		exit(1);
	}
	rc = get_ve_root(veid, root, sizeof(root));
	if (rc)
		return rc;

	if ((addr = inet_addr(hostname)) == INADDR_NONE) {
		/* need to resolve address */
		struct hostent *host;
		if ((host = gethostbyname(argv[1])) == NULL) {
			fprintf(stderr, "gethostbyname(%s) err : %m\n", hostname);
			exit(1);
		}
		memcpy(&addr, host->h_addr, sizeof(addr));
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = addr;
	saddr.sin_port = htons(port);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() err : %m\n");
		exit(1);
	}
	if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		fprintf(stderr, "connect() err : %m\n");
		exit(1);
	}
	/* set socket nonblock */
	if ((fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)) == -1) {
		fprintf(stderr, "fcntl() err : %m\n");
		exit(1);
	}

	rc = ploop_src_online_copy_image_1(root, sock, tmo, &data);
	if (rc)
		return rc;
/*
	rc = stopVE();
	if (rc) {
		ploop_data_close(&data);
		return rc;
	}
*/

	rc = ploop_src_online_copy_image_2(&data);
	if (rc)
		return rc;

	close(sock);

	return rc;
}


