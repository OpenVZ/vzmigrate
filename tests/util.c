/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 * queues
 */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <dirent.h>
#include <linux/unistd.h>

#include "util.h"

/*
 char* double-linked list
*/
/* add new element in tail */
int string_list_add(struct string_list *ls, char *str)
{
	struct string_list_el *p;

	p = (struct string_list_el *)malloc(sizeof(struct string_list_el));
	if (p == NULL) {
		fprintf(stderr, "malloc() : %m");
		return 1;
	}
	if ((p->s = strdup(str)) == NULL) {
		fprintf(stderr, "strdup() : %m");
		return 1;
	}
	TAILQ_INSERT_TAIL(ls, p, e);

	return 0;
}

/* remove all elements and its content */
void string_list_clean(struct string_list *ls)
{
	struct string_list_el *el;

	while (ls->tqh_first != NULL) {
		el = ls->tqh_first;
		TAILQ_REMOVE(ls, ls->tqh_first, e);
		free((void *)el->s);
		free((void *)el);
	}
}

/* find string <str> in list <ls> */
struct string_list_el *string_list_find(struct string_list *ls, char *str)
{
	struct string_list_el *p;

	if (str == NULL)
		return NULL;

	for (p = ls->tqh_first; p != NULL; p = p->e.tqe_next) {
		if (strcmp(str, p->s) == 0)
			return p;
	}
	return NULL;
}

/* remove element and its content and return pointer to previous elem */
struct string_list_el *string_list_remove(
		struct string_list *ls,
		struct string_list_el *el)
{
	/* get previous element */
	struct string_list_el *prev = *el->e.tqe_prev;

	TAILQ_REMOVE(ls, el, e);
	free((void *)el->s);
	free((void *)el);

	return prev;
}

/* get size of string list <ls> */
size_t string_list_size(struct string_list *ls)
{
	struct string_list_el *p;
	size_t sz = 0;

	for (p = ls->tqh_first; p != NULL; p = p->e.tqe_next)
		sz++;
	return sz;
}

/* copy string list <ls> to string array <*a> */
int string_list_to_array(struct string_list *ls, char ***a)
{
	struct string_list_el *p;
	size_t sz, i;

	/* get array size */
	sz = string_list_size(ls);
	if ((*a = (char **)calloc(sz + 1, sizeof(char *))) == NULL) {
		fprintf(stderr, "calloc() : %m");
		return 1;
	}
	for (p = ls->tqh_first, i = 0; p != NULL && i < sz; \
				p = p->e.tqe_next, i++) {
		if (((*a)[i] = strdup(p->s)) == NULL) {
			fprintf(stderr, "strdup() : %m");
			return 1;
		}
	}
	(*a)[sz] = NULL;

	return 0;
}

/* copy all elements of <src> to <dst> */
int string_list_copy(struct string_list *dst, struct string_list *src)
{
	int rc;
	struct string_list_el *p;

	for (p = src->tqh_first; p != NULL; p = p->e.tqe_next)
		if ((rc = string_list_add(dst, p->s)))
			return rc;
	return 0;
}

/* run arglist[0] with arglist and redirect std{in,out,err} */
int run_rw(int in, int out, int err, struct string_list *arglist)
{
	pid_t pid, wpid;
	int status, retcode;
	char *fn;

	if (string_list_empty(arglist)) {
		fprintf(stderr, "arglist is empty\n");
		return -1;
	}
	fn = arglist->tqh_first->s;

	wpid = fork();
	if (wpid < 0) {
		fprintf(stderr, "fork() err: %m\n");
		return -1;
	} else if (wpid == 0) {
		char **argv;
		int i;

		string_list_to_array(arglist, &argv);
		for (i = 0; argv[i]; i++)
			printf("%s ", argv[i]);
		printf("\n");
		fflush(stdout);

		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
		dup2(in, STDIN_FILENO);
		dup2(out, STDOUT_FILENO);
		dup2(err, STDERR_FILENO);
		close(in); close(out); close(err);
		/* TODO: last syncronization before start */
		execvp(fn, (char *const *)argv);
		fprintf(stderr, "execve(%s) err: %m\n", fn);
		fflush(stderr);
		exit(-1);
	}

	while ((pid = waitpid(wpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	if (pid < 0) {
		fprintf(stderr, "waitpid() err: %m\n");
		return -1;
	}

	if (WIFEXITED(status)) {
		if ((retcode = WEXITSTATUS(status))) {
			fprintf(stderr, "%s failed, exitcode=%d\n",
				fn, retcode);
			return -1;
		}
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "%s got signal %d\n",
			fn, WTERMSIG(status));
		return -1;
	} else {
		fprintf(stderr, "%s exited with status %d\n", fn, status);
		return -1;
	}
	return 0;
}

