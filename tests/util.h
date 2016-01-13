/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 * Double-linked lists functions declarations
 */

#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/queue.h>

#define list_for_each(ls, el) \
	for (	(el) = ((ls) != NULL) ? (ls)->tqh_first : NULL; \
		(el) != NULL; \
		(el) = (el)->e.tqe_next)

/* char* double-linked list */
/* sample of using:
	struct string_list urls;
	struct string_list_el *p;

	init_string_list(&urls);

	if (read_string_list(path, &urls))
		return 0;

	for (p = urls.tqh_first; p != NULL; p = p->e.tqe_next) {
		printf("%s\n", p->s);
	}
	clean_string_list(&urls);

  List functions alloc and free <char *>
*/
TAILQ_HEAD(string_list, string_list_el);
struct string_list_el {
	char *s;
	TAILQ_ENTRY(string_list_el) e;
};

/* list initialization */
static inline void string_list_init(struct string_list *ls)
{
	TAILQ_INIT(ls);
}

/* remove all elements and its content */
void string_list_clean(struct string_list *ls);

/* add new element in tail */
int string_list_add(struct string_list *ls, char *str);

/* find string <str> in list <ls> */
struct string_list_el *string_list_find(struct string_list *ls, char *str);

/* remove element and its content and return pointer to previous elem */
struct string_list_el *string_list_remove(
		struct string_list *ls,
		struct string_list_el *el);

/* 1 if list is empty */
static inline int string_list_empty(struct string_list *ls)
{
	return (ls->tqh_first == NULL)?1:0;
}

/* get size of string list <ls> */
size_t string_list_size(struct string_list *ls);

/* copy string list <ls> to string array <*a> */
int string_list_to_array(struct string_list *ls, char ***a);

/* copy all elements of <src> to <dst> */
int string_list_copy(struct string_list *dst, struct string_list *src);

#define string_list_for_each(ls, el) list_for_each(ls, el)


int run_rw(int in, int out, int err, struct string_list *arglist);

#endif
