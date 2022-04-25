/*
 * Copyright (C) 2003-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2012 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "lib.h"
#include "str_list.h"

struct dm_list *str_list_create(struct dm_pool *mem)
{
	struct dm_list *sl;

	if (!(sl = dm_pool_alloc(mem, sizeof(struct dm_list)))) {
		log_errno(ENOMEM, "str_list allocation failed");
		return NULL;
	}

	dm_list_init(sl);

	return sl;
}

static int _str_list_add_no_dup_check(struct dm_pool *mem, struct dm_list *sll, const char *str, int as_first)
{
	struct dm_str_list *sln;

	if (!str)
		return_0;

	if (!(sln = dm_pool_alloc(mem, sizeof(*sln))))
		return_0;

	sln->str = str;
	if (as_first)
		dm_list_add_h(sll, &sln->list);
	else
		dm_list_add(sll, &sln->list);

	return 1;
}

int str_list_add_no_dup_check(struct dm_pool *mem, struct dm_list *sll, const char *str)
{
	return _str_list_add_no_dup_check(mem, sll, str, 0);
}

int str_list_add_h_no_dup_check(struct dm_pool *mem, struct dm_list *sll, const char *str)
{
	return _str_list_add_no_dup_check(mem, sll, str, 1);
}

int str_list_add(struct dm_pool *mem, struct dm_list *sll, const char *str)
{
	if (!str)
		return_0;

	/* Already in list? */
	if (str_list_match_item(sll, str))
		return 1;

	return str_list_add_no_dup_check(mem, sll, str);
}

/* Add contents of sll2 to sll */
int str_list_add_list(struct dm_pool *mem, struct dm_list *sll, struct dm_list *sll2)
{
	struct dm_str_list *sl;

	if (!sll2)
		return_0;

	dm_list_iterate_items(sl, sll2)
		if (!str_list_add(mem, sll, sl->str))
			return_0;

	return 1;
}

void str_list_del(struct dm_list *sll, const char *str)
{
	struct dm_list *slh, *slht;

	dm_list_iterate_safe(slh, slht, sll)
		if (!strcmp(str, dm_list_item(slh, struct dm_str_list)->str))
			 dm_list_del(slh);
}

int str_list_dup(struct dm_pool *mem, struct dm_list *sllnew,
		 const struct dm_list *sllold)
{
	struct dm_str_list *sl;

	dm_list_init(sllnew);

	dm_list_iterate_items(sl, sllold) {
		if (!str_list_add(mem, sllnew, dm_pool_strdup(mem, sl->str)))
			return_0;
	}

	return 1;
}

/*
 * Is item on list?
 */
int str_list_match_item(const struct dm_list *sll, const char *str)
{
	struct dm_str_list *sl;

	dm_list_iterate_items(sl, sll)
	    if (!strcmp(str, sl->str))
		return 1;

	return 0;
}

/*
 * Is at least one item on both lists?
 * If tag_matched is non-NULL, it is set to the tag that matched.
 */
int str_list_match_list(const struct dm_list *sll, const struct dm_list *sll2, const char **tag_matched)
{
	struct dm_str_list *sl;

	dm_list_iterate_items(sl, sll)
		if (str_list_match_item(sll2, sl->str)) {
			if (tag_matched)
				*tag_matched = sl->str;
			return 1;
		}

	return 0;
}

/*
 * Do both lists contain the same set of items?
 */
int str_list_lists_equal(const struct dm_list *sll, const struct dm_list *sll2)
{
	struct dm_str_list *sl;

	if (dm_list_size(sll) != dm_list_size(sll2))
		return 0;

	dm_list_iterate_items(sl, sll)
	    if (!str_list_match_item(sll2, sl->str))
		return 0;

	return 1;
}
