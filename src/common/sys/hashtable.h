#ifndef SYS_HASHTABLE_H
#define SYS_HASHTABLE_H

typedef unsigned int hash_func_t(const void *key);
typedef int key_cmp_func_t (const void *key1, const void *key2);
typedef void key_cp_func_t(void *keydst, const void *keysrc);

/*
 * Generic hashtable template
 */

#define HASHTABLE_PRIME_TINY	49
#define HASHTABLE_PRIME_SMALL	149
#define HASHTABLE_PRIME_MEDIUM	977
#define HASHTABLE_PRIME_LARGE	1277
#define HASHTABLE_PRIME_HUGE	2459


#define HASHTABLE_LOOKUP_FROM_LIST(head, list, key, var, field, _tfield) do {\
	int _hifound = 0;						\
	list_for_each_entry(var, list, field._tfield) {			\
		if (head->cmpfunc(key, &var->field.keycopy)) {		\
			_hifound = 1;					\
			break;						\
		}							\
	}								\
	if (!_hifound)							\
		var = NULL;						\
} while (0)

#define HASHTABLE_INSERT_INTO_LIST(head, list, key, var, field, _tfield) do {\
	head->cpfunc(&(var->field.keycopy), key);			\
	head->count++;							\
	list_add(&(var->field._tfield), list);				\
} while (0)


#define HASHTABLE_LIST(head, i) (&((head)->list[i]))

#define HASHTABLE_LENGTH(head)  (sizeof((head)->list)/sizeof((head)->list[0]))

#define HASHTABLE_INDEX(head, key) (((head)->hfunc(key))%HASHTABLE_LENGTH(head))

#define HASHTABLE_HEAD(name, type, prime)				\
struct name {								\
	int count;							\
	unsigned int tmp_i;						\
	struct type *tmp_v;						\
	hash_func_t *hfunc;						\
	key_cmp_func_t *cmpfunc;					\
	key_cp_func_t *cpfunc;						\
	struct list_head list[prime];					\
}


#define HASHTABLE_ENTRY(type, keytype, _tfield)				\
struct {								\
	struct list_head _tfield;					\
	struct keytype keycopy;						\
}


#define HASHTABLE_INIT(head, _hfunc, _cmpfunc, _cpfunc) do {		\
	unsigned int _hil;						\
	(head)->hfunc = (hash_func_t *)_hfunc;				\
	(head)->cmpfunc = (key_cmp_func_t *)_cmpfunc;			\
	(head)->cpfunc = (key_cp_func_t *)_cpfunc;			\
	(head)->count = 0;						\
	for (_hil = 0; _hil < HASHTABLE_LENGTH(head); _hil++) {		\
		INIT_LIST_HEAD(HASHTABLE_LIST(head, _hil));		\
	}								\
} while (0)

#define HASHTABLE_EMPTY(head) ((head)->count == 0)

#define HASHTABLE_KEY(var, field) (&(var)->field.keycopy)


#define HASHTABLE_INSERT(head, key, var, field, _tfield) do {		\
	unsigned int _hil = HASHTABLE_INDEX(head, key);			\
	HASHTABLE_INSERT_INTO_LIST((head), HASHTABLE_LIST(head, _hil),	\
			key, var, field, _tfield);			\
} while (0)


#define HASHTABLE_FOREACH(var, head, field, _tfield)			\
for ((head)->tmp_i = 0;							\
		(head)->tmp_i < HASHTABLE_LENGTH(head);			\
		(head)->tmp_i++)					\
	list_for_each_entry(var, HASHTABLE_LIST(head, (head)->tmp_i),	\
			field._tfield)


#define HASHTABLE_FOREACH_SAFE(var, head, field, _tfield)		\
for ((head)->tmp_i = 0;							\
		(head)->tmp_i < HASHTABLE_LENGTH(head);			\
		(head)->tmp_i++)					\
	list_for_each_entry_safe(var, (head)->tmp_v,			\
			HASHTABLE_LIST(head, (head)->tmp_i),		\
			   field._tfield)

#define HASHTABLE_REMOVE(head, var, type, field, _tfield) do {		\
	list_del_init(&(var)->field._tfield);				\
	(head)->count--;						\
} while (0)



#define HASHTABLE_LOOKUP(head, key, var, field, _tfield) do {		\
	unsigned int _hil = HASHTABLE_INDEX(head, key);			\
	HASHTABLE_LOOKUP_FROM_LIST((head), HASHTABLE_LIST(head, _hil),	\
			key, var, field, _tfield);			\
} while (0)


#define HASHTABLE_LOOKUP_FOREACH(h, key, var, field, _tfield)		\
	list_for_each(var, HASHTABLE_LIST(h,			\
			HASHTABLE_INDEX((h), (key))), field._tfield)	\
		if ((h)->cmpfunc(key, &(var)->field.keycopy))

#define HASHTABLE_LOOKUP_FOREACH_SAFE(h, k, d, f, _tfield)		\
	list_for_each_safe(d, (h)->tmp_v,				\
			    HASHTABLE_LIST(h, HASHTABLE_INDEX(h, k)),	\
					   f._tfield)			\
		if ((h)->cmpfunc(k, &d->f.keycopy))

/*
 * Hashtable definitions
 */


#define _HT_LFIELD	mpfld

#define HT_HEAD(name, type, prime)					\
	HASHTABLE_HEAD(name, type, prime)

#define HT_ENTRY(type, keytype)						\
	HASHTABLE_ENTRY(type, keytype, _HT_LFIELD)

#define HT_KEY(var, field)						\
	HASHTABLE_KEY(var, field)

#define HT_INIT(head, _hfunc, _cmpfunc, _cpfunc)			\
	HASHTABLE_INIT(head, _hfunc, _cmpfunc, _cpfunc)

#define HT_EMPTY(head)							\
	HASHTABLE_EMPTY(head)

#define HT_FOREACH(var, head, field)					\
	HASHTABLE_FOREACH(var, head, field, _HT_LFIELD)

#define HT_FOREACH_SAFE(var, head, field)				\
	HASHTABLE_FOREACH_SAFE(var, head, field, _HT_LFIELD)

#define HT_REMOVE(head, var, type, field)				\
	HASHTABLE_REMOVE(head, var, type, field, _HT_LFIELD)

#define HT_REMOVE_BY_KEY(head, key, type, field)			\
	HASHTABLE_REMOVE_BY_KEY(head, key, type, field, _HT_LFIELD)

#define HT_LOOKUP(head, key, var, field)				\
	HASHTABLE_LOOKUP(head, key, var, field, _HT_LFIELD)

#define HT_INSERT(head, key, var, field)				\
	HASHTABLE_INSERT(head, key, var, field, _HT_LFIELD)

/*
 * Multi hashtable definitions
 */

#define _MULTI_HT_LFIELD	mmpfld

#define MULTI_HT_HEAD(name, type, prime)				\
	HASHTABLE_HEAD(name, type, prime)

#define MULTI_HT_ENTRY(type, keytype)					\
	HASHTABLE_ENTRY(type, keytype, _MULTI_HT_LFIELD)

#define MULTI_HT_KEY(var, field)					\
	HASHTABLE_KEY(var, field)

#define MULTI_HT_INIT(head, _hfunc, _cmpfunc, _cpfunc)			\
	HASHTABLE_INIT(head, _hfunc, _cmpfunc, _cpfunc)

#define MULTI_HT_EMPTY(head)						\
	HASHTABLE_EMPTY(head)

#define MULTI_HT_FOREACH(var, head, field)				\
	HASHTABLE_FOREACH(var, head, field, _MULTI_HT_LFIELD)

#define MULTI_HT_FOREACH_SAFE(var, head, field)				\
	HASHTABLE_FOREACH_SAFE(var, head, field, _MULTI_HT_LFIELD)

#define MULTI_HT_REMOVE(head, var, type, field)				\
	HASHTABLE_REMOVE(head, var, type, field, _MULTI_HT_LFIELD)

#define MULTI_HT_REMOVE_BY_KEY(head, key, type, field)			\
	HASHTABLE_REMOVE_BY_KEY(head, key, type, field, _MULTI_HT_LFIELD)

#define MULTI_HT_LOOKUP(head, key, var, field)				\
	HASHTABLE_LOOKUP(head, key, var, field, _MULTI_HT_LFIELD)

#define MULTI_HT_LOOKUP_FOREACH(head, key, var, field)			\
	HASHTABLE_LOOKUP_FOREACH(head, key, var, field, _MULTI_HT_LFIELD)

#define MULTI_HT_LOOKUP_FOREACH_SAFE(head, key, var, field)		\
	HASHTABLE_LOOKUP_FOREACH_SAFE(head, key, var, field, _MULTI_HT_LFIELD)

#define MULTI_HT_INSERT(head, key, var, field)				\
	HASHTABLE_INSERT(head, key, var, field, _MULTI_HT_LFIELD)


#endif /* SYS_HASHTABLE_H */
