  1 /*
  2  *  Generic process-grouping system.
  3  *
  4  *  Based originally on the cpuset system, extracted by Paul Menage
  5  *  Copyright (C) 2006 Google, Inc
  6  *
  7  *  Notifications support
  8  *  Copyright (C) 2009 Nokia Corporation
  9  *  Author: Kirill A. Shutemov
 10  *
 11  *  Copyright notices from the original cpuset code:
 12  *  --------------------------------------------------
 13  *  Copyright (C) 2003 BULL SA.
 14  *  Copyright (C) 2004-2006 Silicon Graphics, Inc.
 15  *
 16  *  Portions derived from Patrick Mochel's sysfs code.
 17  *  sysfs is Copyright (c) 2001-3 Patrick Mochel
 18  *
 19  *  2003-10-10 Written by Simon Derr.
 20  *  2003-10-22 Updates by Stephen Hemminger.
 21  *  2004 May-July Rework by Paul Jackson.
 22  *  ---------------------------------------------------
 23  *
 24  *  This file is subject to the terms and conditions of the GNU General Public
 25  *  License.  See the file COPYING in the main directory of the Linux
 26  *  distribution for more details.
 27  */
 28 
 29 #include <linux/cgroup.h>
 30 #include <linux/cred.h>
 31 #include <linux/ctype.h>
 32 #include <linux/errno.h>
 33 #include <linux/init_task.h>
 34 #include <linux/kernel.h>
 35 #include <linux/list.h>
 36 #include <linux/mm.h>
 37 #include <linux/mutex.h>
 38 #include <linux/mount.h>
 39 #include <linux/pagemap.h>
 40 #include <linux/proc_fs.h>
 41 #include <linux/rcupdate.h>
 42 #include <linux/sched.h>
 43 #include <linux/backing-dev.h>
 44 #include <linux/seq_file.h>
 45 #include <linux/slab.h>
 46 #include <linux/magic.h>
 47 #include <linux/spinlock.h>
 48 #include <linux/string.h>
 49 #include <linux/sort.h>
 50 #include <linux/kmod.h>
 51 #include <linux/module.h>
 52 #include <linux/delayacct.h>
 53 #include <linux/cgroupstats.h>
 54 #include <linux/hashtable.h>
 55 #include <linux/namei.h>
 56 #include <linux/pid_namespace.h>
 57 #include <linux/idr.h>
 58 #include <linux/vmalloc.h> /* TODO: replace with more sophisticated array */
 59 #include <linux/eventfd.h>
 60 #include <linux/poll.h>
 61 #include <linux/flex_array.h> /* used in cgroup_attach_task */
 62 #include <linux/kthread.h>
 63 
 64 #include <linux/atomic.h>
 65 
 66 /*
 67  * cgroup_mutex is the master lock.  Any modification to cgroup or its
 68  * hierarchy must be performed while holding it.
 69  *
 70  * cgroup_root_mutex nests inside cgroup_mutex and should be held to modify
 71  * cgroupfs_root of any cgroup hierarchy - subsys list, flags,
 72  * release_agent_path and so on.  Modifying requires both cgroup_mutex and
 73  * cgroup_root_mutex.  Readers can acquire either of the two.  This is to
 74  * break the following locking order cycle.
 75  *
 76  *  A. cgroup_mutex -> cred_guard_mutex -> s_type->i_mutex_key -> namespace_sem
 77  *  B. namespace_sem -> cgroup_mutex
 78  *
 79  * B happens only through cgroup_show_options() and using cgroup_root_mutex
 80  * breaks it.
 81  */
 82 #ifdef CONFIG_PROVE_RCU
 83 DEFINE_MUTEX(cgroup_mutex);
 84 EXPORT_SYMBOL_GPL(cgroup_mutex);        /* only for task_subsys_state_check() */
 85 #else
 86 static DEFINE_MUTEX(cgroup_mutex);
 87 #endif
 88 
 89 static DEFINE_MUTEX(cgroup_root_mutex);
 90 
 91 /*
 92  * Generate an array of cgroup subsystem pointers. At boot time, this is
 93  * populated with the built in subsystems, and modular subsystems are
 94  * registered after that. The mutable section of this array is protected by
 95  * cgroup_mutex.
 96  */
 97 #define SUBSYS(_x) [_x ## _subsys_id] = &_x ## _subsys,
 98 #define IS_SUBSYS_ENABLED(option) IS_BUILTIN(option)
 99 static struct cgroup_subsys *cgroup_subsys[CGROUP_SUBSYS_COUNT] = {
100 #include <linux/cgroup_subsys.h>
101 };
102 
103 /*
104  * The dummy hierarchy, reserved for the subsystems that are otherwise
105  * unattached - it never has more than a single cgroup, and all tasks are
106  * part of that cgroup.
107  */
108 static struct cgroupfs_root cgroup_dummy_root;
109 
110 /* dummy_top is a shorthand for the dummy hierarchy's top cgroup */
111 static struct cgroup * const cgroup_dummy_top = &cgroup_dummy_root.top_cgroup;
112 
113 /*
114  * cgroupfs file entry, pointed to from leaf dentry->d_fsdata.
115  */
116 struct cfent {
117         struct list_head                node;
118         struct dentry                   *dentry;
119         struct cftype                   *type;
120 
121         /* file xattrs */
122         struct simple_xattrs            xattrs;
123 };
124 
125 /*
126  * CSS ID -- ID per subsys's Cgroup Subsys State(CSS). used only when
127  * cgroup_subsys->use_id != 0.
128  */
129 #define CSS_ID_MAX      (65535)
130 struct css_id {
131         /*
132          * The css to which this ID points. This pointer is set to valid value
133          * after cgroup is populated. If cgroup is removed, this will be NULL.
134          * This pointer is expected to be RCU-safe because destroy()
135          * is called after synchronize_rcu(). But for safe use, css_tryget()
136          * should be used for avoiding race.
137          */
138         struct cgroup_subsys_state __rcu *css;
139         /*
140          * ID of this css.
141          */
142         unsigned short id;
143         /*
144          * Depth in hierarchy which this ID belongs to.
145          */
146         unsigned short depth;
147         /*
148          * ID is freed by RCU. (and lookup routine is RCU safe.)
149          */
150         struct rcu_head rcu_head;
151         /*
152          * Hierarchy of CSS ID belongs to.
153          */
154         unsigned short stack[0]; /* Array of Length (depth+1) */
155 };
156 
157 /*
158  * cgroup_event represents events which userspace want to receive.
159  */
160 struct cgroup_event {
161         /*
162          * Cgroup which the event belongs to.
163          */
164         struct cgroup *cgrp;
165         /*
166          * Control file which the event associated.
167          */
168         struct cftype *cft;
169         /*
170          * eventfd to signal userspace about the event.
171          */
172         struct eventfd_ctx *eventfd;
173         /*
174          * Each of these stored in a list by the cgroup.
175          */
176         struct list_head list;
177         /*
178          * All fields below needed to unregister event when
179          * userspace closes eventfd.
180          */
181         poll_table pt;
182         wait_queue_head_t *wqh;
183         wait_queue_t wait;
184         struct work_struct remove;
185 };
186 
187 /* The list of hierarchy roots */
188 
189 static LIST_HEAD(cgroup_roots);
190 static int cgroup_root_count;
191 
192 /*
193  * Hierarchy ID allocation and mapping.  It follows the same exclusion
194  * rules as other root ops - both cgroup_mutex and cgroup_root_mutex for
195  * writes, either for reads.
196  */
197 static DEFINE_IDR(cgroup_hierarchy_idr);
198 
199 static struct cgroup_name root_cgroup_name = { .name = "/" };
200 
201 /*
202  * Assign a monotonically increasing serial number to cgroups.  It
203  * guarantees cgroups with bigger numbers are newer than those with smaller
204  * numbers.  Also, as cgroups are always appended to the parent's
205  * ->children list, it guarantees that sibling cgroups are always sorted in
206  * the ascending serial number order on the list.  Protected by
207  * cgroup_mutex.
208  */
209 static u64 cgroup_serial_nr_next = 1;
210 
211 /* This flag indicates whether tasks in the fork and exit paths should
212  * check for fork/exit handlers to call. This avoids us having to do
213  * extra work in the fork/exit path if none of the subsystems need to
214  * be called.
215  */
216 static int need_forkexit_callback __read_mostly;
217 
218 static void cgroup_offline_fn(struct work_struct *work);
219 static int cgroup_destroy_locked(struct cgroup *cgrp);
220 static int cgroup_addrm_files(struct cgroup *cgrp, struct cgroup_subsys *subsys,
221                               struct cftype cfts[], bool is_add);
222 
223 /* convenient tests for these bits */
224 static inline bool cgroup_is_dead(const struct cgroup *cgrp)
225 {
226         return test_bit(CGRP_DEAD, &cgrp->flags);
227 }
228 
229 /**
230  * cgroup_is_descendant - test ancestry
231  * @cgrp: the cgroup to be tested
232  * @ancestor: possible ancestor of @cgrp
233  *
234  * Test whether @cgrp is a descendant of @ancestor.  It also returns %true
235  * if @cgrp == @ancestor.  This function is safe to call as long as @cgrp
236  * and @ancestor are accessible.
237  */
238 bool cgroup_is_descendant(struct cgroup *cgrp, struct cgroup *ancestor)
239 {
240         while (cgrp) {
241                 if (cgrp == ancestor)
242                         return true;
243                 cgrp = cgrp->parent;
244         }
245         return false;
246 }
247 EXPORT_SYMBOL_GPL(cgroup_is_descendant);
248 
249 static int cgroup_is_releasable(const struct cgroup *cgrp)
250 {
251         const int bits =
252                 (1 << CGRP_RELEASABLE) |
253                 (1 << CGRP_NOTIFY_ON_RELEASE);
254         return (cgrp->flags & bits) == bits;
255 }
256 
257 static int notify_on_release(const struct cgroup *cgrp)
258 {
259         return test_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
260 }
261 
262 /**
263  * for_each_subsys - iterate all loaded cgroup subsystems
264  * @ss: the iteration cursor
265  * @i: the index of @ss, CGROUP_SUBSYS_COUNT after reaching the end
266  *
267  * Should be called under cgroup_mutex.
268  */
269 #define for_each_subsys(ss, i)                                          \
270         for ((i) = 0; (i) < CGROUP_SUBSYS_COUNT; (i)++)                 \
271                 if (({ lockdep_assert_held(&cgroup_mutex);              \
272                        !((ss) = cgroup_subsys[i]); })) { }              \
273                 else
274 
275 /**
276  * for_each_builtin_subsys - iterate all built-in cgroup subsystems
277  * @ss: the iteration cursor
278  * @i: the index of @ss, CGROUP_BUILTIN_SUBSYS_COUNT after reaching the end
279  *
280  * Bulit-in subsystems are always present and iteration itself doesn't
281  * require any synchronization.
282  */
283 #define for_each_builtin_subsys(ss, i)                                  \
284         for ((i) = 0; (i) < CGROUP_BUILTIN_SUBSYS_COUNT &&              \
285              (((ss) = cgroup_subsys[i]) || true); (i)++)
286 
287 /* iterate each subsystem attached to a hierarchy */
288 #define for_each_root_subsys(root, ss)                                  \
289         list_for_each_entry((ss), &(root)->subsys_list, sibling)
290 
291 /* iterate across the active hierarchies */
292 #define for_each_active_root(root)                                      \
293         list_for_each_entry((root), &cgroup_roots, root_list)
294 
295 static inline struct cgroup *__d_cgrp(struct dentry *dentry)
296 {
297         return dentry->d_fsdata;
298 }
299 
300 static inline struct cfent *__d_cfe(struct dentry *dentry)
301 {
302         return dentry->d_fsdata;
303 }
304 
305 static inline struct cftype *__d_cft(struct dentry *dentry)
306 {
307         return __d_cfe(dentry)->type;
308 }
309 
310 /**
311  * cgroup_lock_live_group - take cgroup_mutex and check that cgrp is alive.
312  * @cgrp: the cgroup to be checked for liveness
313  *
314  * On success, returns true; the mutex should be later unlocked.  On
315  * failure returns false with no lock held.
316  */
317 static bool cgroup_lock_live_group(struct cgroup *cgrp)
318 {
319         mutex_lock(&cgroup_mutex);
320         if (cgroup_is_dead(cgrp)) {
321                 mutex_unlock(&cgroup_mutex);
322                 return false;
323         }
324         return true;
325 }
326 
327 /* the list of cgroups eligible for automatic release. Protected by
328  * release_list_lock */
329 static LIST_HEAD(release_list);
330 static DEFINE_RAW_SPINLOCK(release_list_lock);
331 static void cgroup_release_agent(struct work_struct *work);
332 static DECLARE_WORK(release_agent_work, cgroup_release_agent);
333 static void check_for_release(struct cgroup *cgrp);
334 
335 /*
336  * A cgroup can be associated with multiple css_sets as different tasks may
337  * belong to different cgroups on different hierarchies.  In the other
338  * direction, a css_set is naturally associated with multiple cgroups.
339  * This M:N relationship is represented by the following link structure
340  * which exists for each association and allows traversing the associations
341  * from both sides.
342  */
343 struct cgrp_cset_link {
344         /* the cgroup and css_set this link associates */
345         struct cgroup           *cgrp;
346         struct css_set          *cset;
347 
348         /* list of cgrp_cset_links anchored at cgrp->cset_links */
349         struct list_head        cset_link;
350 
351         /* list of cgrp_cset_links anchored at css_set->cgrp_links */
352         struct list_head        cgrp_link;
353 };
354 
355 /* The default css_set - used by init and its children prior to any
356  * hierarchies being mounted. It contains a pointer to the root state
357  * for each subsystem. Also used to anchor the list of css_sets. Not
358  * reference-counted, to improve performance when child cgroups
359  * haven't been created.
360  */
361 
362 static struct css_set init_css_set;
363 static struct cgrp_cset_link init_cgrp_cset_link;
364 
365 static int cgroup_init_idr(struct cgroup_subsys *ss,
366                            struct cgroup_subsys_state *css);
367 
368 /* css_set_lock protects the list of css_set objects, and the
369  * chain of tasks off each css_set.  Nests outside task->alloc_lock
370  * due to cgroup_iter_start() */
371 static DEFINE_RWLOCK(css_set_lock);
372 static int css_set_count;
373 
374 /*
375  * hash table for cgroup groups. This improves the performance to find
376  * an existing css_set. This hash doesn't (currently) take into
377  * account cgroups in empty hierarchies.
378  */
379 #define CSS_SET_HASH_BITS       7
380 static DEFINE_HASHTABLE(css_set_table, CSS_SET_HASH_BITS);
381 
382 static unsigned long css_set_hash(struct cgroup_subsys_state *css[])
383 {
384         unsigned long key = 0UL;
385         struct cgroup_subsys *ss;
386         int i;
387 
388         for_each_subsys(ss, i)
389                 key += (unsigned long)css[i];
390         key = (key >> 16) ^ key;
391 
392         return key;
393 }
394 
395 /* We don't maintain the lists running through each css_set to its
396  * task until after the first call to cgroup_iter_start(). This
397  * reduces the fork()/exit() overhead for people who have cgroups
398  * compiled into their kernel but not actually in use */
399 static int use_task_css_set_links __read_mostly;
400 
401 static void __put_css_set(struct css_set *cset, int taskexit)
402 {
403         struct cgrp_cset_link *link, *tmp_link;
404 
405         /*
406          * Ensure that the refcount doesn't hit zero while any readers
407          * can see it. Similar to atomic_dec_and_lock(), but for an
408          * rwlock
409          */
410         if (atomic_add_unless(&cset->refcount, -1, 1))
411                 return;
412         write_lock(&css_set_lock);
413         if (!atomic_dec_and_test(&cset->refcount)) {
414                 write_unlock(&css_set_lock);
415                 return;
416         }
417 
418         /* This css_set is dead. unlink it and release cgroup refcounts */
419         hash_del(&cset->hlist);
420         css_set_count--;
421 
422         list_for_each_entry_safe(link, tmp_link, &cset->cgrp_links, cgrp_link) {
423                 struct cgroup *cgrp = link->cgrp;
424 
425                 list_del(&link->cset_link);
426                 list_del(&link->cgrp_link);
427 
428                 /* @cgrp can't go away while we're holding css_set_lock */
429                 if (list_empty(&cgrp->cset_links) && notify_on_release(cgrp)) {
430                         if (taskexit)
431                                 set_bit(CGRP_RELEASABLE, &cgrp->flags);
432                         check_for_release(cgrp);
433                 }
434 
435                 kfree(link);
436         }
437 
438         write_unlock(&css_set_lock);
439         kfree_rcu(cset, rcu_head);
440 }
441 
442 /*
443  * refcounted get/put for css_set objects
444  */
445 static inline void get_css_set(struct css_set *cset)
446 {
447         atomic_inc(&cset->refcount);
448 }
449 
450 static inline void put_css_set(struct css_set *cset)
451 {
452         __put_css_set(cset, 0);
453 }
454 
455 static inline void put_css_set_taskexit(struct css_set *cset)
456 {
457         __put_css_set(cset, 1);
458 }
459 
460 /**
461  * compare_css_sets - helper function for find_existing_css_set().
462  * @cset: candidate css_set being tested
463  * @old_cset: existing css_set for a task
464  * @new_cgrp: cgroup that's being entered by the task
465  * @template: desired set of css pointers in css_set (pre-calculated)
466  *
467  * Returns true if "cg" matches "old_cg" except for the hierarchy
468  * which "new_cgrp" belongs to, for which it should match "new_cgrp".
469  */
470 static bool compare_css_sets(struct css_set *cset,
471                              struct css_set *old_cset,
472                              struct cgroup *new_cgrp,
473                              struct cgroup_subsys_state *template[])
474 {
475         struct list_head *l1, *l2;
476 
477         if (memcmp(template, cset->subsys, sizeof(cset->subsys))) {
478                 /* Not all subsystems matched */
479                 return false;
480         }
481 
482         /*
483          * Compare cgroup pointers in order to distinguish between
484          * different cgroups in heirarchies with no subsystems. We
485          * could get by with just this check alone (and skip the
486          * memcmp above) but on most setups the memcmp check will
487          * avoid the need for this more expensive check on almost all
488          * candidates.
489          */
490 
491         l1 = &cset->cgrp_links;
492         l2 = &old_cset->cgrp_links;
493         while (1) {
494                 struct cgrp_cset_link *link1, *link2;
495                 struct cgroup *cgrp1, *cgrp2;
496 
497                 l1 = l1->next;
498                 l2 = l2->next;
499                 /* See if we reached the end - both lists are equal length. */
500                 if (l1 == &cset->cgrp_links) {
501                         BUG_ON(l2 != &old_cset->cgrp_links);
502                         break;
503                 } else {
504                         BUG_ON(l2 == &old_cset->cgrp_links);
505                 }
506                 /* Locate the cgroups associated with these links. */
507                 link1 = list_entry(l1, struct cgrp_cset_link, cgrp_link);
508                 link2 = list_entry(l2, struct cgrp_cset_link, cgrp_link);
509                 cgrp1 = link1->cgrp;
510                 cgrp2 = link2->cgrp;
511                 /* Hierarchies should be linked in the same order. */
512                 BUG_ON(cgrp1->root != cgrp2->root);
513 
514                 /*
515                  * If this hierarchy is the hierarchy of the cgroup
516                  * that's changing, then we need to check that this
517                  * css_set points to the new cgroup; if it's any other
518                  * hierarchy, then this css_set should point to the
519                  * same cgroup as the old css_set.
520                  */
521                 if (cgrp1->root == new_cgrp->root) {
522                         if (cgrp1 != new_cgrp)
523                                 return false;
524                 } else {
525                         if (cgrp1 != cgrp2)
526                                 return false;
527                 }
528         }
529         return true;
530 }
531 
532 /**
533  * find_existing_css_set - init css array and find the matching css_set
534  * @old_cset: the css_set that we're using before the cgroup transition
535  * @cgrp: the cgroup that we're moving into
536  * @template: out param for the new set of csses, should be clear on entry
537  */
538 static struct css_set *find_existing_css_set(struct css_set *old_cset,
539                                         struct cgroup *cgrp,
540                                         struct cgroup_subsys_state *template[])
541 {
542         struct cgroupfs_root *root = cgrp->root;
543         struct cgroup_subsys *ss;
544         struct css_set *cset;
545         unsigned long key;
546         int i;
547 
548         /*
549          * Build the set of subsystem state objects that we want to see in the
550          * new css_set. while subsystems can change globally, the entries here
551          * won't change, so no need for locking.
552          */
553         for_each_subsys(ss, i) {
554                 if (root->subsys_mask & (1UL << i)) {
555                         /* Subsystem is in this hierarchy. So we want
556                          * the subsystem state from the new
557                          * cgroup */
558                         template[i] = cgrp->subsys[i];
559                 } else {
560                         /* Subsystem is not in this hierarchy, so we
561                          * don't want to change the subsystem state */
562                         template[i] = old_cset->subsys[i];
563                 }
564         }
565 
566         key = css_set_hash(template);
567         hash_for_each_possible(css_set_table, cset, hlist, key) {
568                 if (!compare_css_sets(cset, old_cset, cgrp, template))
569                         continue;
570 
571                 /* This css_set matches what we need */
572                 return cset;
573         }
574 
575         /* No existing cgroup group matched */
576         return NULL;
577 }
578 
579 static void free_cgrp_cset_links(struct list_head *links_to_free)
580 {
581         struct cgrp_cset_link *link, *tmp_link;
582 
583         list_for_each_entry_safe(link, tmp_link, links_to_free, cset_link) {
584                 list_del(&link->cset_link);
585                 kfree(link);
586         }
587 }
588 
589 /**
590  * allocate_cgrp_cset_links - allocate cgrp_cset_links
591  * @count: the number of links to allocate
592  * @tmp_links: list_head the allocated links are put on
593  *
594  * Allocate @count cgrp_cset_link structures and chain them on @tmp_links
595  * through ->cset_link.  Returns 0 on success or -errno.
596  */
597 static int allocate_cgrp_cset_links(int count, struct list_head *tmp_links)
598 {
599         struct cgrp_cset_link *link;
600         int i;
601 
602         INIT_LIST_HEAD(tmp_links);
603 
604         for (i = 0; i < count; i++) {
605                 link = kzalloc(sizeof(*link), GFP_KERNEL);
606                 if (!link) {
607                         free_cgrp_cset_links(tmp_links);
608                         return -ENOMEM;
609                 }
610                 list_add(&link->cset_link, tmp_links);
611         }
612         return 0;
613 }
614 
615 /**
616  * link_css_set - a helper function to link a css_set to a cgroup
617  * @tmp_links: cgrp_cset_link objects allocated by allocate_cgrp_cset_links()
618  * @cset: the css_set to be linked
619  * @cgrp: the destination cgroup
620  */
621 static void link_css_set(struct list_head *tmp_links, struct css_set *cset,
622                          struct cgroup *cgrp)
623 {
624         struct cgrp_cset_link *link;
625 
626         BUG_ON(list_empty(tmp_links));
627         link = list_first_entry(tmp_links, struct cgrp_cset_link, cset_link);
628         link->cset = cset;
629         link->cgrp = cgrp;
630         list_move(&link->cset_link, &cgrp->cset_links);
631         /*
632          * Always add links to the tail of the list so that the list
633          * is sorted by order of hierarchy creation
634          */
635         list_add_tail(&link->cgrp_link, &cset->cgrp_links);
636 }
637 
638 /**
639  * find_css_set - return a new css_set with one cgroup updated
640  * @old_cset: the baseline css_set
641  * @cgrp: the cgroup to be updated
642  *
643  * Return a new css_set that's equivalent to @old_cset, but with @cgrp
644  * substituted into the appropriate hierarchy.
645  */
646 static struct css_set *find_css_set(struct css_set *old_cset,
647                                     struct cgroup *cgrp)
648 {
649         struct cgroup_subsys_state *template[CGROUP_SUBSYS_COUNT] = { };
650         struct css_set *cset;
651         struct list_head tmp_links;
652         struct cgrp_cset_link *link;
653         unsigned long key;
654 
655         lockdep_assert_held(&cgroup_mutex);
656 
657         /* First see if we already have a cgroup group that matches
658          * the desired set */
659         read_lock(&css_set_lock);
660         cset = find_existing_css_set(old_cset, cgrp, template);
661         if (cset)
662                 get_css_set(cset);
663         read_unlock(&css_set_lock);
664 
665         if (cset)
666                 return cset;
667 
668         cset = kzalloc(sizeof(*cset), GFP_KERNEL);
669         if (!cset)
670                 return NULL;
671 
672         /* Allocate all the cgrp_cset_link objects that we'll need */
673         if (allocate_cgrp_cset_links(cgroup_root_count, &tmp_links) < 0) {
674                 kfree(cset);
675                 return NULL;
676         }
677 
678         atomic_set(&cset->refcount, 1);
679         INIT_LIST_HEAD(&cset->cgrp_links);
680         INIT_LIST_HEAD(&cset->tasks);
681         INIT_HLIST_NODE(&cset->hlist);
682 
683         /* Copy the set of subsystem state objects generated in
684          * find_existing_css_set() */
685         memcpy(cset->subsys, template, sizeof(cset->subsys));
686 
687         write_lock(&css_set_lock);
688         /* Add reference counts and links from the new css_set. */
689         list_for_each_entry(link, &old_cset->cgrp_links, cgrp_link) {
690                 struct cgroup *c = link->cgrp;
691 
692                 if (c->root == cgrp->root)
693                         c = cgrp;
694                 link_css_set(&tmp_links, cset, c);
695         }
696 
697         BUG_ON(!list_empty(&tmp_links));
698 
699         css_set_count++;
700 
701         /* Add this cgroup group to the hash table */
702         key = css_set_hash(cset->subsys);
703         hash_add(css_set_table, &cset->hlist, key);
704 
705         write_unlock(&css_set_lock);
706 
707         return cset;
708 }
709 
710 /*
711  * Return the cgroup for "task" from the given hierarchy. Must be
712  * called with cgroup_mutex held.
713  */
714 static struct cgroup *task_cgroup_from_root(struct task_struct *task,
715                                             struct cgroupfs_root *root)
716 {
717         struct css_set *cset;
718         struct cgroup *res = NULL;
719 
720         BUG_ON(!mutex_is_locked(&cgroup_mutex));
721         read_lock(&css_set_lock);
722         /*
723          * No need to lock the task - since we hold cgroup_mutex the
724          * task can't change groups, so the only thing that can happen
725          * is that it exits and its css is set back to init_css_set.
726          */
727         cset = task_css_set(task);
728         if (cset == &init_css_set) {
729                 res = &root->top_cgroup;
730         } else {
731                 struct cgrp_cset_link *link;
732 
733                 list_for_each_entry(link, &cset->cgrp_links, cgrp_link) {
734                         struct cgroup *c = link->cgrp;
735 
736                         if (c->root == root) {
737                                 res = c;
738                                 break;
739                         }
740                 }
741         }
742         read_unlock(&css_set_lock);
743         BUG_ON(!res);
744         return res;
745 }
746 
747 /*
748  * There is one global cgroup mutex. We also require taking
749  * task_lock() when dereferencing a task's cgroup subsys pointers.
750  * See "The task_lock() exception", at the end of this comment.
751  *
752  * A task must hold cgroup_mutex to modify cgroups.
753  *
754  * Any task can increment and decrement the count field without lock.
755  * So in general, code holding cgroup_mutex can't rely on the count
756  * field not changing.  However, if the count goes to zero, then only
757  * cgroup_attach_task() can increment it again.  Because a count of zero
758  * means that no tasks are currently attached, therefore there is no
759  * way a task attached to that cgroup can fork (the other way to
760  * increment the count).  So code holding cgroup_mutex can safely
761  * assume that if the count is zero, it will stay zero. Similarly, if
762  * a task holds cgroup_mutex on a cgroup with zero count, it
763  * knows that the cgroup won't be removed, as cgroup_rmdir()
764  * needs that mutex.
765  *
766  * The fork and exit callbacks cgroup_fork() and cgroup_exit(), don't
767  * (usually) take cgroup_mutex.  These are the two most performance
768  * critical pieces of code here.  The exception occurs on cgroup_exit(),
769  * when a task in a notify_on_release cgroup exits.  Then cgroup_mutex
770  * is taken, and if the cgroup count is zero, a usermode call made
771  * to the release agent with the name of the cgroup (path relative to
772  * the root of cgroup file system) as the argument.
773  *
774  * A cgroup can only be deleted if both its 'count' of using tasks
775  * is zero, and its list of 'children' cgroups is empty.  Since all
776  * tasks in the system use _some_ cgroup, and since there is always at
777  * least one task in the system (init, pid == 1), therefore, top_cgroup
778  * always has either children cgroups and/or using tasks.  So we don't
779  * need a special hack to ensure that top_cgroup cannot be deleted.
780  *
781  *      The task_lock() exception
782  *
783  * The need for this exception arises from the action of
784  * cgroup_attach_task(), which overwrites one task's cgroup pointer with
785  * another.  It does so using cgroup_mutex, however there are
786  * several performance critical places that need to reference
787  * task->cgroup without the expense of grabbing a system global
788  * mutex.  Therefore except as noted below, when dereferencing or, as
789  * in cgroup_attach_task(), modifying a task's cgroup pointer we use
790  * task_lock(), which acts on a spinlock (task->alloc_lock) already in
791  * the task_struct routinely used for such matters.
792  *
793  * P.S.  One more locking exception.  RCU is used to guard the
794  * update of a tasks cgroup pointer by cgroup_attach_task()
795  */
796 
797 /*
798  * A couple of forward declarations required, due to cyclic reference loop:
799  * cgroup_mkdir -> cgroup_create -> cgroup_populate_dir ->
800  * cgroup_add_file -> cgroup_create_file -> cgroup_dir_inode_operations
801  * -> cgroup_mkdir.
802  */
803 
804 static int cgroup_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode);
805 static int cgroup_rmdir(struct inode *unused_dir, struct dentry *dentry);
806 static int cgroup_populate_dir(struct cgroup *cgrp, bool base_files,
807                                unsigned long subsys_mask);
808 static const struct inode_operations cgroup_dir_inode_operations;
809 static const struct file_operations proc_cgroupstats_operations;
810 
811 static struct backing_dev_info cgroup_backing_dev_info = {
812         .name           = "cgroup",
813         .capabilities   = BDI_CAP_NO_ACCT_AND_WRITEBACK,
814 };
815 
816 static int alloc_css_id(struct cgroup_subsys *ss,
817                         struct cgroup *parent, struct cgroup *child);
818 
819 static struct inode *cgroup_new_inode(umode_t mode, struct super_block *sb)
820 {
821         struct inode *inode = new_inode(sb);
822 
823         if (inode) {
824                 inode->i_ino = get_next_ino();
825                 inode->i_mode = mode;
826                 inode->i_uid = current_fsuid();
827                 inode->i_gid = current_fsgid();
828                 inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
829                 inode->i_mapping->backing_dev_info = &cgroup_backing_dev_info;
830         }
831         return inode;
832 }
833 
834 static struct cgroup_name *cgroup_alloc_name(struct dentry *dentry)
835 {
836         struct cgroup_name *name;
837 
838         name = kmalloc(sizeof(*name) + dentry->d_name.len + 1, GFP_KERNEL);
839         if (!name)
840                 return NULL;
841         strcpy(name->name, dentry->d_name.name);
842         return name;
843 }
844 
845 static void cgroup_free_fn(struct work_struct *work)
846 {
847         struct cgroup *cgrp = container_of(work, struct cgroup, destroy_work);
848         struct cgroup_subsys *ss;
849 
850         mutex_lock(&cgroup_mutex);
851         /*
852          * Release the subsystem state objects.
853          */
854         for_each_root_subsys(cgrp->root, ss)
855                 ss->css_free(cgrp);
856 
857         cgrp->root->number_of_cgroups--;
858         mutex_unlock(&cgroup_mutex);
859 
860         /*
861          * We get a ref to the parent's dentry, and put the ref when
862          * this cgroup is being freed, so it's guaranteed that the
863          * parent won't be destroyed before its children.
864          */
865         dput(cgrp->parent->dentry);
866 
867         ida_simple_remove(&cgrp->root->cgroup_ida, cgrp->id);
868 
869         /*
870          * Drop the active superblock reference that we took when we
871          * created the cgroup. This will free cgrp->root, if we are
872          * holding the last reference to @sb.
873          */
874         deactivate_super(cgrp->root->sb);
875 
876         /*
877          * if we're getting rid of the cgroup, refcount should ensure
878          * that there are no pidlists left.
879          */
880         BUG_ON(!list_empty(&cgrp->pidlists));
881 
882         simple_xattrs_free(&cgrp->xattrs);
883 
884         kfree(rcu_dereference_raw(cgrp->name));
885         kfree(cgrp);
886 }
887 
888 static void cgroup_free_rcu(struct rcu_head *head)
889 {
890         struct cgroup *cgrp = container_of(head, struct cgroup, rcu_head);
891 
892         INIT_WORK(&cgrp->destroy_work, cgroup_free_fn);
893         schedule_work(&cgrp->destroy_work);
894 }
895 
896 static void cgroup_diput(struct dentry *dentry, struct inode *inode)
897 {
898         /* is dentry a directory ? if so, kfree() associated cgroup */
899         if (S_ISDIR(inode->i_mode)) {
900                 struct cgroup *cgrp = dentry->d_fsdata;
901 
902                 BUG_ON(!(cgroup_is_dead(cgrp)));
903                 call_rcu(&cgrp->rcu_head, cgroup_free_rcu);
904         } else {
905                 struct cfent *cfe = __d_cfe(dentry);
906                 struct cgroup *cgrp = dentry->d_parent->d_fsdata;
907 
908                 WARN_ONCE(!list_empty(&cfe->node) &&
909                           cgrp != &cgrp->root->top_cgroup,
910                           "cfe still linked for %s\n", cfe->type->name);
911                 simple_xattrs_free(&cfe->xattrs);
912                 kfree(cfe);
913         }
914         iput(inode);
915 }
916 
917 static int cgroup_delete(const struct dentry *d)
918 {
919         return 1;
920 }
921 
922 static void remove_dir(struct dentry *d)
923 {
924         struct dentry *parent = dget(d->d_parent);
925 
926         d_delete(d);
927         simple_rmdir(parent->d_inode, d);
928         dput(parent);
929 }
930 
931 static void cgroup_rm_file(struct cgroup *cgrp, const struct cftype *cft)
932 {
933         struct cfent *cfe;
934 
935         lockdep_assert_held(&cgrp->dentry->d_inode->i_mutex);
936         lockdep_assert_held(&cgroup_mutex);
937 
938         /*
939          * If we're doing cleanup due to failure of cgroup_create(),
940          * the corresponding @cfe may not exist.
941          */
942         list_for_each_entry(cfe, &cgrp->files, node) {
943                 struct dentry *d = cfe->dentry;
944 
945                 if (cft && cfe->type != cft)
946                         continue;
947 
948                 dget(d);
949                 d_delete(d);
950                 simple_unlink(cgrp->dentry->d_inode, d);
951                 list_del_init(&cfe->node);
952                 dput(d);
953 
954                 break;
955         }
956 }
957 
958 /**
959  * cgroup_clear_directory - selective removal of base and subsystem files
960  * @dir: directory containing the files
961  * @base_files: true if the base files should be removed
962  * @subsys_mask: mask of the subsystem ids whose files should be removed
963  */
964 static void cgroup_clear_directory(struct dentry *dir, bool base_files,
965                                    unsigned long subsys_mask)
966 {
967         struct cgroup *cgrp = __d_cgrp(dir);
968         struct cgroup_subsys *ss;
969 
970         for_each_root_subsys(cgrp->root, ss) {
971                 struct cftype_set *set;
972                 if (!test_bit(ss->subsys_id, &subsys_mask))
973                         continue;
974                 list_for_each_entry(set, &ss->cftsets, node)
975                         cgroup_addrm_files(cgrp, NULL, set->cfts, false);
976         }
977         if (base_files) {
978                 while (!list_empty(&cgrp->files))
979                         cgroup_rm_file(cgrp, NULL);
980         }
981 }
982 
983 /*
984  * NOTE : the dentry must have been dget()'ed
985  */
986 static void cgroup_d_remove_dir(struct dentry *dentry)
987 {
988         struct dentry *parent;
989         struct cgroupfs_root *root = dentry->d_sb->s_fs_info;
990 
991         cgroup_clear_directory(dentry, true, root->subsys_mask);
992 
993         parent = dentry->d_parent;
994         spin_lock(&parent->d_lock);
995         spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
996         list_del_init(&dentry->d_u.d_child);
997         spin_unlock(&dentry->d_lock);
998         spin_unlock(&parent->d_lock);
999         remove_dir(dentry);
1000 }
1001 
1002 /*
1003  * Call with cgroup_mutex held. Drops reference counts on modules, including
1004  * any duplicate ones that parse_cgroupfs_options took. If this function
1005  * returns an error, no reference counts are touched.
1006  */
1007 static int rebind_subsystems(struct cgroupfs_root *root,
1008                              unsigned long added_mask, unsigned removed_mask)
1009 {
1010         struct cgroup *cgrp = &root->top_cgroup;
1011         struct cgroup_subsys *ss;
1012         int i;
1013 
1014         BUG_ON(!mutex_is_locked(&cgroup_mutex));
1015         BUG_ON(!mutex_is_locked(&cgroup_root_mutex));
1016 
1017         /* Check that any added subsystems are currently free */
1018         for_each_subsys(ss, i) {
1019                 unsigned long bit = 1UL << i;
1020 
1021                 if (!(bit & added_mask))
1022                         continue;
1023 
1024                 if (ss->root != &cgroup_dummy_root) {
1025                         /* Subsystem isn't free */
1026                         return -EBUSY;
1027                 }
1028         }
1029 
1030         /* Currently we don't handle adding/removing subsystems when
1031          * any child cgroups exist. This is theoretically supportable
1032          * but involves complex error handling, so it's being left until
1033          * later */
1034         if (root->number_of_cgroups > 1)
1035                 return -EBUSY;
1036 
1037         /* Process each subsystem */
1038         for_each_subsys(ss, i) {
1039                 unsigned long bit = 1UL << i;
1040 
1041                 if (bit & added_mask) {
1042                         /* We're binding this subsystem to this hierarchy */
1043                         BUG_ON(cgrp->subsys[i]);
1044                         BUG_ON(!cgroup_dummy_top->subsys[i]);
1045                         BUG_ON(cgroup_dummy_top->subsys[i]->cgroup != cgroup_dummy_top);
1046 
1047                         cgrp->subsys[i] = cgroup_dummy_top->subsys[i];
1048                         cgrp->subsys[i]->cgroup = cgrp;
1049                         list_move(&ss->sibling, &root->subsys_list);
1050                         ss->root = root;
1051                         if (ss->bind)
1052                                 ss->bind(cgrp);
1053 
1054                         /* refcount was already taken, and we're keeping it */
1055                         root->subsys_mask |= bit;
1056                 } else if (bit & removed_mask) {
1057                         /* We're removing this subsystem */
1058                         BUG_ON(cgrp->subsys[i] != cgroup_dummy_top->subsys[i]);
1059                         BUG_ON(cgrp->subsys[i]->cgroup != cgrp);
1060 
1061                         if (ss->bind)
1062                                 ss->bind(cgroup_dummy_top);
1063                         cgroup_dummy_top->subsys[i]->cgroup = cgroup_dummy_top;
1064                         cgrp->subsys[i] = NULL;
1065                         cgroup_subsys[i]->root = &cgroup_dummy_root;
1066                         list_move(&ss->sibling, &cgroup_dummy_root.subsys_list);
1067 
1068                         /* subsystem is now free - drop reference on module */
1069                         module_put(ss->module);
1070                         root->subsys_mask &= ~bit;
1071                 } else if (bit & root->subsys_mask) {
1072                         /* Subsystem state should already exist */
1073                         BUG_ON(!cgrp->subsys[i]);
1074                         /*
1075                          * a refcount was taken, but we already had one, so
1076                          * drop the extra reference.
1077                          */
1078                         module_put(ss->module);
1079 #ifdef CONFIG_MODULE_UNLOAD
1080                         BUG_ON(ss->module && !module_refcount(ss->module));
1081 #endif
1082                 } else {
1083                         /* Subsystem state shouldn't exist */
1084                         BUG_ON(cgrp->subsys[i]);
1085                 }
1086         }
1087 
1088         /*
1089          * Mark @root has finished binding subsystems.  @root->subsys_mask
1090          * now matches the bound subsystems.
1091          */
1092         root->flags |= CGRP_ROOT_SUBSYS_BOUND;
1093 
1094         return 0;
1095 }
1096 
1097 static int cgroup_show_options(struct seq_file *seq, struct dentry *dentry)
1098 {
1099         struct cgroupfs_root *root = dentry->d_sb->s_fs_info;
1100         struct cgroup_subsys *ss;
1101 
1102         mutex_lock(&cgroup_root_mutex);
1103         for_each_root_subsys(root, ss)
1104                 seq_printf(seq, ",%s", ss->name);
1105         if (root->flags & CGRP_ROOT_SANE_BEHAVIOR)
1106                 seq_puts(seq, ",sane_behavior");
1107         if (root->flags & CGRP_ROOT_NOPREFIX)
1108                 seq_puts(seq, ",noprefix");
1109         if (root->flags & CGRP_ROOT_XATTR)
1110                 seq_puts(seq, ",xattr");
1111         if (strlen(root->release_agent_path))
1112                 seq_printf(seq, ",release_agent=%s", root->release_agent_path);
1113         if (test_bit(CGRP_CPUSET_CLONE_CHILDREN, &root->top_cgroup.flags))
1114                 seq_puts(seq, ",clone_children");
1115         if (strlen(root->name))
1116                 seq_printf(seq, ",name=%s", root->name);
1117         mutex_unlock(&cgroup_root_mutex);
1118         return 0;
1119 }
1120 
1121 struct cgroup_sb_opts {
1122         unsigned long subsys_mask;
1123         unsigned long flags;
1124         char *release_agent;
1125         bool cpuset_clone_children;
1126         char *name;
1127         /* User explicitly requested empty subsystem */
1128         bool none;
1129 
1130         struct cgroupfs_root *new_root;
1131 
1132 };
1133 
1134 /*
1135  * Convert a hierarchy specifier into a bitmask of subsystems and
1136  * flags. Call with cgroup_mutex held to protect the cgroup_subsys[]
1137  * array. This function takes refcounts on subsystems to be used, unless it
1138  * returns error, in which case no refcounts are taken.
1139  */
1140 static int parse_cgroupfs_options(char *data, struct cgroup_sb_opts *opts)
1141 {
1142         char *token, *o = data;
1143         bool all_ss = false, one_ss = false;
1144         unsigned long mask = (unsigned long)-1;
1145         bool module_pin_failed = false;
1146         struct cgroup_subsys *ss;
1147         int i;
1148 
1149         BUG_ON(!mutex_is_locked(&cgroup_mutex));
1150 
1151 #ifdef CONFIG_CPUSETS
1152         mask = ~(1UL << cpuset_subsys_id);
1153 #endif
1154 
1155         memset(opts, 0, sizeof(*opts));
1156 
1157         while ((token = strsep(&o, ",")) != NULL) {
1158                 if (!*token)
1159                         return -EINVAL;
1160                 if (!strcmp(token, "none")) {
1161                         /* Explicitly have no subsystems */
1162                         opts->none = true;
1163                         continue;
1164                 }
1165                 if (!strcmp(token, "all")) {
1166                         /* Mutually exclusive option 'all' + subsystem name */
1167                         if (one_ss)
1168                                 return -EINVAL;
1169                         all_ss = true;
1170                         continue;
1171                 }
1172                 if (!strcmp(token, "__DEVEL__sane_behavior")) {
1173                         opts->flags |= CGRP_ROOT_SANE_BEHAVIOR;
1174                         continue;
1175                 }
1176                 if (!strcmp(token, "noprefix")) {
1177                         opts->flags |= CGRP_ROOT_NOPREFIX;
1178                         continue;
1179                 }
1180                 if (!strcmp(token, "clone_children")) {
1181                         opts->cpuset_clone_children = true;
1182                         continue;
1183                 }
1184                 if (!strcmp(token, "xattr")) {
1185                         opts->flags |= CGRP_ROOT_XATTR;
1186                         continue;
1187                 }
1188                 if (!strncmp(token, "release_agent=", 14)) {
1189                         /* Specifying two release agents is forbidden */
1190                         if (opts->release_agent)
1191                                 return -EINVAL;
1192                         opts->release_agent =
1193                                 kstrndup(token + 14, PATH_MAX - 1, GFP_KERNEL);
1194                         if (!opts->release_agent)
1195                                 return -ENOMEM;
1196                         continue;
1197                 }
1198                 if (!strncmp(token, "name=", 5)) {
1199                         const char *name = token + 5;
1200                         /* Can't specify an empty name */
1201                         if (!strlen(name))
1202                                 return -EINVAL;
1203                         /* Must match [\w.-]+ */
1204                         for (i = 0; i < strlen(name); i++) {
1205                                 char c = name[i];
1206                                 if (isalnum(c))
1207                                         continue;
1208                                 if ((c == '.') || (c == '-') || (c == '_'))
1209                                         continue;
1210                                 return -EINVAL;
1211                         }
1212                         /* Specifying two names is forbidden */
1213                         if (opts->name)
1214                                 return -EINVAL;
1215                         opts->name = kstrndup(name,
1216                                               MAX_CGROUP_ROOT_NAMELEN - 1,
1217                                               GFP_KERNEL);
1218                         if (!opts->name)
1219                                 return -ENOMEM;
1220 
1221                         continue;
1222                 }
1223 
1224                 for_each_subsys(ss, i) {
1225                         if (strcmp(token, ss->name))
1226                                 continue;
1227                         if (ss->disabled)
1228                                 continue;
1229 
1230                         /* Mutually exclusive option 'all' + subsystem name */
1231                         if (all_ss)
1232                                 return -EINVAL;
1233                         set_bit(i, &opts->subsys_mask);
1234                         one_ss = true;
1235 
1236                         break;
1237                 }
1238                 if (i == CGROUP_SUBSYS_COUNT)
1239                         return -ENOENT;
1240         }
1241 
1242         /*
1243          * If the 'all' option was specified select all the subsystems,
1244          * otherwise if 'none', 'name=' and a subsystem name options
1245          * were not specified, let's default to 'all'
1246          */
1247         if (all_ss || (!one_ss && !opts->none && !opts->name))
1248                 for_each_subsys(ss, i)
1249                         if (!ss->disabled)
1250                                 set_bit(i, &opts->subsys_mask);
1251 
1252         /* Consistency checks */
1253 
1254         if (opts->flags & CGRP_ROOT_SANE_BEHAVIOR) {
1255                 pr_warning("cgroup: sane_behavior: this is still under development and its behaviors will change, proceed at your own risk\n");
1256 
1257                 if (opts->flags & CGRP_ROOT_NOPREFIX) {
1258                         pr_err("cgroup: sane_behavior: noprefix is not allowed\n");
1259                         return -EINVAL;
1260                 }
1261 
1262                 if (opts->cpuset_clone_children) {
1263                         pr_err("cgroup: sane_behavior: clone_children is not allowed\n");
1264                         return -EINVAL;
1265                 }
1266         }
1267 
1268         /*
1269          * Option noprefix was introduced just for backward compatibility
1270          * with the old cpuset, so we allow noprefix only if mounting just
1271          * the cpuset subsystem.
1272          */
1273         if ((opts->flags & CGRP_ROOT_NOPREFIX) && (opts->subsys_mask & mask))
1274                 return -EINVAL;
1275 
1276 
1277         /* Can't specify "none" and some subsystems */
1278         if (opts->subsys_mask && opts->none)
1279                 return -EINVAL;
1280 
1281         /*
1282          * We either have to specify by name or by subsystems. (So all
1283          * empty hierarchies must have a name).
1284          */
1285         if (!opts->subsys_mask && !opts->name)
1286                 return -EINVAL;
1287 
1288         /*
1289          * Grab references on all the modules we'll need, so the subsystems
1290          * don't dance around before rebind_subsystems attaches them. This may
1291          * take duplicate reference counts on a subsystem that's already used,
1292          * but rebind_subsystems handles this case.
1293          */
1294         for_each_subsys(ss, i) {
1295                 if (!(opts->subsys_mask & (1UL << i)))
1296                         continue;
1297                 if (!try_module_get(cgroup_subsys[i]->module)) {
1298                         module_pin_failed = true;
1299                         break;
1300                 }
1301         }
1302         if (module_pin_failed) {
1303                 /*
1304                  * oops, one of the modules was going away. this means that we
1305                  * raced with a module_delete call, and to the user this is
1306                  * essentially a "subsystem doesn't exist" case.
1307                  */
1308                 for (i--; i >= 0; i--) {
1309                         /* drop refcounts only on the ones we took */
1310                         unsigned long bit = 1UL << i;
1311 
1312                         if (!(bit & opts->subsys_mask))
1313                                 continue;
1314                         module_put(cgroup_subsys[i]->module);
1315                 }
1316                 return -ENOENT;
1317         }
1318 
1319         return 0;
1320 }
1321 
1322 static void drop_parsed_module_refcounts(unsigned long subsys_mask)
1323 {
1324         struct cgroup_subsys *ss;
1325         int i;
1326 
1327         mutex_lock(&cgroup_mutex);
1328         for_each_subsys(ss, i)
1329                 if (subsys_mask & (1UL << i))
1330                         module_put(cgroup_subsys[i]->module);
1331         mutex_unlock(&cgroup_mutex);
1332 }
1333 
1334 static int cgroup_remount(struct super_block *sb, int *flags, char *data)
1335 {
1336         int ret = 0;
1337         struct cgroupfs_root *root = sb->s_fs_info;
1338         struct cgroup *cgrp = &root->top_cgroup;
1339         struct cgroup_sb_opts opts;
1340         unsigned long added_mask, removed_mask;
1341 
1342         if (root->flags & CGRP_ROOT_SANE_BEHAVIOR) {
1343                 pr_err("cgroup: sane_behavior: remount is not allowed\n");
1344                 return -EINVAL;
1345         }
1346 
1347         mutex_lock(&cgrp->dentry->d_inode->i_mutex);
1348         mutex_lock(&cgroup_mutex);
1349         mutex_lock(&cgroup_root_mutex);
1350 
1351         /* See what subsystems are wanted */
1352         ret = parse_cgroupfs_options(data, &opts);
1353         if (ret)
1354                 goto out_unlock;
1355 
1356         if (opts.subsys_mask != root->subsys_mask || opts.release_agent)
1357                 pr_warning("cgroup: option changes via remount are deprecated (pid=%d comm=%s)\n",
1358                            task_tgid_nr(current), current->comm);
1359 
1360         added_mask = opts.subsys_mask & ~root->subsys_mask;
1361         removed_mask = root->subsys_mask & ~opts.subsys_mask;
1362 
1363         /* Don't allow flags or name to change at remount */
1364         if (((opts.flags ^ root->flags) & CGRP_ROOT_OPTION_MASK) ||
1365             (opts.name && strcmp(opts.name, root->name))) {
1366                 pr_err("cgroup: option or name mismatch, new: 0x%lx \"%s\", old: 0x%lx \"%s\"\n",
1367                        opts.flags & CGRP_ROOT_OPTION_MASK, opts.name ?: "",
1368                        root->flags & CGRP_ROOT_OPTION_MASK, root->name);
1369                 ret = -EINVAL;
1370                 goto out_unlock;
1371         }
1372 
1373         /*
1374          * Clear out the files of subsystems that should be removed, do
1375          * this before rebind_subsystems, since rebind_subsystems may
1376          * change this hierarchy's subsys_list.
1377          */
1378         cgroup_clear_directory(cgrp->dentry, false, removed_mask);
1379 
1380         ret = rebind_subsystems(root, added_mask, removed_mask);
1381         if (ret) {
1382                 /* rebind_subsystems failed, re-populate the removed files */
1383                 cgroup_populate_dir(cgrp, false, removed_mask);
1384                 goto out_unlock;
1385         }
1386 
1387         /* re-populate subsystem files */
1388         cgroup_populate_dir(cgrp, false, added_mask);
1389 
1390         if (opts.release_agent)
1391                 strcpy(root->release_agent_path, opts.release_agent);
1392  out_unlock:
1393         kfree(opts.release_agent);
1394         kfree(opts.name);
1395         mutex_unlock(&cgroup_root_mutex);
1396         mutex_unlock(&cgroup_mutex);
1397         mutex_unlock(&cgrp->dentry->d_inode->i_mutex);
1398         if (ret)
1399                 drop_parsed_module_refcounts(opts.subsys_mask);
1400         return ret;
1401 }
1402 
1403 static const struct super_operations cgroup_ops = {
1404         .statfs = simple_statfs,
1405         .drop_inode = generic_delete_inode,
1406         .show_options = cgroup_show_options,
1407         .remount_fs = cgroup_remount,
1408 };
1409 
1410 static void init_cgroup_housekeeping(struct cgroup *cgrp)
1411 {
1412         INIT_LIST_HEAD(&cgrp->sibling);
1413         INIT_LIST_HEAD(&cgrp->children);
1414         INIT_LIST_HEAD(&cgrp->files);
1415         INIT_LIST_HEAD(&cgrp->cset_links);
1416         INIT_LIST_HEAD(&cgrp->release_list);
1417         INIT_LIST_HEAD(&cgrp->pidlists);
1418         mutex_init(&cgrp->pidlist_mutex);
1419         INIT_LIST_HEAD(&cgrp->event_list);
1420         spin_lock_init(&cgrp->event_list_lock);
1421         simple_xattrs_init(&cgrp->xattrs);
1422 }
1423 
1424 static void init_cgroup_root(struct cgroupfs_root *root)
1425 {
1426         struct cgroup *cgrp = &root->top_cgroup;
1427 
1428         INIT_LIST_HEAD(&root->subsys_list);
1429         INIT_LIST_HEAD(&root->root_list);
1430         root->number_of_cgroups = 1;
1431         cgrp->root = root;
1432         RCU_INIT_POINTER(cgrp->name, &root_cgroup_name);
1433         init_cgroup_housekeeping(cgrp);
1434 }
1435 
1436 static int cgroup_init_root_id(struct cgroupfs_root *root, int start, int end)
1437 {
1438         int id;
1439 
1440         lockdep_assert_held(&cgroup_mutex);
1441         lockdep_assert_held(&cgroup_root_mutex);
1442 
1443         id = idr_alloc_cyclic(&cgroup_hierarchy_idr, root, start, end,
1444                               GFP_KERNEL);
1445         if (id < 0)
1446                 return id;
1447 
1448         root->hierarchy_id = id;
1449         return 0;
1450 }
1451 
1452 static void cgroup_exit_root_id(struct cgroupfs_root *root)
1453 {
1454         lockdep_assert_held(&cgroup_mutex);
1455         lockdep_assert_held(&cgroup_root_mutex);
1456 
1457         if (root->hierarchy_id) {
1458                 idr_remove(&cgroup_hierarchy_idr, root->hierarchy_id);
1459                 root->hierarchy_id = 0;
1460         }
1461 }
1462 
1463 static int cgroup_test_super(struct super_block *sb, void *data)
1464 {
1465         struct cgroup_sb_opts *opts = data;
1466         struct cgroupfs_root *root = sb->s_fs_info;
1467 
1468         /* If we asked for a name then it must match */
1469         if (opts->name && strcmp(opts->name, root->name))
1470                 return 0;
1471 
1472         /*
1473          * If we asked for subsystems (or explicitly for no
1474          * subsystems) then they must match
1475          */
1476         if ((opts->subsys_mask || opts->none)
1477             && (opts->subsys_mask != root->subsys_mask))
1478                 return 0;
1479 
1480         return 1;
1481 }
1482 
1483 static struct cgroupfs_root *cgroup_root_from_opts(struct cgroup_sb_opts *opts)
1484 {
1485         struct cgroupfs_root *root;
1486 
1487         if (!opts->subsys_mask && !opts->none)
1488                 return NULL;
1489 
1490         root = kzalloc(sizeof(*root), GFP_KERNEL);
1491         if (!root)
1492                 return ERR_PTR(-ENOMEM);
1493 
1494         init_cgroup_root(root);
1495 
1496         /*
1497          * We need to set @root->subsys_mask now so that @root can be
1498          * matched by cgroup_test_super() before it finishes
1499          * initialization; otherwise, competing mounts with the same
1500          * options may try to bind the same subsystems instead of waiting
1501          * for the first one leading to unexpected mount errors.
1502          * SUBSYS_BOUND will be set once actual binding is complete.
1503          */
1504         root->subsys_mask = opts->subsys_mask;
1505         root->flags = opts->flags;
1506         ida_init(&root->cgroup_ida);
1507         if (opts->release_agent)
1508                 strcpy(root->release_agent_path, opts->release_agent);
1509         if (opts->name)
1510                 strcpy(root->name, opts->name);
1511         if (opts->cpuset_clone_children)
1512                 set_bit(CGRP_CPUSET_CLONE_CHILDREN, &root->top_cgroup.flags);
1513         return root;
1514 }
1515 
1516 static void cgroup_free_root(struct cgroupfs_root *root)
1517 {
1518         if (root) {
1519                 /* hierarhcy ID shoulid already have been released */
1520                 WARN_ON_ONCE(root->hierarchy_id);
1521 
1522                 ida_destroy(&root->cgroup_ida);
1523                 kfree(root);
1524         }
1525 }
1526 
1527 static int cgroup_set_super(struct super_block *sb, void *data)
1528 {
1529         int ret;
1530         struct cgroup_sb_opts *opts = data;
1531 
1532         /* If we don't have a new root, we can't set up a new sb */
1533         if (!opts->new_root)
1534                 return -EINVAL;
1535 
1536         BUG_ON(!opts->subsys_mask && !opts->none);
1537 
1538         ret = set_anon_super(sb, NULL);
1539         if (ret)
1540                 return ret;
1541 
1542         sb->s_fs_info = opts->new_root;
1543         opts->new_root->sb = sb;
1544 
1545         sb->s_blocksize = PAGE_CACHE_SIZE;
1546         sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
1547         sb->s_magic = CGROUP_SUPER_MAGIC;
1548         sb->s_op = &cgroup_ops;
1549 
1550         return 0;
1551 }
1552 
1553 static int cgroup_get_rootdir(struct super_block *sb)
1554 {
1555         static const struct dentry_operations cgroup_dops = {
1556                 .d_iput = cgroup_diput,
1557                 .d_delete = cgroup_delete,
1558         };
1559 
1560         struct inode *inode =
1561                 cgroup_new_inode(S_IFDIR | S_IRUGO | S_IXUGO | S_IWUSR, sb);
1562 
1563         if (!inode)
1564                 return -ENOMEM;
1565 
1566         inode->i_fop = &simple_dir_operations;
1567         inode->i_op = &cgroup_dir_inode_operations;
1568         /* directories start off with i_nlink == 2 (for "." entry) */
1569         inc_nlink(inode);
1570         sb->s_root = d_make_root(inode);
1571         if (!sb->s_root)
1572                 return -ENOMEM;
1573         /* for everything else we want ->d_op set */
1574         sb->s_d_op = &cgroup_dops;
1575         return 0;
1576 }
1577 
1578 static struct dentry *cgroup_mount(struct file_system_type *fs_type,
1579                          int flags, const char *unused_dev_name,
1580                          void *data)
1581 {
1582         struct cgroup_sb_opts opts;
1583         struct cgroupfs_root *root;
1584         int ret = 0;
1585         struct super_block *sb;
1586         struct cgroupfs_root *new_root;
1587         struct inode *inode;
1588 
1589         /* First find the desired set of subsystems */
1590         mutex_lock(&cgroup_mutex);
1591         ret = parse_cgroupfs_options(data, &opts);
1592         mutex_unlock(&cgroup_mutex);
1593         if (ret)
1594                 goto out_err;
1595 
1596         /*
1597          * Allocate a new cgroup root. We may not need it if we're
1598          * reusing an existing hierarchy.
1599          */
1600         new_root = cgroup_root_from_opts(&opts);
1601         if (IS_ERR(new_root)) {
1602                 ret = PTR_ERR(new_root);
1603                 goto drop_modules;
1604         }
1605         opts.new_root = new_root;
1606 
1607         /* Locate an existing or new sb for this hierarchy */
1608         sb = sget(fs_type, cgroup_test_super, cgroup_set_super, 0, &opts);
1609         if (IS_ERR(sb)) {
1610                 ret = PTR_ERR(sb);
1611                 cgroup_free_root(opts.new_root);
1612                 goto drop_modules;
1613         }
1614 
1615         root = sb->s_fs_info;
1616         BUG_ON(!root);
1617         if (root == opts.new_root) {
1618                 /* We used the new root structure, so this is a new hierarchy */
1619                 struct list_head tmp_links;
1620                 struct cgroup *root_cgrp = &root->top_cgroup;
1621                 struct cgroupfs_root *existing_root;
1622                 const struct cred *cred;
1623                 int i;
1624                 struct css_set *cset;
1625 
1626                 BUG_ON(sb->s_root != NULL);
1627 
1628                 ret = cgroup_get_rootdir(sb);
1629                 if (ret)
1630                         goto drop_new_super;
1631                 inode = sb->s_root->d_inode;
1632 
1633                 mutex_lock(&inode->i_mutex);
1634                 mutex_lock(&cgroup_mutex);
1635                 mutex_lock(&cgroup_root_mutex);
1636 
1637                 /* Check for name clashes with existing mounts */
1638                 ret = -EBUSY;
1639                 if (strlen(root->name))
1640                         for_each_active_root(existing_root)
1641                                 if (!strcmp(existing_root->name, root->name))
1642                                         goto unlock_drop;
1643 
1644                 /*
1645                  * We're accessing css_set_count without locking
1646                  * css_set_lock here, but that's OK - it can only be
1647                  * increased by someone holding cgroup_lock, and
1648                  * that's us. The worst that can happen is that we
1649                  * have some link structures left over
1650                  */
1651                 ret = allocate_cgrp_cset_links(css_set_count, &tmp_links);
1652                 if (ret)
1653                         goto unlock_drop;
1654 
1655                 /* ID 0 is reserved for dummy root, 1 for unified hierarchy */
1656                 ret = cgroup_init_root_id(root, 2, 0);
1657                 if (ret)
1658                         goto unlock_drop;
1659 
1660                 ret = rebind_subsystems(root, root->subsys_mask, 0);
1661                 if (ret == -EBUSY) {
1662                         free_cgrp_cset_links(&tmp_links);
1663                         goto unlock_drop;
1664                 }
1665                 /*
1666                  * There must be no failure case after here, since rebinding
1667                  * takes care of subsystems' refcounts, which are explicitly
1668                  * dropped in the failure exit path.
1669                  */
1670 
1671                 /* EBUSY should be the only error here */
1672                 BUG_ON(ret);
1673 
1674                 list_add(&root->root_list, &cgroup_roots);
1675                 cgroup_root_count++;
1676 
1677                 sb->s_root->d_fsdata = root_cgrp;
1678                 root->top_cgroup.dentry = sb->s_root;
1679 
1680                 /* Link the top cgroup in this hierarchy into all
1681                  * the css_set objects */
1682                 write_lock(&css_set_lock);
1683                 hash_for_each(css_set_table, i, cset, hlist)
1684                         link_css_set(&tmp_links, cset, root_cgrp);
1685                 write_unlock(&css_set_lock);
1686 
1687                 free_cgrp_cset_links(&tmp_links);
1688 
1689                 BUG_ON(!list_empty(&root_cgrp->children));
1690                 BUG_ON(root->number_of_cgroups != 1);
1691 
1692                 cred = override_creds(&init_cred);
1693                 cgroup_populate_dir(root_cgrp, true, root->subsys_mask);
1694                 revert_creds(cred);
1695                 mutex_unlock(&cgroup_root_mutex);
1696                 mutex_unlock(&cgroup_mutex);
1697                 mutex_unlock(&inode->i_mutex);
1698         } else {
1699                 /*
1700                  * We re-used an existing hierarchy - the new root (if
1701                  * any) is not needed
1702                  */
1703                 cgroup_free_root(opts.new_root);
1704 
1705                 if ((root->flags ^ opts.flags) & CGRP_ROOT_OPTION_MASK) {
1706                         if ((root->flags | opts.flags) & CGRP_ROOT_SANE_BEHAVIOR) {
1707                                 pr_err("cgroup: sane_behavior: new mount options should match the existing superblock\n");
1708                                 ret = -EINVAL;
1709                                 goto drop_new_super;
1710                         } else {
1711                                 pr_warning("cgroup: new mount options do not match the existing superblock, will be ignored\n");
1712                         }
1713                 }
1714 
1715                 /* no subsys rebinding, so refcounts don't change */
1716                 drop_parsed_module_refcounts(opts.subsys_mask);
1717         }
1718 
1719         kfree(opts.release_agent);
1720         kfree(opts.name);
1721         return dget(sb->s_root);
1722 
1723  unlock_drop:
1724         cgroup_exit_root_id(root);
1725         mutex_unlock(&cgroup_root_mutex);
1726         mutex_unlock(&cgroup_mutex);
1727         mutex_unlock(&inode->i_mutex);
1728  drop_new_super:
1729         deactivate_locked_super(sb);
1730  drop_modules:
1731         drop_parsed_module_refcounts(opts.subsys_mask);
1732  out_err:
1733         kfree(opts.release_agent);
1734         kfree(opts.name);
1735         return ERR_PTR(ret);
1736 }
1737 
1738 static void cgroup_kill_sb(struct super_block *sb) {
1739         struct cgroupfs_root *root = sb->s_fs_info;
1740         struct cgroup *cgrp = &root->top_cgroup;
1741         struct cgrp_cset_link *link, *tmp_link;
1742         int ret;
1743 
1744         BUG_ON(!root);
1745 
1746         BUG_ON(root->number_of_cgroups != 1);
1747         BUG_ON(!list_empty(&cgrp->children));
1748 
1749         mutex_lock(&cgroup_mutex);
1750         mutex_lock(&cgroup_root_mutex);
1751 
1752         /* Rebind all subsystems back to the default hierarchy */
1753         if (root->flags & CGRP_ROOT_SUBSYS_BOUND) {
1754                 ret = rebind_subsystems(root, 0, root->subsys_mask);
1755                 /* Shouldn't be able to fail ... */
1756                 BUG_ON(ret);
1757         }
1758 
1759         /*
1760          * Release all the links from cset_links to this hierarchy's
1761          * root cgroup
1762          */
1763         write_lock(&css_set_lock);
1764 
1765         list_for_each_entry_safe(link, tmp_link, &cgrp->cset_links, cset_link) {
1766                 list_del(&link->cset_link);
1767                 list_del(&link->cgrp_link);
1768                 kfree(link);
1769         }
1770         write_unlock(&css_set_lock);
1771 
1772         if (!list_empty(&root->root_list)) {
1773                 list_del(&root->root_list);
1774                 cgroup_root_count--;
1775         }
1776 
1777         cgroup_exit_root_id(root);
1778 
1779         mutex_unlock(&cgroup_root_mutex);
1780         mutex_unlock(&cgroup_mutex);
1781 
1782         simple_xattrs_free(&cgrp->xattrs);
1783 
1784         kill_litter_super(sb);
1785         cgroup_free_root(root);
1786 }
1787 
1788 static struct file_system_type cgroup_fs_type = {
1789         .name = "cgroup",
1790         .mount = cgroup_mount,
1791         .kill_sb = cgroup_kill_sb,
1792 };
1793 
1794 static struct kobject *cgroup_kobj;
1795 
1796 /**
1797  * cgroup_path - generate the path of a cgroup
1798  * @cgrp: the cgroup in question
1799  * @buf: the buffer to write the path into
1800  * @buflen: the length of the buffer
1801  *
1802  * Writes path of cgroup into buf.  Returns 0 on success, -errno on error.
1803  *
1804  * We can't generate cgroup path using dentry->d_name, as accessing
1805  * dentry->name must be protected by irq-unsafe dentry->d_lock or parent
1806  * inode's i_mutex, while on the other hand cgroup_path() can be called
1807  * with some irq-safe spinlocks held.
1808  */
1809 int cgroup_path(const struct cgroup *cgrp, char *buf, int buflen)
1810 {
1811         int ret = -ENAMETOOLONG;
1812         char *start;
1813 
1814         if (!cgrp->parent) {
1815                 if (strlcpy(buf, "/", buflen) >= buflen)
1816                         return -ENAMETOOLONG;
1817                 return 0;
1818         }
1819 
1820         start = buf + buflen - 1;
1821         *start = '\0';
1822 
1823         rcu_read_lock();
1824         do {
1825                 const char *name = cgroup_name(cgrp);
1826                 int len;
1827 
1828                 len = strlen(name);
1829                 if ((start -= len) < buf)
1830                         goto out;
1831                 memcpy(start, name, len);
1832 
1833                 if (--start < buf)
1834                         goto out;
1835                 *start = '/';
1836 
1837                 cgrp = cgrp->parent;
1838         } while (cgrp->parent);
1839         ret = 0;
1840         memmove(buf, start, buf + buflen - start);
1841 out:
1842         rcu_read_unlock();
1843         return ret;
1844 }
1845 EXPORT_SYMBOL_GPL(cgroup_path);
1846 
1847 /**
1848  * task_cgroup_path - cgroup path of a task in the first cgroup hierarchy
1849  * @task: target task
1850  * @buf: the buffer to write the path into
1851  * @buflen: the length of the buffer
1852  *
1853  * Determine @task's cgroup on the first (the one with the lowest non-zero
1854  * hierarchy_id) cgroup hierarchy and copy its path into @buf.  This
1855  * function grabs cgroup_mutex and shouldn't be used inside locks used by
1856  * cgroup controller callbacks.
1857  *
1858  * Returns 0 on success, fails with -%ENAMETOOLONG if @buflen is too short.
1859  */
1860 int task_cgroup_path(struct task_struct *task, char *buf, size_t buflen)
1861 {
1862         struct cgroupfs_root *root;
1863         struct cgroup *cgrp;
1864         int hierarchy_id = 1, ret = 0;
1865 
1866         if (buflen < 2)
1867                 return -ENAMETOOLONG;
1868 
1869         mutex_lock(&cgroup_mutex);
1870 
1871         root = idr_get_next(&cgroup_hierarchy_idr, &hierarchy_id);
1872 
1873         if (root) {
1874                 cgrp = task_cgroup_from_root(task, root);
1875                 ret = cgroup_path(cgrp, buf, buflen);
1876         } else {
1877                 /* if no hierarchy exists, everyone is in "/" */
1878                 memcpy(buf, "/", 2);
1879         }
1880 
1881         mutex_unlock(&cgroup_mutex);
1882         return ret;
1883 }
1884 EXPORT_SYMBOL_GPL(task_cgroup_path);
1885 
1886 /*
1887  * Control Group taskset
1888  */
1889 struct task_and_cgroup {
1890         struct task_struct      *task;
1891         struct cgroup           *cgrp;
1892         struct css_set          *cg;
1893 };
1894 
1895 struct cgroup_taskset {
1896         struct task_and_cgroup  single;
1897         struct flex_array       *tc_array;
1898         int                     tc_array_len;
1899         int                     idx;
1900         struct cgroup           *cur_cgrp;
1901 };
1902 
1903 /**
1904  * cgroup_taskset_first - reset taskset and return the first task
1905  * @tset: taskset of interest
1906  *
1907  * @tset iteration is initialized and the first task is returned.
1908  */
1909 struct task_struct *cgroup_taskset_first(struct cgroup_taskset *tset)
1910 {
1911         if (tset->tc_array) {
1912                 tset->idx = 0;
1913                 return cgroup_taskset_next(tset);
1914         } else {
1915                 tset->cur_cgrp = tset->single.cgrp;
1916                 return tset->single.task;
1917         }
1918 }
1919 EXPORT_SYMBOL_GPL(cgroup_taskset_first);
1920 
1921 /**
1922  * cgroup_taskset_next - iterate to the next task in taskset
1923  * @tset: taskset of interest
1924  *
1925  * Return the next task in @tset.  Iteration must have been initialized
1926  * with cgroup_taskset_first().
1927  */
1928 struct task_struct *cgroup_taskset_next(struct cgroup_taskset *tset)
1929 {
1930         struct task_and_cgroup *tc;
1931 
1932         if (!tset->tc_array || tset->idx >= tset->tc_array_len)
1933                 return NULL;
1934 
1935         tc = flex_array_get(tset->tc_array, tset->idx++);
1936         tset->cur_cgrp = tc->cgrp;
1937         return tc->task;
1938 }
1939 EXPORT_SYMBOL_GPL(cgroup_taskset_next);
1940 
1941 /**
1942  * cgroup_taskset_cur_cgroup - return the matching cgroup for the current task
1943  * @tset: taskset of interest
1944  *
1945  * Return the cgroup for the current (last returned) task of @tset.  This
1946  * function must be preceded by either cgroup_taskset_first() or
1947  * cgroup_taskset_next().
1948  */
1949 struct cgroup *cgroup_taskset_cur_cgroup(struct cgroup_taskset *tset)
1950 {
1951         return tset->cur_cgrp;
1952 }
1953 EXPORT_SYMBOL_GPL(cgroup_taskset_cur_cgroup);
1954 
1955 /**
1956  * cgroup_taskset_size - return the number of tasks in taskset
1957  * @tset: taskset of interest
1958  */
1959 int cgroup_taskset_size(struct cgroup_taskset *tset)
1960 {
1961         return tset->tc_array ? tset->tc_array_len : 1;
1962 }
1963 EXPORT_SYMBOL_GPL(cgroup_taskset_size);
1964 
1965 
1966 /*
1967  * cgroup_task_migrate - move a task from one cgroup to another.
1968  *
1969  * Must be called with cgroup_mutex and threadgroup locked.
1970  */
1971 static void cgroup_task_migrate(struct cgroup *old_cgrp,
1972                                 struct task_struct *tsk,
1973                                 struct css_set *new_cset)
1974 {
1975         struct css_set *old_cset;
1976 
1977         /*
1978          * We are synchronized through threadgroup_lock() against PF_EXITING
1979          * setting such that we can't race against cgroup_exit() changing the
1980          * css_set to init_css_set and dropping the old one.
1981          */
1982         WARN_ON_ONCE(tsk->flags & PF_EXITING);
1983         old_cset = task_css_set(tsk);
1984 
1985         task_lock(tsk);
1986         rcu_assign_pointer(tsk->cgroups, new_cset);
1987         task_unlock(tsk);
1988 
1989         /* Update the css_set linked lists if we're using them */
1990         write_lock(&css_set_lock);
1991         if (!list_empty(&tsk->cg_list))
1992                 list_move(&tsk->cg_list, &new_cset->tasks);
1993         write_unlock(&css_set_lock);
1994 
1995         /*
1996          * We just gained a reference on old_cset by taking it from the
1997          * task. As trading it for new_cset is protected by cgroup_mutex,
1998          * we're safe to drop it here; it will be freed under RCU.
1999          */
2000         set_bit(CGRP_RELEASABLE, &old_cgrp->flags);
2001         put_css_set(old_cset);
2002 }
2003 
2004 /**
2005  * cgroup_attach_task - attach a task or a whole threadgroup to a cgroup
2006  * @cgrp: the cgroup to attach to
2007  * @tsk: the task or the leader of the threadgroup to be attached
2008  * @threadgroup: attach the whole threadgroup?
2009  *
2010  * Call holding cgroup_mutex and the group_rwsem of the leader. Will take
2011  * task_lock of @tsk or each thread in the threadgroup individually in turn.
2012  */
2013 static int cgroup_attach_task(struct cgroup *cgrp, struct task_struct *tsk,
2014                               bool threadgroup)
2015 {
2016         int retval, i, group_size;
2017         struct cgroup_subsys *ss, *failed_ss = NULL;
2018         struct cgroupfs_root *root = cgrp->root;
2019         /* threadgroup list cursor and array */
2020         struct task_struct *leader = tsk;
2021         struct task_and_cgroup *tc;
2022         struct flex_array *group;
2023         struct cgroup_taskset tset = { };
2024 
2025         /*
2026          * step 0: in order to do expensive, possibly blocking operations for
2027          * every thread, we cannot iterate the thread group list, since it needs
2028          * rcu or tasklist locked. instead, build an array of all threads in the
2029          * group - group_rwsem prevents new threads from appearing, and if
2030          * threads exit, this will just be an over-estimate.
2031          */
2032         if (threadgroup)
2033                 group_size = get_nr_threads(tsk);
2034         else
2035                 group_size = 1;
2036         /* flex_array supports very large thread-groups better than kmalloc. */
2037         group = flex_array_alloc(sizeof(*tc), group_size, GFP_KERNEL);
2038         if (!group)
2039                 return -ENOMEM;
2040         /* pre-allocate to guarantee space while iterating in rcu read-side. */
2041         retval = flex_array_prealloc(group, 0, group_size, GFP_KERNEL);
2042         if (retval)
2043                 goto out_free_group_list;
2044 
2045         i = 0;
2046         /*
2047          * Prevent freeing of tasks while we take a snapshot. Tasks that are
2048          * already PF_EXITING could be freed from underneath us unless we
2049          * take an rcu_read_lock.
2050          */
2051         rcu_read_lock();
2052         do {
2053                 struct task_and_cgroup ent;
2054 
2055                 /* @tsk either already exited or can't exit until the end */
2056                 if (tsk->flags & PF_EXITING)
2057                         continue;
2058 
2059                 /* as per above, nr_threads may decrease, but not increase. */
2060                 BUG_ON(i >= group_size);
2061                 ent.task = tsk;
2062                 ent.cgrp = task_cgroup_from_root(tsk, root);
2063                 /* nothing to do if this task is already in the cgroup */
2064                 if (ent.cgrp == cgrp)
2065                         continue;
2066                 /*
2067                  * saying GFP_ATOMIC has no effect here because we did prealloc
2068                  * earlier, but it's good form to communicate our expectations.
2069                  */
2070                 retval = flex_array_put(group, i, &ent, GFP_ATOMIC);
2071                 BUG_ON(retval != 0);
2072                 i++;
2073 
2074                 if (!threadgroup)
2075                         break;
2076         } while_each_thread(leader, tsk);
2077         rcu_read_unlock();
2078         /* remember the number of threads in the array for later. */
2079         group_size = i;
2080         tset.tc_array = group;
2081         tset.tc_array_len = group_size;
2082 
2083         /* methods shouldn't be called if no task is actually migrating */
2084         retval = 0;
2085         if (!group_size)
2086                 goto out_free_group_list;
2087 
2088         /*
2089          * step 1: check that we can legitimately attach to the cgroup.
2090          */
2091         for_each_root_subsys(root, ss) {
2092                 if (ss->can_attach) {
2093                         retval = ss->can_attach(cgrp, &tset);
2094                         if (retval) {
2095                                 failed_ss = ss;
2096                                 goto out_cancel_attach;
2097                         }
2098                 }
2099         }
2100 
2101         /*
2102          * step 2: make sure css_sets exist for all threads to be migrated.
2103          * we use find_css_set, which allocates a new one if necessary.
2104          */
2105         for (i = 0; i < group_size; i++) {
2106                 struct css_set *old_cset;
2107 
2108                 tc = flex_array_get(group, i);
2109                 old_cset = task_css_set(tc->task);
2110                 tc->cg = find_css_set(old_cset, cgrp);
2111                 if (!tc->cg) {
2112                         retval = -ENOMEM;
2113                         goto out_put_css_set_refs;
2114                 }
2115         }
2116 
2117         /*
2118          * step 3: now that we're guaranteed success wrt the css_sets,
2119          * proceed to move all tasks to the new cgroup.  There are no
2120          * failure cases after here, so this is the commit point.
2121          */
2122         for (i = 0; i < group_size; i++) {
2123                 tc = flex_array_get(group, i);
2124                 cgroup_task_migrate(tc->cgrp, tc->task, tc->cg);
2125         }
2126         /* nothing is sensitive to fork() after this point. */
2127 
2128         /*
2129          * step 4: do subsystem attach callbacks.
2130          */
2131         for_each_root_subsys(root, ss) {
2132                 if (ss->attach)
2133                         ss->attach(cgrp, &tset);
2134         }
2135 
2136         /*
2137          * step 5: success! and cleanup
2138          */
2139         retval = 0;
2140 out_put_css_set_refs:
2141         if (retval) {
2142                 for (i = 0; i < group_size; i++) {
2143                         tc = flex_array_get(group, i);
2144                         if (!tc->cg)
2145                                 break;
2146                         put_css_set(tc->cg);
2147                 }
2148         }
2149 out_cancel_attach:
2150         if (retval) {
2151                 for_each_root_subsys(root, ss) {
2152                         if (ss == failed_ss)
2153                                 break;
2154                         if (ss->cancel_attach)
2155                                 ss->cancel_attach(cgrp, &tset);
2156                 }
2157         }
2158 out_free_group_list:
2159         flex_array_free(group);
2160         return retval;
2161 }
2162 
2163 /*
2164  * Find the task_struct of the task to attach by vpid and pass it along to the
2165  * function to attach either it or all tasks in its threadgroup. Will lock
2166  * cgroup_mutex and threadgroup; may take task_lock of task.
2167  */
2168 static int attach_task_by_pid(struct cgroup *cgrp, u64 pid, bool threadgroup)
2169 {
2170         struct task_struct *tsk;
2171         const struct cred *cred = current_cred(), *tcred;
2172         int ret;
2173 
2174         if (!cgroup_lock_live_group(cgrp))
2175                 return -ENODEV;
2176 
2177 retry_find_task:
2178         rcu_read_lock();
2179         if (pid) {
2180                 tsk = find_task_by_vpid(pid);
2181                 if (!tsk) {
2182                         rcu_read_unlock();
2183                         ret= -ESRCH;
2184                         goto out_unlock_cgroup;
2185                 }
2186                 /*
2187                  * even if we're attaching all tasks in the thread group, we
2188                  * only need to check permissions on one of them.
2189                  */
2190                 tcred = __task_cred(tsk);
2191                 if (!uid_eq(cred->euid, GLOBAL_ROOT_UID) &&
2192                     !uid_eq(cred->euid, tcred->uid) &&
2193                     !uid_eq(cred->euid, tcred->suid)) {
2194                         rcu_read_unlock();
2195                         ret = -EACCES;
2196                         goto out_unlock_cgroup;
2197                 }
2198         } else
2199                 tsk = current;
2200 
2201         if (threadgroup)
2202                 tsk = tsk->group_leader;
2203 
2204         /*
2205          * Workqueue threads may acquire PF_NO_SETAFFINITY and become
2206          * trapped in a cpuset, or RT worker may be born in a cgroup
2207          * with no rt_runtime allocated.  Just say no.
2208          */
2209         if (tsk == kthreadd_task || (tsk->flags & PF_NO_SETAFFINITY)) {
2210                 ret = -EINVAL;
2211                 rcu_read_unlock();
2212                 goto out_unlock_cgroup;
2213         }
2214 
2215         get_task_struct(tsk);
2216         rcu_read_unlock();
2217 
2218         threadgroup_lock(tsk);
2219         if (threadgroup) {
2220                 if (!thread_group_leader(tsk)) {
2221                         /*
2222                          * a race with de_thread from another thread's exec()
2223                          * may strip us of our leadership, if this happens,
2224                          * there is no choice but to throw this task away and
2225                          * try again; this is
2226                          * "double-double-toil-and-trouble-check locking".
2227                          */
2228                         threadgroup_unlock(tsk);
2229                         put_task_struct(tsk);
2230                         goto retry_find_task;
2231                 }
2232         }
2233 
2234         ret = cgroup_attach_task(cgrp, tsk, threadgroup);
2235 
2236         threadgroup_unlock(tsk);
2237 
2238         put_task_struct(tsk);
2239 out_unlock_cgroup:
2240         mutex_unlock(&cgroup_mutex);
2241         return ret;
2242 }
2243 
2244 /**
2245  * cgroup_attach_task_all - attach task 'tsk' to all cgroups of task 'from'
2246  * @from: attach to all cgroups of a given task
2247  * @tsk: the task to be attached
2248  */
2249 int cgroup_attach_task_all(struct task_struct *from, struct task_struct *tsk)
2250 {
2251         struct cgroupfs_root *root;
2252         int retval = 0;
2253 
2254         mutex_lock(&cgroup_mutex);
2255         for_each_active_root(root) {
2256                 struct cgroup *from_cg = task_cgroup_from_root(from, root);
2257 
2258                 retval = cgroup_attach_task(from_cg, tsk, false);
2259                 if (retval)
2260                         break;
2261         }
2262         mutex_unlock(&cgroup_mutex);
2263 
2264         return retval;
2265 }
2266 EXPORT_SYMBOL_GPL(cgroup_attach_task_all);
2267 
2268 static int cgroup_tasks_write(struct cgroup *cgrp, struct cftype *cft, u64 pid)
2269 {
2270         return attach_task_by_pid(cgrp, pid, false);
2271 }
2272 
2273 static int cgroup_procs_write(struct cgroup *cgrp, struct cftype *cft, u64 tgid)
2274 {
2275         return attach_task_by_pid(cgrp, tgid, true);
2276 }
2277 
2278 static int cgroup_release_agent_write(struct cgroup *cgrp, struct cftype *cft,
2279                                       const char *buffer)
2280 {
2281         BUILD_BUG_ON(sizeof(cgrp->root->release_agent_path) < PATH_MAX);
2282         if (strlen(buffer) >= PATH_MAX)
2283                 return -EINVAL;
2284         if (!cgroup_lock_live_group(cgrp))
2285                 return -ENODEV;
2286         mutex_lock(&cgroup_root_mutex);
2287         strcpy(cgrp->root->release_agent_path, buffer);
2288         mutex_unlock(&cgroup_root_mutex);
2289         mutex_unlock(&cgroup_mutex);
2290         return 0;
2291 }
2292 
2293 static int cgroup_release_agent_show(struct cgroup *cgrp, struct cftype *cft,
2294                                      struct seq_file *seq)
2295 {
2296         if (!cgroup_lock_live_group(cgrp))
2297                 return -ENODEV;
2298         seq_puts(seq, cgrp->root->release_agent_path);
2299         seq_putc(seq, '\n');
2300         mutex_unlock(&cgroup_mutex);
2301         return 0;
2302 }
2303 
2304 static int cgroup_sane_behavior_show(struct cgroup *cgrp, struct cftype *cft,
2305                                      struct seq_file *seq)
2306 {
2307         seq_printf(seq, "%d\n", cgroup_sane_behavior(cgrp));
2308         return 0;
2309 }
2310 
2311 /* A buffer size big enough for numbers or short strings */
2312 #define CGROUP_LOCAL_BUFFER_SIZE 64
2313 
2314 static ssize_t cgroup_write_X64(struct cgroup *cgrp, struct cftype *cft,
2315                                 struct file *file,
2316                                 const char __user *userbuf,
2317                                 size_t nbytes, loff_t *unused_ppos)
2318 {
2319         char buffer[CGROUP_LOCAL_BUFFER_SIZE];
2320         int retval = 0;
2321         char *end;
2322 
2323         if (!nbytes)
2324                 return -EINVAL;
2325         if (nbytes >= sizeof(buffer))
2326                 return -E2BIG;
2327         if (copy_from_user(buffer, userbuf, nbytes))
2328                 return -EFAULT;
2329 
2330         buffer[nbytes] = 0;     /* nul-terminate */
2331         if (cft->write_u64) {
2332                 u64 val = simple_strtoull(strstrip(buffer), &end, 0);
2333                 if (*end)
2334                         return -EINVAL;
2335                 retval = cft->write_u64(cgrp, cft, val);
2336         } else {
2337                 s64 val = simple_strtoll(strstrip(buffer), &end, 0);
2338                 if (*end)
2339                         return -EINVAL;
2340                 retval = cft->write_s64(cgrp, cft, val);
2341         }
2342         if (!retval)
2343                 retval = nbytes;
2344         return retval;
2345 }
2346 
2347 static ssize_t cgroup_write_string(struct cgroup *cgrp, struct cftype *cft,
2348                                    struct file *file,
2349                                    const char __user *userbuf,
2350                                    size_t nbytes, loff_t *unused_ppos)
2351 {
2352         char local_buffer[CGROUP_LOCAL_BUFFER_SIZE];
2353         int retval = 0;
2354         size_t max_bytes = cft->max_write_len;
2355         char *buffer = local_buffer;
2356 
2357         if (!max_bytes)
2358                 max_bytes = sizeof(local_buffer) - 1;
2359         if (nbytes >= max_bytes)
2360                 return -E2BIG;
2361         /* Allocate a dynamic buffer if we need one */
2362         if (nbytes >= sizeof(local_buffer)) {
2363                 buffer = kmalloc(nbytes + 1, GFP_KERNEL);
2364                 if (buffer == NULL)
2365                         return -ENOMEM;
2366         }
2367         if (nbytes && copy_from_user(buffer, userbuf, nbytes)) {
2368                 retval = -EFAULT;
2369                 goto out;
2370         }
2371 
2372         buffer[nbytes] = 0;     /* nul-terminate */
2373         retval = cft->write_string(cgrp, cft, strstrip(buffer));
2374         if (!retval)
2375                 retval = nbytes;
2376 out:
2377         if (buffer != local_buffer)
2378                 kfree(buffer);
2379         return retval;
2380 }
2381 
2382 static ssize_t cgroup_file_write(struct file *file, const char __user *buf,
2383                                                 size_t nbytes, loff_t *ppos)
2384 {
2385         struct cftype *cft = __d_cft(file->f_dentry);
2386         struct cgroup *cgrp = __d_cgrp(file->f_dentry->d_parent);
2387 
2388         if (cgroup_is_dead(cgrp))
2389                 return -ENODEV;
2390         if (cft->write)
2391                 return cft->write(cgrp, cft, file, buf, nbytes, ppos);
2392         if (cft->write_u64 || cft->write_s64)
2393                 return cgroup_write_X64(cgrp, cft, file, buf, nbytes, ppos);
2394         if (cft->write_string)
2395                 return cgroup_write_string(cgrp, cft, file, buf, nbytes, ppos);
2396         if (cft->trigger) {
2397                 int ret = cft->trigger(cgrp, (unsigned int)cft->private);
2398                 return ret ? ret : nbytes;
2399         }
2400         return -EINVAL;
2401 }
2402 
2403 static ssize_t cgroup_read_u64(struct cgroup *cgrp, struct cftype *cft,
2404                                struct file *file,
2405                                char __user *buf, size_t nbytes,
2406                                loff_t *ppos)
2407 {
2408         char tmp[CGROUP_LOCAL_BUFFER_SIZE];
2409         u64 val = cft->read_u64(cgrp, cft);
2410         int len = sprintf(tmp, "%llu\n", (unsigned long long) val);
2411 
2412         return simple_read_from_buffer(buf, nbytes, ppos, tmp, len);
2413 }
2414 
2415 static ssize_t cgroup_read_s64(struct cgroup *cgrp, struct cftype *cft,
2416                                struct file *file,
2417                                char __user *buf, size_t nbytes,
2418                                loff_t *ppos)
2419 {
2420         char tmp[CGROUP_LOCAL_BUFFER_SIZE];
2421         s64 val = cft->read_s64(cgrp, cft);
2422         int len = sprintf(tmp, "%lld\n", (long long) val);
2423 
2424         return simple_read_from_buffer(buf, nbytes, ppos, tmp, len);
2425 }
2426 
2427 static ssize_t cgroup_file_read(struct file *file, char __user *buf,
2428                                    size_t nbytes, loff_t *ppos)
2429 {
2430         struct cftype *cft = __d_cft(file->f_dentry);
2431         struct cgroup *cgrp = __d_cgrp(file->f_dentry->d_parent);
2432 
2433         if (cgroup_is_dead(cgrp))
2434                 return -ENODEV;
2435 
2436         if (cft->read)
2437                 return cft->read(cgrp, cft, file, buf, nbytes, ppos);
2438         if (cft->read_u64)
2439                 return cgroup_read_u64(cgrp, cft, file, buf, nbytes, ppos);
2440         if (cft->read_s64)
2441                 return cgroup_read_s64(cgrp, cft, file, buf, nbytes, ppos);
2442         return -EINVAL;
2443 }
2444 
2445 /*
2446  * seqfile ops/methods for returning structured data. Currently just
2447  * supports string->u64 maps, but can be extended in future.
2448  */
2449 
2450 struct cgroup_seqfile_state {
2451         struct cftype *cft;
2452         struct cgroup *cgroup;
2453 };
2454 
2455 static int cgroup_map_add(struct cgroup_map_cb *cb, const char *key, u64 value)
2456 {
2457         struct seq_file *sf = cb->state;
2458         return seq_printf(sf, "%s %llu\n", key, (unsigned long long)value);
2459 }
2460 
2461 static int cgroup_seqfile_show(struct seq_file *m, void *arg)
2462 {
2463         struct cgroup_seqfile_state *state = m->private;
2464         struct cftype *cft = state->cft;
2465         if (cft->read_map) {
2466                 struct cgroup_map_cb cb = {
2467                         .fill = cgroup_map_add,
2468                         .state = m,
2469                 };
2470                 return cft->read_map(state->cgroup, cft, &cb);
2471         }
2472         return cft->read_seq_string(state->cgroup, cft, m);
2473 }
2474 
2475 static int cgroup_seqfile_release(struct inode *inode, struct file *file)
2476 {
2477         struct seq_file *seq = file->private_data;
2478         kfree(seq->private);
2479         return single_release(inode, file);
2480 }
2481 
2482 static const struct file_operations cgroup_seqfile_operations = {
2483         .read = seq_read,
2484         .write = cgroup_file_write,
2485         .llseek = seq_lseek,
2486         .release = cgroup_seqfile_release,
2487 };
2488 
2489 static int cgroup_file_open(struct inode *inode, struct file *file)
2490 {
2491         int err;
2492         struct cftype *cft;
2493 
2494         err = generic_file_open(inode, file);
2495         if (err)
2496                 return err;
2497         cft = __d_cft(file->f_dentry);
2498 
2499         if (cft->read_map || cft->read_seq_string) {
2500                 struct cgroup_seqfile_state *state;
2501 
2502                 state = kzalloc(sizeof(*state), GFP_USER);
2503                 if (!state)
2504                         return -ENOMEM;
2505 
2506                 state->cft = cft;
2507                 state->cgroup = __d_cgrp(file->f_dentry->d_parent);
2508                 file->f_op = &cgroup_seqfile_operations;
2509                 err = single_open(file, cgroup_seqfile_show, state);
2510                 if (err < 0)
2511                         kfree(state);
2512         } else if (cft->open)
2513                 err = cft->open(inode, file);
2514         else
2515                 err = 0;
2516 
2517         return err;
2518 }
2519 
2520 static int cgroup_file_release(struct inode *inode, struct file *file)
2521 {
2522         struct cftype *cft = __d_cft(file->f_dentry);
2523         if (cft->release)
2524                 return cft->release(inode, file);
2525         return 0;
2526 }
2527 
2528 /*
2529  * cgroup_rename - Only allow simple rename of directories in place.
2530  */
2531 static int cgroup_rename(struct inode *old_dir, struct dentry *old_dentry,
2532                             struct inode *new_dir, struct dentry *new_dentry)
2533 {
2534         int ret;
2535         struct cgroup_name *name, *old_name;
2536         struct cgroup *cgrp;
2537 
2538         /*
2539          * It's convinient to use parent dir's i_mutex to protected
2540          * cgrp->name.
2541          */
2542         lockdep_assert_held(&old_dir->i_mutex);
2543 
2544         if (!S_ISDIR(old_dentry->d_inode->i_mode))
2545                 return -ENOTDIR;
2546         if (new_dentry->d_inode)
2547                 return -EEXIST;
2548         if (old_dir != new_dir)
2549                 return -EIO;
2550 
2551         cgrp = __d_cgrp(old_dentry);
2552 
2553         /*
2554          * This isn't a proper migration and its usefulness is very
2555          * limited.  Disallow if sane_behavior.
2556          */
2557         if (cgroup_sane_behavior(cgrp))
2558                 return -EPERM;
2559 
2560         name = cgroup_alloc_name(new_dentry);
2561         if (!name)
2562                 return -ENOMEM;
2563 
2564         ret = simple_rename(old_dir, old_dentry, new_dir, new_dentry);
2565         if (ret) {
2566                 kfree(name);
2567                 return ret;
2568         }
2569 
2570         old_name = rcu_dereference_protected(cgrp->name, true);
2571         rcu_assign_pointer(cgrp->name, name);
2572 
2573         kfree_rcu(old_name, rcu_head);
2574         return 0;
2575 }
2576 
2577 static struct simple_xattrs *__d_xattrs(struct dentry *dentry)
2578 {
2579         if (S_ISDIR(dentry->d_inode->i_mode))
2580                 return &__d_cgrp(dentry)->xattrs;
2581         else
2582                 return &__d_cfe(dentry)->xattrs;
2583 }
2584 
2585 static inline int xattr_enabled(struct dentry *dentry)
2586 {
2587         struct cgroupfs_root *root = dentry->d_sb->s_fs_info;
2588         return root->flags & CGRP_ROOT_XATTR;
2589 }
2590 
2591 static bool is_valid_xattr(const char *name)
2592 {
2593         if (!strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN) ||
2594             !strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN))
2595                 return true;
2596         return false;
2597 }
2598 
2599 static int cgroup_setxattr(struct dentry *dentry, const char *name,
2600                            const void *val, size_t size, int flags)
2601 {
2602         if (!xattr_enabled(dentry))
2603                 return -EOPNOTSUPP;
2604         if (!is_valid_xattr(name))
2605                 return -EINVAL;
2606         return simple_xattr_set(__d_xattrs(dentry), name, val, size, flags);
2607 }
2608 
2609 static int cgroup_removexattr(struct dentry *dentry, const char *name)
2610 {
2611         if (!xattr_enabled(dentry))
2612                 return -EOPNOTSUPP;
2613         if (!is_valid_xattr(name))
2614                 return -EINVAL;
2615         return simple_xattr_remove(__d_xattrs(dentry), name);
2616 }
2617 
2618 static ssize_t cgroup_getxattr(struct dentry *dentry, const char *name,
2619                                void *buf, size_t size)
2620 {
2621         if (!xattr_enabled(dentry))
2622                 return -EOPNOTSUPP;
2623         if (!is_valid_xattr(name))
2624                 return -EINVAL;
2625         return simple_xattr_get(__d_xattrs(dentry), name, buf, size);
2626 }
2627 
2628 static ssize_t cgroup_listxattr(struct dentry *dentry, char *buf, size_t size)
2629 {
2630         if (!xattr_enabled(dentry))
2631                 return -EOPNOTSUPP;
2632         return simple_xattr_list(__d_xattrs(dentry), buf, size);
2633 }
2634 
2635 static const struct file_operations cgroup_file_operations = {
2636         .read = cgroup_file_read,
2637         .write = cgroup_file_write,
2638         .llseek = generic_file_llseek,
2639         .open = cgroup_file_open,
2640         .release = cgroup_file_release,
2641 };
2642 
2643 static const struct inode_operations cgroup_file_inode_operations = {
2644         .setxattr = cgroup_setxattr,
2645         .getxattr = cgroup_getxattr,
2646         .listxattr = cgroup_listxattr,
2647         .removexattr = cgroup_removexattr,
2648 };
2649 
2650 static const struct inode_operations cgroup_dir_inode_operations = {
2651         .lookup = simple_lookup,
2652         .mkdir = cgroup_mkdir,
2653         .rmdir = cgroup_rmdir,
2654         .rename = cgroup_rename,
2655         .setxattr = cgroup_setxattr,
2656         .getxattr = cgroup_getxattr,
2657         .listxattr = cgroup_listxattr,
2658         .removexattr = cgroup_removexattr,
2659 };
2660 
2661 /*
2662  * Check if a file is a control file
2663  */
2664 static inline struct cftype *__file_cft(struct file *file)
2665 {
2666         if (file_inode(file)->i_fop != &cgroup_file_operations)
2667                 return ERR_PTR(-EINVAL);
2668         return __d_cft(file->f_dentry);
2669 }
2670 
2671 static int cgroup_create_file(struct dentry *dentry, umode_t mode,
2672                                 struct super_block *sb)
2673 {
2674         struct inode *inode;
2675 
2676         if (!dentry)
2677                 return -ENOENT;
2678         if (dentry->d_inode)
2679                 return -EEXIST;
2680 
2681         inode = cgroup_new_inode(mode, sb);
2682         if (!inode)
2683                 return -ENOMEM;
2684 
2685         if (S_ISDIR(mode)) {
2686                 inode->i_op = &cgroup_dir_inode_operations;
2687                 inode->i_fop = &simple_dir_operations;
2688 
2689                 /* start off with i_nlink == 2 (for "." entry) */
2690                 inc_nlink(inode);
2691                 inc_nlink(dentry->d_parent->d_inode);
2692 
2693                 /*
2694                  * Control reaches here with cgroup_mutex held.
2695                  * @inode->i_mutex should nest outside cgroup_mutex but we
2696                  * want to populate it immediately without releasing
2697                  * cgroup_mutex.  As @inode isn't visible to anyone else
2698                  * yet, trylock will always succeed without affecting
2699                  * lockdep checks.
2700                  */
2701                 WARN_ON_ONCE(!mutex_trylock(&inode->i_mutex));
2702         } else if (S_ISREG(mode)) {
2703                 inode->i_size = 0;
2704                 inode->i_fop = &cgroup_file_operations;
2705                 inode->i_op = &cgroup_file_inode_operations;
2706         }
2707         d_instantiate(dentry, inode);
2708         dget(dentry);   /* Extra count - pin the dentry in core */
2709         return 0;
2710 }
2711 
2712 /**
2713  * cgroup_file_mode - deduce file mode of a control file
2714  * @cft: the control file in question
2715  *
2716  * returns cft->mode if ->mode is not 0
2717  * returns S_IRUGO|S_IWUSR if it has both a read and a write handler
2718  * returns S_IRUGO if it has only a read handler
2719  * returns S_IWUSR if it has only a write hander
2720  */
2721 static umode_t cgroup_file_mode(const struct cftype *cft)
2722 {
2723         umode_t mode = 0;
2724 
2725         if (cft->mode)
2726                 return cft->mode;
2727 
2728         if (cft->read || cft->read_u64 || cft->read_s64 ||
2729             cft->read_map || cft->read_seq_string)
2730                 mode |= S_IRUGO;
2731 
2732         if (cft->write || cft->write_u64 || cft->write_s64 ||
2733             cft->write_string || cft->trigger)
2734                 mode |= S_IWUSR;
2735 
2736         return mode;
2737 }
2738 
2739 static int cgroup_add_file(struct cgroup *cgrp, struct cgroup_subsys *subsys,
2740                            struct cftype *cft)
2741 {
2742         struct dentry *dir = cgrp->dentry;
2743         struct cgroup *parent = __d_cgrp(dir);
2744         struct dentry *dentry;
2745         struct cfent *cfe;
2746         int error;
2747         umode_t mode;
2748         char name[MAX_CGROUP_TYPE_NAMELEN + MAX_CFTYPE_NAME + 2] = { 0 };
2749 
2750         if (subsys && !(cgrp->root->flags & CGRP_ROOT_NOPREFIX)) {
2751                 strcpy(name, subsys->name);
2752                 strcat(name, ".");
2753         }
2754         strcat(name, cft->name);
2755 
2756         BUG_ON(!mutex_is_locked(&dir->d_inode->i_mutex));
2757 
2758         cfe = kzalloc(sizeof(*cfe), GFP_KERNEL);
2759         if (!cfe)
2760                 return -ENOMEM;
2761 
2762         dentry = lookup_one_len(name, dir, strlen(name));
2763         if (IS_ERR(dentry)) {
2764                 error = PTR_ERR(dentry);
2765                 goto out;
2766         }
2767 
2768         cfe->type = (void *)cft;
2769         cfe->dentry = dentry;
2770         dentry->d_fsdata = cfe;
2771         simple_xattrs_init(&cfe->xattrs);
2772 
2773         mode = cgroup_file_mode(cft);
2774         error = cgroup_create_file(dentry, mode | S_IFREG, cgrp->root->sb);
2775         if (!error) {
2776                 list_add_tail(&cfe->node, &parent->files);
2777                 cfe = NULL;
2778         }
2779         dput(dentry);
2780 out:
2781         kfree(cfe);
2782         return error;
2783 }
2784 
2785 static int cgroup_addrm_files(struct cgroup *cgrp, struct cgroup_subsys *subsys,
2786                               struct cftype cfts[], bool is_add)
2787 {
2788         struct cftype *cft;
2789         int err, ret = 0;
2790 
2791         for (cft = cfts; cft->name[0] != '\0'; cft++) {
2792                 /* does cft->flags tell us to skip this file on @cgrp? */
2793                 if ((cft->flags & CFTYPE_INSANE) && cgroup_sane_behavior(cgrp))
2794                         continue;
2795                 if ((cft->flags & CFTYPE_NOT_ON_ROOT) && !cgrp->parent)
2796                         continue;
2797                 if ((cft->flags & CFTYPE_ONLY_ON_ROOT) && cgrp->parent)
2798                         continue;
2799 
2800                 if (is_add) {
2801                         err = cgroup_add_file(cgrp, subsys, cft);
2802                         if (err)
2803                                 pr_warn("cgroup_addrm_files: failed to add %s, err=%d\n",
2804                                         cft->name, err);
2805                         ret = err;
2806                 } else {
2807                         cgroup_rm_file(cgrp, cft);
2808                 }
2809         }
2810         return ret;
2811 }
2812 
2813 static void cgroup_cfts_prepare(void)
2814         __acquires(&cgroup_mutex)
2815 {
2816         /*
2817          * Thanks to the entanglement with vfs inode locking, we can't walk
2818          * the existing cgroups under cgroup_mutex and create files.
2819          * Instead, we use cgroup_for_each_descendant_pre() and drop RCU
2820          * read lock before calling cgroup_addrm_files().
2821          */
2822         mutex_lock(&cgroup_mutex);
2823 }
2824 
2825 static void cgroup_cfts_commit(struct cgroup_subsys *ss,
2826                                struct cftype *cfts, bool is_add)
2827         __releases(&cgroup_mutex)
2828 {
2829         LIST_HEAD(pending);
2830         struct cgroup *cgrp, *root = &ss->root->top_cgroup;
2831         struct super_block *sb = ss->root->sb;
2832         struct dentry *prev = NULL;
2833         struct inode *inode;
2834         u64 update_before;
2835 
2836         /* %NULL @cfts indicates abort and don't bother if @ss isn't attached */
2837         if (!cfts || ss->root == &cgroup_dummy_root ||
2838             !atomic_inc_not_zero(&sb->s_active)) {
2839                 mutex_unlock(&cgroup_mutex);
2840                 return;
2841         }
2842 
2843         /*
2844          * All cgroups which are created after we drop cgroup_mutex will
2845          * have the updated set of files, so we only need to update the
2846          * cgroups created before the current @cgroup_serial_nr_next.
2847          */
2848         update_before = cgroup_serial_nr_next;
2849 
2850         mutex_unlock(&cgroup_mutex);
2851 
2852         /* @root always needs to be updated */
2853         inode = root->dentry->d_inode;
2854         mutex_lock(&inode->i_mutex);
2855         mutex_lock(&cgroup_mutex);
2856         cgroup_addrm_files(root, ss, cfts, is_add);
2857         mutex_unlock(&cgroup_mutex);
2858         mutex_unlock(&inode->i_mutex);
2859 
2860         /* add/rm files for all cgroups created before */
2861         rcu_read_lock();
2862         cgroup_for_each_descendant_pre(cgrp, root) {
2863                 if (cgroup_is_dead(cgrp))
2864                         continue;
2865 
2866                 inode = cgrp->dentry->d_inode;
2867                 dget(cgrp->dentry);
2868                 rcu_read_unlock();
2869 
2870                 dput(prev);
2871                 prev = cgrp->dentry;
2872 
2873                 mutex_lock(&inode->i_mutex);
2874                 mutex_lock(&cgroup_mutex);
2875                 if (cgrp->serial_nr < update_before && !cgroup_is_dead(cgrp))
2876                         cgroup_addrm_files(cgrp, ss, cfts, is_add);
2877                 mutex_unlock(&cgroup_mutex);
2878                 mutex_unlock(&inode->i_mutex);
2879 
2880                 rcu_read_lock();
2881         }
2882         rcu_read_unlock();
2883         dput(prev);
2884         deactivate_super(sb);
2885 }
2886 
2887 /**
2888  * cgroup_add_cftypes - add an array of cftypes to a subsystem
2889  * @ss: target cgroup subsystem
2890  * @cfts: zero-length name terminated array of cftypes
2891  *
2892  * Register @cfts to @ss.  Files described by @cfts are created for all
2893  * existing cgroups to which @ss is attached and all future cgroups will
2894  * have them too.  This function can be called anytime whether @ss is
2895  * attached or not.
2896  *
2897  * Returns 0 on successful registration, -errno on failure.  Note that this
2898  * function currently returns 0 as long as @cfts registration is successful
2899  * even if some file creation attempts on existing cgroups fail.
2900  */
2901 int cgroup_add_cftypes(struct cgroup_subsys *ss, struct cftype *cfts)
2902 {
2903         struct cftype_set *set;
2904 
2905         set = kzalloc(sizeof(*set), GFP_KERNEL);
2906         if (!set)
2907                 return -ENOMEM;
2908 
2909         cgroup_cfts_prepare();
2910         set->cfts = cfts;
2911         list_add_tail(&set->node, &ss->cftsets);
2912         cgroup_cfts_commit(ss, cfts, true);
2913 
2914         return 0;
2915 }
2916 EXPORT_SYMBOL_GPL(cgroup_add_cftypes);
2917 
2918 /**
2919  * cgroup_rm_cftypes - remove an array of cftypes from a subsystem
2920  * @ss: target cgroup subsystem
2921  * @cfts: zero-length name terminated array of cftypes
2922  *
2923  * Unregister @cfts from @ss.  Files described by @cfts are removed from
2924  * all existing cgroups to which @ss is attached and all future cgroups
2925  * won't have them either.  This function can be called anytime whether @ss
2926  * is attached or not.
2927  *
2928  * Returns 0 on successful unregistration, -ENOENT if @cfts is not
2929  * registered with @ss.
2930  */
2931 int cgroup_rm_cftypes(struct cgroup_subsys *ss, struct cftype *cfts)
2932 {
2933         struct cftype_set *set;
2934 
2935         cgroup_cfts_prepare();
2936 
2937         list_for_each_entry(set, &ss->cftsets, node) {
2938                 if (set->cfts == cfts) {
2939                         list_del(&set->node);
2940                         kfree(set);
2941                         cgroup_cfts_commit(ss, cfts, false);
2942                         return 0;
2943                 }
2944         }
2945 
2946         cgroup_cfts_commit(ss, NULL, false);
2947         return -ENOENT;
2948 }
2949 
2950 /**
2951  * cgroup_task_count - count the number of tasks in a cgroup.
2952  * @cgrp: the cgroup in question
2953  *
2954  * Return the number of tasks in the cgroup.
2955  */
2956 int cgroup_task_count(const struct cgroup *cgrp)
2957 {
2958         int count = 0;
2959         struct cgrp_cset_link *link;
2960 
2961         read_lock(&css_set_lock);
2962         list_for_each_entry(link, &cgrp->cset_links, cset_link)
2963                 count += atomic_read(&link->cset->refcount);
2964         read_unlock(&css_set_lock);
2965         return count;
2966 }
2967 
2968 /*
2969  * Advance a list_head iterator.  The iterator should be positioned at
2970  * the start of a css_set
2971  */
2972 static void cgroup_advance_iter(struct cgroup *cgrp, struct cgroup_iter *it)
2973 {
2974         struct list_head *l = it->cset_link;
2975         struct cgrp_cset_link *link;
2976         struct css_set *cset;
2977 
2978         /* Advance to the next non-empty css_set */
2979         do {
2980                 l = l->next;
2981                 if (l == &cgrp->cset_links) {
2982                         it->cset_link = NULL;
2983                         return;
2984                 }
2985                 link = list_entry(l, struct cgrp_cset_link, cset_link);
2986                 cset = link->cset;
2987         } while (list_empty(&cset->tasks));
2988         it->cset_link = l;
2989         it->task = cset->tasks.next;
2990 }
2991 
2992 /*
2993  * To reduce the fork() overhead for systems that are not actually
2994  * using their cgroups capability, we don't maintain the lists running
2995  * through each css_set to its tasks until we see the list actually
2996  * used - in other words after the first call to cgroup_iter_start().
2997  */
2998 static void cgroup_enable_task_cg_lists(void)
2999 {
3000         struct task_struct *p, *g;
3001         write_lock(&css_set_lock);
3002         use_task_css_set_links = 1;
3003         /*
3004          * We need tasklist_lock because RCU is not safe against
3005          * while_each_thread(). Besides, a forking task that has passed
3006          * cgroup_post_fork() without seeing use_task_css_set_links = 1
3007          * is not guaranteed to have its child immediately visible in the
3008          * tasklist if we walk through it with RCU.
3009          */
3010         read_lock(&tasklist_lock);
3011         do_each_thread(g, p) {
3012                 task_lock(p);
3013                 /*
3014                  * We should check if the process is exiting, otherwise
3015                  * it will race with cgroup_exit() in that the list
3016                  * entry won't be deleted though the process has exited.
3017                  */
3018                 if (!(p->flags & PF_EXITING) && list_empty(&p->cg_list))
3019                         list_add(&p->cg_list, &task_css_set(p)->tasks);
3020                 task_unlock(p);
3021         } while_each_thread(g, p);
3022         read_unlock(&tasklist_lock);
3023         write_unlock(&css_set_lock);
3024 }
3025 
3026 /**
3027  * cgroup_next_sibling - find the next sibling of a given cgroup
3028  * @pos: the current cgroup
3029  *
3030  * This function returns the next sibling of @pos and should be called
3031  * under RCU read lock.  The only requirement is that @pos is accessible.
3032  * The next sibling is guaranteed to be returned regardless of @pos's
3033  * state.
3034  */
3035 struct cgroup *cgroup_next_sibling(struct cgroup *pos)
3036 {
3037         struct cgroup *next;
3038 
3039         WARN_ON_ONCE(!rcu_read_lock_held());
3040 
3041         /*
3042          * @pos could already have been removed.  Once a cgroup is removed,
3043          * its ->sibling.next is no longer updated when its next sibling
3044          * changes.  As CGRP_DEAD assertion is serialized and happens
3045          * before the cgroup is taken off the ->sibling list, if we see it
3046          * unasserted, it's guaranteed that the next sibling hasn't
3047          * finished its grace period even if it's already removed, and thus
3048          * safe to dereference from this RCU critical section.  If
3049          * ->sibling.next is inaccessible, cgroup_is_dead() is guaranteed
3050          * to be visible as %true here.
3051          */
3052         if (likely(!cgroup_is_dead(pos))) {
3053                 next = list_entry_rcu(pos->sibling.next, struct cgroup, sibling);
3054                 if (&next->sibling != &pos->parent->children)
3055                         return next;
3056                 return NULL;
3057         }
3058 
3059         /*
3060          * Can't dereference the next pointer.  Each cgroup is given a
3061          * monotonically increasing unique serial number and always
3062          * appended to the sibling list, so the next one can be found by
3063          * walking the parent's children until we see a cgroup with higher
3064          * serial number than @pos's.
3065          *
3066          * While this path can be slow, it's taken only when either the
3067          * current cgroup is removed or iteration and removal race.
3068          */
3069         list_for_each_entry_rcu(next, &pos->parent->children, sibling)
3070                 if (next->serial_nr > pos->serial_nr)
3071                         return next;
3072         return NULL;
3073 }
3074 EXPORT_SYMBOL_GPL(cgroup_next_sibling);
3075 
3076 /**
3077  * cgroup_next_descendant_pre - find the next descendant for pre-order walk
3078  * @pos: the current position (%NULL to initiate traversal)
3079  * @cgroup: cgroup whose descendants to walk
3080  *
3081  * To be used by cgroup_for_each_descendant_pre().  Find the next
3082  * descendant to visit for pre-order traversal of @cgroup's descendants.
3083  *
3084  * While this function requires RCU read locking, it doesn't require the
3085  * whole traversal to be contained in a single RCU critical section.  This
3086  * function will return the correct next descendant as long as both @pos
3087  * and @cgroup are accessible and @pos is a descendant of @cgroup.
3088  */
3089 struct cgroup *cgroup_next_descendant_pre(struct cgroup *pos,
3090                                           struct cgroup *cgroup)
3091 {
3092         struct cgroup *next;
3093 
3094         WARN_ON_ONCE(!rcu_read_lock_held());
3095 
3096         /* if first iteration, pretend we just visited @cgroup */
3097         if (!pos)
3098                 pos = cgroup;
3099 
3100         /* visit the first child if exists */
3101         next = list_first_or_null_rcu(&pos->children, struct cgroup, sibling);
3102         if (next)
3103                 return next;
3104 
3105         /* no child, visit my or the closest ancestor's next sibling */
3106         while (pos != cgroup) {
3107                 next = cgroup_next_sibling(pos);
3108                 if (next)
3109                         return next;
3110                 pos = pos->parent;
3111         }
3112 
3113         return NULL;
3114 }
3115 EXPORT_SYMBOL_GPL(cgroup_next_descendant_pre);
3116 
3117 /**
3118  * cgroup_rightmost_descendant - return the rightmost descendant of a cgroup
3119  * @pos: cgroup of interest
3120  *
3121  * Return the rightmost descendant of @pos.  If there's no descendant,
3122  * @pos is returned.  This can be used during pre-order traversal to skip
3123  * subtree of @pos.
3124  *
3125  * While this function requires RCU read locking, it doesn't require the
3126  * whole traversal to be contained in a single RCU critical section.  This
3127  * function will return the correct rightmost descendant as long as @pos is
3128  * accessible.
3129  */
3130 struct cgroup *cgroup_rightmost_descendant(struct cgroup *pos)
3131 {
3132         struct cgroup *last, *tmp;
3133 
3134         WARN_ON_ONCE(!rcu_read_lock_held());
3135 
3136         do {
3137                 last = pos;
3138                 /* ->prev isn't RCU safe, walk ->next till the end */
3139                 pos = NULL;
3140                 list_for_each_entry_rcu(tmp, &last->children, sibling)
3141                         pos = tmp;
3142         } while (pos);
3143 
3144         return last;
3145 }
3146 EXPORT_SYMBOL_GPL(cgroup_rightmost_descendant);
3147 
3148 static struct cgroup *cgroup_leftmost_descendant(struct cgroup *pos)
3149 {
3150         struct cgroup *last;
3151 
3152         do {
3153                 last = pos;
3154                 pos = list_first_or_null_rcu(&pos->children, struct cgroup,
3155                                              sibling);
3156         } while (pos);
3157 
3158         return last;
3159 }
3160 
3161 /**
3162  * cgroup_next_descendant_post - find the next descendant for post-order walk
3163  * @pos: the current position (%NULL to initiate traversal)
3164  * @cgroup: cgroup whose descendants to walk
3165  *
3166  * To be used by cgroup_for_each_descendant_post().  Find the next
3167  * descendant to visit for post-order traversal of @cgroup's descendants.
3168  *
3169  * While this function requires RCU read locking, it doesn't require the
3170  * whole traversal to be contained in a single RCU critical section.  This
3171  * function will return the correct next descendant as long as both @pos
3172  * and @cgroup are accessible and @pos is a descendant of @cgroup.
3173  */
3174 struct cgroup *cgroup_next_descendant_post(struct cgroup *pos,
3175                                            struct cgroup *cgroup)
3176 {
3177         struct cgroup *next;
3178 
3179         WARN_ON_ONCE(!rcu_read_lock_held());
3180 
3181         /* if first iteration, visit the leftmost descendant */
3182         if (!pos) {
3183                 next = cgroup_leftmost_descendant(cgroup);
3184                 return next != cgroup ? next : NULL;
3185         }
3186 
3187         /* if there's an unvisited sibling, visit its leftmost descendant */
3188         next = cgroup_next_sibling(pos);
3189         if (next)
3190                 return cgroup_leftmost_descendant(next);
3191 
3192         /* no sibling left, visit parent */
3193         next = pos->parent;
3194         return next != cgroup ? next : NULL;
3195 }
3196 EXPORT_SYMBOL_GPL(cgroup_next_descendant_post);
3197 
3198 void cgroup_iter_start(struct cgroup *cgrp, struct cgroup_iter *it)
3199         __acquires(css_set_lock)
3200 {
3201         /*
3202          * The first time anyone tries to iterate across a cgroup,
3203          * we need to enable the list linking each css_set to its
3204          * tasks, and fix up all existing tasks.
3205          */
3206         if (!use_task_css_set_links)
3207                 cgroup_enable_task_cg_lists();
3208 
3209         read_lock(&css_set_lock);
3210         it->cset_link = &cgrp->cset_links;
3211         cgroup_advance_iter(cgrp, it);
3212 }
3213 
3214 struct task_struct *cgroup_iter_next(struct cgroup *cgrp,
3215                                         struct cgroup_iter *it)
3216 {
3217         struct task_struct *res;
3218         struct list_head *l = it->task;
3219         struct cgrp_cset_link *link;
3220 
3221         /* If the iterator cg is NULL, we have no tasks */
3222         if (!it->cset_link)
3223                 return NULL;
3224         res = list_entry(l, struct task_struct, cg_list);
3225         /* Advance iterator to find next entry */
3226         l = l->next;
3227         link = list_entry(it->cset_link, struct cgrp_cset_link, cset_link);
3228         if (l == &link->cset->tasks) {
3229                 /* We reached the end of this task list - move on to
3230                  * the next cg_cgroup_link */
3231                 cgroup_advance_iter(cgrp, it);
3232         } else {
3233                 it->task = l;
3234         }
3235         return res;
3236 }
3237 
3238 void cgroup_iter_end(struct cgroup *cgrp, struct cgroup_iter *it)
3239         __releases(css_set_lock)
3240 {
3241         read_unlock(&css_set_lock);
3242 }
3243 
3244 static inline int started_after_time(struct task_struct *t1,
3245                                      struct timespec *time,
3246                                      struct task_struct *t2)
3247 {
3248         int start_diff = timespec_compare(&t1->start_time, time);
3249         if (start_diff > 0) {
3250                 return 1;
3251         } else if (start_diff < 0) {
3252                 return 0;
3253         } else {
3254                 /*
3255                  * Arbitrarily, if two processes started at the same
3256                  * time, we'll say that the lower pointer value
3257                  * started first. Note that t2 may have exited by now
3258                  * so this may not be a valid pointer any longer, but
3259                  * that's fine - it still serves to distinguish
3260                  * between two tasks started (effectively) simultaneously.
3261                  */
3262                 return t1 > t2;
3263         }
3264 }
3265 
3266 /*
3267  * This function is a callback from heap_insert() and is used to order
3268  * the heap.
3269  * In this case we order the heap in descending task start time.
3270  */
3271 static inline int started_after(void *p1, void *p2)
3272 {
3273         struct task_struct *t1 = p1;
3274         struct task_struct *t2 = p2;
3275         return started_after_time(t1, &t2->start_time, t2);
3276 }
3277 
3278 /**
3279  * cgroup_scan_tasks - iterate though all the tasks in a cgroup
3280  * @scan: struct cgroup_scanner containing arguments for the scan
3281  *
3282  * Arguments include pointers to callback functions test_task() and
3283  * process_task().
3284  * Iterate through all the tasks in a cgroup, calling test_task() for each,
3285  * and if it returns true, call process_task() for it also.
3286  * The test_task pointer may be NULL, meaning always true (select all tasks).
3287  * Effectively duplicates cgroup_iter_{start,next,end}()
3288  * but does not lock css_set_lock for the call to process_task().
3289  * The struct cgroup_scanner may be embedded in any structure of the caller's
3290  * creation.
3291  * It is guaranteed that process_task() will act on every task that
3292  * is a member of the cgroup for the duration of this call. This
3293  * function may or may not call process_task() for tasks that exit
3294  * or move to a different cgroup during the call, or are forked or
3295  * move into the cgroup during the call.
3296  *
3297  * Note that test_task() may be called with locks held, and may in some
3298  * situations be called multiple times for the same task, so it should
3299  * be cheap.
3300  * If the heap pointer in the struct cgroup_scanner is non-NULL, a heap has been
3301  * pre-allocated and will be used for heap operations (and its "gt" member will
3302  * be overwritten), else a temporary heap will be used (allocation of which
3303  * may cause this function to fail).
3304  */
3305 int cgroup_scan_tasks(struct cgroup_scanner *scan)
3306 {
3307         int retval, i;
3308         struct cgroup_iter it;
3309         struct task_struct *p, *dropped;
3310         /* Never dereference latest_task, since it's not refcounted */
3311         struct task_struct *latest_task = NULL;
3312         struct ptr_heap tmp_heap;
3313         struct ptr_heap *heap;
3314         struct timespec latest_time = { 0, 0 };
3315 
3316         if (scan->heap) {
3317                 /* The caller supplied our heap and pre-allocated its memory */
3318                 heap = scan->heap;
3319                 heap->gt = &started_after;
3320         } else {
3321                 /* We need to allocate our own heap memory */
3322                 heap = &tmp_heap;
3323                 retval = heap_init(heap, PAGE_SIZE, GFP_KERNEL, &started_after);
3324                 if (retval)
3325                         /* cannot allocate the heap */
3326                         return retval;
3327         }
3328 
3329  again:
3330         /*
3331          * Scan tasks in the cgroup, using the scanner's "test_task" callback
3332          * to determine which are of interest, and using the scanner's
3333          * "process_task" callback to process any of them that need an update.
3334          * Since we don't want to hold any locks during the task updates,
3335          * gather tasks to be processed in a heap structure.
3336          * The heap is sorted by descending task start time.
3337          * If the statically-sized heap fills up, we overflow tasks that
3338          * started later, and in future iterations only consider tasks that
3339          * started after the latest task in the previous pass. This
3340          * guarantees forward progress and that we don't miss any tasks.
3341          */
3342         heap->size = 0;
3343         cgroup_iter_start(scan->cg, &it);
3344         while ((p = cgroup_iter_next(scan->cg, &it))) {
3345                 /*
3346                  * Only affect tasks that qualify per the caller's callback,
3347                  * if he provided one
3348                  */
3349                 if (scan->test_task && !scan->test_task(p, scan))
3350                         continue;
3351                 /*
3352                  * Only process tasks that started after the last task
3353                  * we processed
3354                  */
3355                 if (!started_after_time(p, &latest_time, latest_task))
3356                         continue;
3357                 dropped = heap_insert(heap, p);
3358                 if (dropped == NULL) {
3359                         /*
3360                          * The new task was inserted; the heap wasn't
3361                          * previously full
3362                          */
3363                         get_task_struct(p);
3364                 } else if (dropped != p) {
3365                         /*
3366                          * The new task was inserted, and pushed out a
3367                          * different task
3368                          */
3369                         get_task_struct(p);
3370                         put_task_struct(dropped);
3371                 }
3372                 /*
3373                  * Else the new task was newer than anything already in
3374                  * the heap and wasn't inserted
3375                  */
3376         }
3377         cgroup_iter_end(scan->cg, &it);
3378 
3379         if (heap->size) {
3380                 for (i = 0; i < heap->size; i++) {
3381                         struct task_struct *q = heap->ptrs[i];
3382                         if (i == 0) {
3383                                 latest_time = q->start_time;
3384                                 latest_task = q;
3385                         }
3386                         /* Process the task per the caller's callback */
3387                         scan->process_task(q, scan);
3388                         put_task_struct(q);
3389                 }
3390                 /*
3391                  * If we had to process any tasks at all, scan again
3392                  * in case some of them were in the middle of forking
3393                  * children that didn't get processed.
3394                  * Not the most efficient way to do it, but it avoids
3395                  * having to take callback_mutex in the fork path
3396                  */
3397                 goto again;
3398         }
3399         if (heap == &tmp_heap)
3400                 heap_free(&tmp_heap);
3401         return 0;
3402 }
3403 
3404 static void cgroup_transfer_one_task(struct task_struct *task,
3405                                      struct cgroup_scanner *scan)
3406 {
3407         struct cgroup *new_cgroup = scan->data;
3408 
3409         mutex_lock(&cgroup_mutex);
3410         cgroup_attach_task(new_cgroup, task, false);
3411         mutex_unlock(&cgroup_mutex);
3412 }
3413 
3414 /**
3415  * cgroup_trasnsfer_tasks - move tasks from one cgroup to another
3416  * @to: cgroup to which the tasks will be moved
3417  * @from: cgroup in which the tasks currently reside
3418  */
3419 int cgroup_transfer_tasks(struct cgroup *to, struct cgroup *from)
3420 {
3421         struct cgroup_scanner scan;
3422 
3423         scan.cg = from;
3424         scan.test_task = NULL; /* select all tasks in cgroup */
3425         scan.process_task = cgroup_transfer_one_task;
3426         scan.heap = NULL;
3427         scan.data = to;
3428 
3429         return cgroup_scan_tasks(&scan);
3430 }
3431 
3432 /*
3433  * Stuff for reading the 'tasks'/'procs' files.
3434  *
3435  * Reading this file can return large amounts of data if a cgroup has
3436  * *lots* of attached tasks. So it may need several calls to read(),
3437  * but we cannot guarantee that the information we produce is correct
3438  * unless we produce it entirely atomically.
3439  *
3440  */
3441 
3442 /* which pidlist file are we talking about? */
3443 enum cgroup_filetype {
3444         CGROUP_FILE_PROCS,
3445         CGROUP_FILE_TASKS,
3446 };
3447 
3448 /*
3449  * A pidlist is a list of pids that virtually represents the contents of one
3450  * of the cgroup files ("procs" or "tasks"). We keep a list of such pidlists,
3451  * a pair (one each for procs, tasks) for each pid namespace that's relevant
3452  * to the cgroup.
3453  */
3454 struct cgroup_pidlist {
3455         /*
3456          * used to find which pidlist is wanted. doesn't change as long as
3457          * this particular list stays in the list.
3458         */
3459         struct { enum cgroup_filetype type; struct pid_namespace *ns; } key;
3460         /* array of xids */
3461         pid_t *list;
3462         /* how many elements the above list has */
3463         int length;
3464         /* how many files are using the current array */
3465         int use_count;
3466         /* each of these stored in a list by its cgroup */
3467         struct list_head links;
3468         /* pointer to the cgroup we belong to, for list removal purposes */
3469         struct cgroup *owner;
3470         /* protects the other fields */
3471         struct rw_semaphore mutex;
3472 };
3473 
3474 /*
3475  * The following two functions "fix" the issue where there are more pids
3476  * than kmalloc will give memory for; in such cases, we use vmalloc/vfree.
3477  * TODO: replace with a kernel-wide solution to this problem
3478  */
3479 #define PIDLIST_TOO_LARGE(c) ((c) * sizeof(pid_t) > (PAGE_SIZE * 2))
3480 static void *pidlist_allocate(int count)
3481 {
3482         if (PIDLIST_TOO_LARGE(count))
3483                 return vmalloc(count * sizeof(pid_t));
3484         else
3485                 return kmalloc(count * sizeof(pid_t), GFP_KERNEL);
3486 }
3487 static void pidlist_free(void *p)
3488 {
3489         if (is_vmalloc_addr(p))
3490                 vfree(p);
3491         else
3492                 kfree(p);
3493 }
3494 
3495 /*
3496  * pidlist_uniq - given a kmalloc()ed list, strip out all duplicate entries
3497  * Returns the number of unique elements.
3498  */
3499 static int pidlist_uniq(pid_t *list, int length)
3500 {
3501         int src, dest = 1;
3502 
3503         /*
3504          * we presume the 0th element is unique, so i starts at 1. trivial
3505          * edge cases first; no work needs to be done for either
3506          */
3507         if (length == 0 || length == 1)
3508                 return length;
3509         /* src and dest walk down the list; dest counts unique elements */
3510         for (src = 1; src < length; src++) {
3511                 /* find next unique element */
3512                 while (list[src] == list[src-1]) {
3513                         src++;
3514                         if (src == length)
3515                                 goto after;
3516                 }
3517                 /* dest always points to where the next unique element goes */
3518                 list[dest] = list[src];
3519                 dest++;
3520         }
3521 after:
3522         return dest;
3523 }
3524 
3525 static int cmppid(const void *a, const void *b)
3526 {
3527         return *(pid_t *)a - *(pid_t *)b;
3528 }
3529 
3530 /*
3531  * find the appropriate pidlist for our purpose (given procs vs tasks)
3532  * returns with the lock on that pidlist already held, and takes care
3533  * of the use count, or returns NULL with no locks held if we're out of
3534  * memory.
3535  */
3536 static struct cgroup_pidlist *cgroup_pidlist_find(struct cgroup *cgrp,
3537                                                   enum cgroup_filetype type)
3538 {
3539         struct cgroup_pidlist *l;
3540         /* don't need task_nsproxy() if we're looking at ourself */
3541         struct pid_namespace *ns = task_active_pid_ns(current);
3542 
3543         /*
3544          * We can't drop the pidlist_mutex before taking the l->mutex in case
3545          * the last ref-holder is trying to remove l from the list at the same
3546          * time. Holding the pidlist_mutex precludes somebody taking whichever
3547          * list we find out from under us - compare release_pid_array().
3548          */
3549         mutex_lock(&cgrp->pidlist_mutex);
3550         list_for_each_entry(l, &cgrp->pidlists, links) {
3551                 if (l->key.type == type && l->key.ns == ns) {
3552                         /* make sure l doesn't vanish out from under us */
3553                         down_write(&l->mutex);
3554                         mutex_unlock(&cgrp->pidlist_mutex);
3555                         return l;
3556                 }
3557         }
3558         /* entry not found; create a new one */
3559         l = kzalloc(sizeof(struct cgroup_pidlist), GFP_KERNEL);
3560         if (!l) {
3561                 mutex_unlock(&cgrp->pidlist_mutex);
3562                 return l;
3563         }
3564         init_rwsem(&l->mutex);
3565         down_write(&l->mutex);
3566         l->key.type = type;
3567         l->key.ns = get_pid_ns(ns);
3568         l->owner = cgrp;
3569         list_add(&l->links, &cgrp->pidlists);
3570         mutex_unlock(&cgrp->pidlist_mutex);
3571         return l;
3572 }
3573 
3574 /*
3575  * Load a cgroup's pidarray with either procs' tgids or tasks' pids
3576  */
3577 static int pidlist_array_load(struct cgroup *cgrp, enum cgroup_filetype type,
3578                               struct cgroup_pidlist **lp)
3579 {
3580         pid_t *array;
3581         int length;
3582         int pid, n = 0; /* used for populating the array */
3583         struct cgroup_iter it;
3584         struct task_struct *tsk;
3585         struct cgroup_pidlist *l;
3586 
3587         /*
3588          * If cgroup gets more users after we read count, we won't have
3589          * enough space - tough.  This race is indistinguishable to the
3590          * caller from the case that the additional cgroup users didn't
3591          * show up until sometime later on.
3592          */
3593         length = cgroup_task_count(cgrp);
3594         array = pidlist_allocate(length);
3595         if (!array)
3596                 return -ENOMEM;
3597         /* now, populate the array */
3598         cgroup_iter_start(cgrp, &it);
3599         while ((tsk = cgroup_iter_next(cgrp, &it))) {
3600                 if (unlikely(n == length))
3601                         break;
3602                 /* get tgid or pid for procs or tasks file respectively */
3603                 if (type == CGROUP_FILE_PROCS)
3604                         pid = task_tgid_vnr(tsk);
3605                 else
3606                         pid = task_pid_vnr(tsk);
3607                 if (pid > 0) /* make sure to only use valid results */
3608                         array[n++] = pid;
3609         }
3610         cgroup_iter_end(cgrp, &it);
3611         length = n;
3612         /* now sort & (if procs) strip out duplicates */
3613         sort(array, length, sizeof(pid_t), cmppid, NULL);
3614         if (type == CGROUP_FILE_PROCS)
3615                 length = pidlist_uniq(array, length);
3616         l = cgroup_pidlist_find(cgrp, type);
3617         if (!l) {
3618                 pidlist_free(array);
3619                 return -ENOMEM;
3620         }
3621         /* store array, freeing old if necessary - lock already held */
3622         pidlist_free(l->list);
3623         l->list = array;
3624         l->length = length;
3625         l->use_count++;
3626         up_write(&l->mutex);
3627         *lp = l;
3628         return 0;
3629 }
3630 
3631 /**
3632  * cgroupstats_build - build and fill cgroupstats
3633  * @stats: cgroupstats to fill information into
3634  * @dentry: A dentry entry belonging to the cgroup for which stats have
3635  * been requested.
3636  *
3637  * Build and fill cgroupstats so that taskstats can export it to user
3638  * space.
3639  */
3640 int cgroupstats_build(struct cgroupstats *stats, struct dentry *dentry)
3641 {
3642         int ret = -EINVAL;
3643         struct cgroup *cgrp;
3644         struct cgroup_iter it;
3645         struct task_struct *tsk;
3646 
3647         /*
3648          * Validate dentry by checking the superblock operations,
3649          * and make sure it's a directory.
3650          */
3651         if (dentry->d_sb->s_op != &cgroup_ops ||
3652             !S_ISDIR(dentry->d_inode->i_mode))
3653                  goto err;
3654 
3655         ret = 0;
3656         cgrp = dentry->d_fsdata;
3657 
3658         cgroup_iter_start(cgrp, &it);
3659         while ((tsk = cgroup_iter_next(cgrp, &it))) {
3660                 switch (tsk->state) {
3661                 case TASK_RUNNING:
3662                         stats->nr_running++;
3663                         break;
3664                 case TASK_INTERRUPTIBLE:
3665                         stats->nr_sleeping++;
3666                         break;
3667                 case TASK_UNINTERRUPTIBLE:
3668                         stats->nr_uninterruptible++;
3669                         break;
3670                 case TASK_STOPPED:
3671                         stats->nr_stopped++;
3672                         break;
3673                 default:
3674                         if (delayacct_is_task_waiting_on_io(tsk))
3675                                 stats->nr_io_wait++;
3676                         break;
3677                 }
3678         }
3679         cgroup_iter_end(cgrp, &it);
3680 
3681 err:
3682         return ret;
3683 }
3684 
3685 
3686 /*
3687  * seq_file methods for the tasks/procs files. The seq_file position is the
3688  * next pid to display; the seq_file iterator is a pointer to the pid
3689  * in the cgroup->l->list array.
3690  */
3691 
3692 static void *cgroup_pidlist_start(struct seq_file *s, loff_t *pos)
3693 {
3694         /*
3695          * Initially we receive a position value that corresponds to
3696          * one more than the last pid shown (or 0 on the first call or
3697          * after a seek to the start). Use a binary-search to find the
3698          * next pid to display, if any
3699          */
3700         struct cgroup_pidlist *l = s->private;
3701         int index = 0, pid = *pos;
3702         int *iter;
3703 
3704         down_read(&l->mutex);
3705         if (pid) {
3706                 int end = l->length;
3707 
3708                 while (index < end) {
3709                         int mid = (index + end) / 2;
3710                         if (l->list[mid] == pid) {
3711                                 index = mid;
3712                                 break;
3713                         } else if (l->list[mid] <= pid)
3714                                 index = mid + 1;
3715                         else
3716                                 end = mid;
3717                 }
3718         }
3719         /* If we're off the end of the array, we're done */
3720         if (index >= l->length)
3721                 return NULL;
3722         /* Update the abstract position to be the actual pid that we found */
3723         iter = l->list + index;
3724         *pos = *iter;
3725         return iter;
3726 }
3727 
3728 static void cgroup_pidlist_stop(struct seq_file *s, void *v)
3729 {
3730         struct cgroup_pidlist *l = s->private;
3731         up_read(&l->mutex);
3732 }
3733 
3734 static void *cgroup_pidlist_next(struct seq_file *s, void *v, loff_t *pos)
3735 {
3736         struct cgroup_pidlist *l = s->private;
3737         pid_t *p = v;
3738         pid_t *end = l->list + l->length;
3739         /*
3740          * Advance to the next pid in the array. If this goes off the
3741          * end, we're done
3742          */
3743         p++;
3744         if (p >= end) {
3745                 return NULL;
3746         } else {
3747                 *pos = *p;
3748                 return p;
3749         }
3750 }
3751 
3752 static int cgroup_pidlist_show(struct seq_file *s, void *v)
3753 {
3754         return seq_printf(s, "%d\n", *(int *)v);
3755 }
3756 
3757 /*
3758  * seq_operations functions for iterating on pidlists through seq_file -
3759  * independent of whether it's tasks or procs
3760  */
3761 static const struct seq_operations cgroup_pidlist_seq_operations = {
3762         .start = cgroup_pidlist_start,
3763         .stop = cgroup_pidlist_stop,
3764         .next = cgroup_pidlist_next,
3765         .show = cgroup_pidlist_show,
3766 };
3767 
3768 static void cgroup_release_pid_array(struct cgroup_pidlist *l)
3769 {
3770         /*
3771          * the case where we're the last user of this particular pidlist will
3772          * have us remove it from the cgroup's list, which entails taking the
3773          * mutex. since in pidlist_find the pidlist->lock depends on cgroup->
3774          * pidlist_mutex, we have to take pidlist_mutex first.
3775          */
3776         mutex_lock(&l->owner->pidlist_mutex);
3777         down_write(&l->mutex);
3778         BUG_ON(!l->use_count);
3779         if (!--l->use_count) {
3780                 /* we're the last user if refcount is 0; remove and free */
3781                 list_del(&l->links);
3782                 mutex_unlock(&l->owner->pidlist_mutex);
3783                 pidlist_free(l->list);
3784                 put_pid_ns(l->key.ns);
3785                 up_write(&l->mutex);
3786                 kfree(l);
3787                 return;
3788         }
3789         mutex_unlock(&l->owner->pidlist_mutex);
3790         up_write(&l->mutex);
3791 }
3792 
3793 static int cgroup_pidlist_release(struct inode *inode, struct file *file)
3794 {
3795         struct cgroup_pidlist *l;
3796         if (!(file->f_mode & FMODE_READ))
3797                 return 0;
3798         /*
3799          * the seq_file will only be initialized if the file was opened for
3800          * reading; hence we check if it's not null only in that case.
3801          */
3802         l = ((struct seq_file *)file->private_data)->private;
3803         cgroup_release_pid_array(l);
3804         return seq_release(inode, file);
3805 }
3806 
3807 static const struct file_operations cgroup_pidlist_operations = {
3808         .read = seq_read,
3809         .llseek = seq_lseek,
3810         .write = cgroup_file_write,
3811         .release = cgroup_pidlist_release,
3812 };
3813 
3814 /*
3815  * The following functions handle opens on a file that displays a pidlist
3816  * (tasks or procs). Prepare an array of the process/thread IDs of whoever's
3817  * in the cgroup.
3818  */
3819 /* helper function for the two below it */
3820 static int cgroup_pidlist_open(struct file *file, enum cgroup_filetype type)
3821 {
3822         struct cgroup *cgrp = __d_cgrp(file->f_dentry->d_parent);
3823         struct cgroup_pidlist *l;
3824         int retval;
3825 
3826         /* Nothing to do for write-only files */
3827         if (!(file->f_mode & FMODE_READ))
3828                 return 0;
3829 
3830         /* have the array populated */
3831         retval = pidlist_array_load(cgrp, type, &l);
3832         if (retval)
3833                 return retval;
3834         /* configure file information */
3835         file->f_op = &cgroup_pidlist_operations;
3836 
3837         retval = seq_open(file, &cgroup_pidlist_seq_operations);
3838         if (retval) {
3839                 cgroup_release_pid_array(l);
3840                 return retval;
3841         }
3842         ((struct seq_file *)file->private_data)->private = l;
3843         return 0;
3844 }
3845 static int cgroup_tasks_open(struct inode *unused, struct file *file)
3846 {
3847         return cgroup_pidlist_open(file, CGROUP_FILE_TASKS);
3848 }
3849 static int cgroup_procs_open(struct inode *unused, struct file *file)
3850 {
3851         return cgroup_pidlist_open(file, CGROUP_FILE_PROCS);
3852 }
3853 
3854 static u64 cgroup_read_notify_on_release(struct cgroup *cgrp,
3855                                             struct cftype *cft)
3856 {
3857         return notify_on_release(cgrp);
3858 }
3859 
3860 static int cgroup_write_notify_on_release(struct cgroup *cgrp,
3861                                           struct cftype *cft,
3862                                           u64 val)
3863 {
3864         clear_bit(CGRP_RELEASABLE, &cgrp->flags);
3865         if (val)
3866                 set_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
3867         else
3868                 clear_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
3869         return 0;
3870 }
3871 
3872 /*
3873  * When dput() is called asynchronously, if umount has been done and
3874  * then deactivate_super() in cgroup_free_fn() kills the superblock,
3875  * there's a small window that vfs will see the root dentry with non-zero
3876  * refcnt and trigger BUG().
3877  *
3878  * That's why we hold a reference before dput() and drop it right after.
3879  */
3880 static void cgroup_dput(struct cgroup *cgrp)
3881 {
3882         struct super_block *sb = cgrp->root->sb;
3883 
3884         atomic_inc(&sb->s_active);
3885         dput(cgrp->dentry);
3886         deactivate_super(sb);
3887 }
3888 
3889 /*
3890  * Unregister event and free resources.
3891  *
3892  * Gets called from workqueue.
3893  */
3894 static void cgroup_event_remove(struct work_struct *work)
3895 {
3896         struct cgroup_event *event = container_of(work, struct cgroup_event,
3897                         remove);
3898         struct cgroup *cgrp = event->cgrp;
3899 
3900         remove_wait_queue(event->wqh, &event->wait);
3901 
3902         event->cft->unregister_event(cgrp, event->cft, event->eventfd);
3903 
3904         /* Notify userspace the event is going away. */
3905         eventfd_signal(event->eventfd, 1);
3906 
3907         eventfd_ctx_put(event->eventfd);
3908         kfree(event);
3909         cgroup_dput(cgrp);
3910 }
3911 
3912 /*
3913  * Gets called on POLLHUP on eventfd when user closes it.
3914  *
3915  * Called with wqh->lock held and interrupts disabled.
3916  */
3917 static int cgroup_event_wake(wait_queue_t *wait, unsigned mode,
3918                 int sync, void *key)
3919 {
3920         struct cgroup_event *event = container_of(wait,
3921                         struct cgroup_event, wait);
3922         struct cgroup *cgrp = event->cgrp;
3923         unsigned long flags = (unsigned long)key;
3924 
3925         if (flags & POLLHUP) {
3926                 /*
3927                  * If the event has been detached at cgroup removal, we
3928                  * can simply return knowing the other side will cleanup
3929                  * for us.
3930                  *
3931                  * We can't race against event freeing since the other
3932                  * side will require wqh->lock via remove_wait_queue(),
3933                  * which we hold.
3934                  */
3935                 spin_lock(&cgrp->event_list_lock);
3936                 if (!list_empty(&event->list)) {
3937                         list_del_init(&event->list);
3938                         /*
3939                          * We are in atomic context, but cgroup_event_remove()
3940                          * may sleep, so we have to call it in workqueue.
3941                          */
3942                         schedule_work(&event->remove);
3943                 }
3944                 spin_unlock(&cgrp->event_list_lock);
3945         }
3946 
3947         return 0;
3948 }
3949 
3950 static void cgroup_event_ptable_queue_proc(struct file *file,
3951                 wait_queue_head_t *wqh, poll_table *pt)
3952 {
3953         struct cgroup_event *event = container_of(pt,
3954                         struct cgroup_event, pt);
3955 
3956         event->wqh = wqh;
3957         add_wait_queue(wqh, &event->wait);
3958 }
3959 
3960 /*
3961  * Parse input and register new cgroup event handler.
3962  *
3963  * Input must be in format '<event_fd> <control_fd> <args>'.
3964  * Interpretation of args is defined by control file implementation.
3965  */
3966 static int cgroup_write_event_control(struct cgroup *cgrp, struct cftype *cft,
3967                                       const char *buffer)
3968 {
3969         struct cgroup_event *event = NULL;
3970         struct cgroup *cgrp_cfile;
3971         unsigned int efd, cfd;
3972         struct file *efile = NULL;
3973         struct file *cfile = NULL;
3974         char *endp;
3975         int ret;
3976 
3977         efd = simple_strtoul(buffer, &endp, 10);
3978         if (*endp != ' ')
3979                 return -EINVAL;
3980         buffer = endp + 1;
3981 
3982         cfd = simple_strtoul(buffer, &endp, 10);
3983         if ((*endp != ' ') && (*endp != '\0'))
3984                 return -EINVAL;
3985         buffer = endp + 1;
3986 
3987         event = kzalloc(sizeof(*event), GFP_KERNEL);
3988         if (!event)
3989                 return -ENOMEM;
3990         event->cgrp = cgrp;
3991         INIT_LIST_HEAD(&event->list);
3992         init_poll_funcptr(&event->pt, cgroup_event_ptable_queue_proc);
3993         init_waitqueue_func_entry(&event->wait, cgroup_event_wake);
3994         INIT_WORK(&event->remove, cgroup_event_remove);
3995 
3996         efile = eventfd_fget(efd);
3997         if (IS_ERR(efile)) {
3998                 ret = PTR_ERR(efile);
3999                 goto fail;
4000         }
4001 
4002         event->eventfd = eventfd_ctx_fileget(efile);
4003         if (IS_ERR(event->eventfd)) {
4004                 ret = PTR_ERR(event->eventfd);
4005                 goto fail;
4006         }
4007 
4008         cfile = fget(cfd);
4009         if (!cfile) {
4010                 ret = -EBADF;
4011                 goto fail;
4012         }
4013 
4014         /* the process need read permission on control file */
4015         /* AV: shouldn't we check that it's been opened for read instead? */
4016         ret = inode_permission(file_inode(cfile), MAY_READ);
4017         if (ret < 0)
4018                 goto fail;
4019 
4020         event->cft = __file_cft(cfile);
4021         if (IS_ERR(event->cft)) {
4022                 ret = PTR_ERR(event->cft);
4023                 goto fail;
4024         }
4025 
4026         /*
4027          * The file to be monitored must be in the same cgroup as
4028          * cgroup.event_control is.
4029          */
4030         cgrp_cfile = __d_cgrp(cfile->f_dentry->d_parent);
4031         if (cgrp_cfile != cgrp) {
4032                 ret = -EINVAL;
4033                 goto fail;
4034         }
4035 
4036         if (!event->cft->register_event || !event->cft->unregister_event) {
4037                 ret = -EINVAL;
4038                 goto fail;
4039         }
4040 
4041         ret = event->cft->register_event(cgrp, event->cft,
4042                         event->eventfd, buffer);
4043         if (ret)
4044                 goto fail;
4045 
4046         efile->f_op->poll(efile, &event->pt);
4047 
4048         /*
4049          * Events should be removed after rmdir of cgroup directory, but before
4050          * destroying subsystem state objects. Let's take reference to cgroup
4051          * directory dentry to do that.
4052          */
4053         dget(cgrp->dentry);
4054 
4055         spin_lock(&cgrp->event_list_lock);
4056         list_add(&event->list, &cgrp->event_list);
4057         spin_unlock(&cgrp->event_list_lock);
4058 
4059         fput(cfile);
4060         fput(efile);
4061 
4062         return 0;
4063 
4064 fail:
4065         if (cfile)
4066                 fput(cfile);
4067 
4068         if (event && event->eventfd && !IS_ERR(event->eventfd))
4069                 eventfd_ctx_put(event->eventfd);
4070 
4071         if (!IS_ERR_OR_NULL(efile))
4072                 fput(efile);
4073 
4074         kfree(event);
4075 
4076         return ret;
4077 }
4078 
4079 static u64 cgroup_clone_children_read(struct cgroup *cgrp,
4080                                     struct cftype *cft)
4081 {
4082         return test_bit(CGRP_CPUSET_CLONE_CHILDREN, &cgrp->flags);
4083 }
4084 
4085 static int cgroup_clone_children_write(struct cgroup *cgrp,
4086                                      struct cftype *cft,
4087                                      u64 val)
4088 {
4089         if (val)
4090                 set_bit(CGRP_CPUSET_CLONE_CHILDREN, &cgrp->flags);
4091         else
4092                 clear_bit(CGRP_CPUSET_CLONE_CHILDREN, &cgrp->flags);
4093         return 0;
4094 }
4095 
4096 static struct cftype cgroup_base_files[] = {
4097         {
4098                 .name = "cgroup.procs",
4099                 .open = cgroup_procs_open,
4100                 .write_u64 = cgroup_procs_write,
4101                 .release = cgroup_pidlist_release,
4102                 .mode = S_IRUGO | S_IWUSR,
4103         },
4104         {
4105                 .name = "cgroup.event_control",
4106                 .write_string = cgroup_write_event_control,
4107                 .mode = S_IWUGO,
4108         },
4109         {
4110                 .name = "cgroup.clone_children",
4111                 .flags = CFTYPE_INSANE,
4112                 .read_u64 = cgroup_clone_children_read,
4113                 .write_u64 = cgroup_clone_children_write,
4114         },
4115         {
4116                 .name = "cgroup.sane_behavior",
4117                 .flags = CFTYPE_ONLY_ON_ROOT,
4118                 .read_seq_string = cgroup_sane_behavior_show,
4119         },
4120 
4121         /*
4122          * Historical crazy stuff.  These don't have "cgroup."  prefix and
4123          * don't exist if sane_behavior.  If you're depending on these, be
4124          * prepared to be burned.
4125          */
4126         {
4127                 .name = "tasks",
4128                 .flags = CFTYPE_INSANE,         /* use "procs" instead */
4129                 .open = cgroup_tasks_open,
4130                 .write_u64 = cgroup_tasks_write,
4131                 .release = cgroup_pidlist_release,
4132                 .mode = S_IRUGO | S_IWUSR,
4133         },
4134         {
4135                 .name = "notify_on_release",
4136                 .flags = CFTYPE_INSANE,
4137                 .read_u64 = cgroup_read_notify_on_release,
4138                 .write_u64 = cgroup_write_notify_on_release,
4139         },
4140         {
4141                 .name = "release_agent",
4142                 .flags = CFTYPE_INSANE | CFTYPE_ONLY_ON_ROOT,
4143                 .read_seq_string = cgroup_release_agent_show,
4144                 .write_string = cgroup_release_agent_write,
4145                 .max_write_len = PATH_MAX,
4146         },
4147         { }     /* terminate */
4148 };
4149 
4150 /**
4151  * cgroup_populate_dir - selectively creation of files in a directory
4152  * @cgrp: target cgroup
4153  * @base_files: true if the base files should be added
4154  * @subsys_mask: mask of the subsystem ids whose files should be added
4155  */
4156 static int cgroup_populate_dir(struct cgroup *cgrp, bool base_files,
4157                                unsigned long subsys_mask)
4158 {
4159         int err;
4160         struct cgroup_subsys *ss;
4161 
4162         if (base_files) {
4163                 err = cgroup_addrm_files(cgrp, NULL, cgroup_base_files, true);
4164                 if (err < 0)
4165                         return err;
4166         }
4167 
4168         /* process cftsets of each subsystem */
4169         for_each_root_subsys(cgrp->root, ss) {
4170                 struct cftype_set *set;
4171                 if (!test_bit(ss->subsys_id, &subsys_mask))
4172                         continue;
4173 
4174                 list_for_each_entry(set, &ss->cftsets, node)
4175                         cgroup_addrm_files(cgrp, ss, set->cfts, true);
4176         }
4177 
4178         /* This cgroup is ready now */
4179         for_each_root_subsys(cgrp->root, ss) {
4180                 struct cgroup_subsys_state *css = cgrp->subsys[ss->subsys_id];
4181                 struct css_id *id = rcu_dereference_protected(css->id, true);
4182 
4183                 /*
4184                  * Update id->css pointer and make this css visible from
4185                  * CSS ID functions. This pointer will be dereferened
4186                  * from RCU-read-side without locks.
4187                  */
4188                 if (id)
4189                         rcu_assign_pointer(id->css, css);
4190         }
4191 
4192         return 0;
4193 }
4194 
4195 static void css_dput_fn(struct work_struct *work)
4196 {
4197         struct cgroup_subsys_state *css =
4198                 container_of(work, struct cgroup_subsys_state, dput_work);
4199 
4200         cgroup_dput(css->cgroup);
4201 }
4202 
4203 static void css_release(struct percpu_ref *ref)
4204 {
4205         struct cgroup_subsys_state *css =
4206                 container_of(ref, struct cgroup_subsys_state, refcnt);
4207 
4208         schedule_work(&css->dput_work);
4209 }
4210 
4211 static void init_cgroup_css(struct cgroup_subsys_state *css,
4212                                struct cgroup_subsys *ss,
4213                                struct cgroup *cgrp)
4214 {
4215         css->cgroup = cgrp;
4216         css->flags = 0;
4217         css->id = NULL;
4218         if (cgrp == cgroup_dummy_top)
4219                 css->flags |= CSS_ROOT;
4220         BUG_ON(cgrp->subsys[ss->subsys_id]);
4221         cgrp->subsys[ss->subsys_id] = css;
4222 
4223         /*
4224          * css holds an extra ref to @cgrp->dentry which is put on the last
4225          * css_put().  dput() requires process context, which css_put() may
4226          * be called without.  @css->dput_work will be used to invoke
4227          * dput() asynchronously from css_put().
4228          */
4229         INIT_WORK(&css->dput_work, css_dput_fn);
4230 }
4231 
4232 /* invoke ->post_create() on a new CSS and mark it online if successful */
4233 static int online_css(struct cgroup_subsys *ss, struct cgroup *cgrp)
4234 {
4235         int ret = 0;
4236 
4237         lockdep_assert_held(&cgroup_mutex);
4238 
4239         if (ss->css_online)
4240                 ret = ss->css_online(cgrp);
4241         if (!ret)
4242                 cgrp->subsys[ss->subsys_id]->flags |= CSS_ONLINE;
4243         return ret;
4244 }
4245 
4246 /* if the CSS is online, invoke ->pre_destory() on it and mark it offline */
4247 static void offline_css(struct cgroup_subsys *ss, struct cgroup *cgrp)
4248         __releases(&cgroup_mutex) __acquires(&cgroup_mutex)
4249 {
4250         struct cgroup_subsys_state *css = cgrp->subsys[ss->subsys_id];
4251 
4252         lockdep_assert_held(&cgroup_mutex);
4253 
4254         if (!(css->flags & CSS_ONLINE))
4255                 return;
4256 
4257         if (ss->css_offline)
4258                 ss->css_offline(cgrp);
4259 
4260         cgrp->subsys[ss->subsys_id]->flags &= ~CSS_ONLINE;
4261 }
4262 
4263 /*
4264  * cgroup_create - create a cgroup
4265  * @parent: cgroup that will be parent of the new cgroup
4266  * @dentry: dentry of the new cgroup
4267  * @mode: mode to set on new inode
4268  *
4269  * Must be called with the mutex on the parent inode held
4270  */
4271 static long cgroup_create(struct cgroup *parent, struct dentry *dentry,
4272                              umode_t mode)
4273 {
4274         struct cgroup *cgrp;
4275         struct cgroup_name *name;
4276         struct cgroupfs_root *root = parent->root;
4277         int err = 0;
4278         struct cgroup_subsys *ss;
4279         struct super_block *sb = root->sb;
4280 
4281         /* allocate the cgroup and its ID, 0 is reserved for the root */
4282         cgrp = kzalloc(sizeof(*cgrp), GFP_KERNEL);
4283         if (!cgrp)
4284                 return -ENOMEM;
4285 
4286         name = cgroup_alloc_name(dentry);
4287         if (!name)
4288                 goto err_free_cgrp;
4289         rcu_assign_pointer(cgrp->name, name);
4290 
4291         cgrp->id = ida_simple_get(&root->cgroup_ida, 1, 0, GFP_KERNEL);
4292         if (cgrp->id < 0)
4293                 goto err_free_name;
4294 
4295         /*
4296          * Only live parents can have children.  Note that the liveliness
4297          * check isn't strictly necessary because cgroup_mkdir() and
4298          * cgroup_rmdir() are fully synchronized by i_mutex; however, do it
4299          * anyway so that locking is contained inside cgroup proper and we
4300          * don't get nasty surprises if we ever grow another caller.
4301          */
4302         if (!cgroup_lock_live_group(parent)) {
4303                 err = -ENODEV;
4304                 goto err_free_id;
4305         }
4306 
4307         /* Grab a reference on the superblock so the hierarchy doesn't
4308          * get deleted on unmount if there are child cgroups.  This
4309          * can be done outside cgroup_mutex, since the sb can't
4310          * disappear while someone has an open control file on the
4311          * fs */
4312         atomic_inc(&sb->s_active);
4313 
4314         init_cgroup_housekeeping(cgrp);
4315 
4316         dentry->d_fsdata = cgrp;
4317         cgrp->dentry = dentry;
4318 
4319         cgrp->parent = parent;
4320         cgrp->root = parent->root;
4321 
4322         if (notify_on_release(parent))
4323                 set_bit(CGRP_NOTIFY_ON_RELEASE, &cgrp->flags);
4324 
4325         if (test_bit(CGRP_CPUSET_CLONE_CHILDREN, &parent->flags))
4326                 set_bit(CGRP_CPUSET_CLONE_CHILDREN, &cgrp->flags);
4327 
4328         for_each_root_subsys(root, ss) {
4329                 struct cgroup_subsys_state *css;
4330 
4331                 css = ss->css_alloc(cgrp);
4332                 if (IS_ERR(css)) {
4333                         err = PTR_ERR(css);
4334                         goto err_free_all;
4335                 }
4336 
4337                 err = percpu_ref_init(&css->refcnt, css_release);
4338                 if (err) {
4339                         ss->css_free(cgrp);
4340                         goto err_free_all;
4341                 }
4342 
4343                 init_cgroup_css(css, ss, cgrp);
4344 
4345                 if (ss->use_id) {
4346                         err = alloc_css_id(ss, parent, cgrp);
4347                         if (err)
4348                                 goto err_free_all;
4349                 }
4350         }
4351 
4352         /*
4353          * Create directory.  cgroup_create_file() returns with the new
4354          * directory locked on success so that it can be populated without
4355          * dropping cgroup_mutex.
4356          */
4357         err = cgroup_create_file(dentry, S_IFDIR | mode, sb);
4358         if (err < 0)
4359                 goto err_free_all;
4360         lockdep_assert_held(&dentry->d_inode->i_mutex);
4361 
4362         cgrp->serial_nr = cgroup_serial_nr_next++;
4363 
4364         /* allocation complete, commit to creation */
4365         list_add_tail_rcu(&cgrp->sibling, &cgrp->parent->children);
4366         root->number_of_cgroups++;
4367 
4368         /* each css holds a ref to the cgroup's dentry */
4369         for_each_root_subsys(root, ss)
4370                 dget(dentry);
4371 
4372         /* hold a ref to the parent's dentry */
4373         dget(parent->dentry);
4374 
4375         /* creation succeeded, notify subsystems */
4376         for_each_root_subsys(root, ss) {
4377                 err = online_css(ss, cgrp);
4378                 if (err)
4379                         goto err_destroy;
4380 
4381                 if (ss->broken_hierarchy && !ss->warned_broken_hierarchy &&
4382                     parent->parent) {
4383                         pr_warning("cgroup: %s (%d) created nested cgroup for controller \"%s\" which has incomplete hierarchy support. Nested cgroups may change behavior in the future.\n",
4384                                    current->comm, current->pid, ss->name);
4385                         if (!strcmp(ss->name, "memory"))
4386                                 pr_warning("cgroup: \"memory\" requires setting use_hierarchy to 1 on the root.\n");
4387                         ss->warned_broken_hierarchy = true;
4388                 }
4389         }
4390 
4391         err = cgroup_populate_dir(cgrp, true, root->subsys_mask);
4392         if (err)
4393                 goto err_destroy;
4394 
4395         mutex_unlock(&cgroup_mutex);
4396         mutex_unlock(&cgrp->dentry->d_inode->i_mutex);
4397 
4398         return 0;
4399 
4400 err_free_all:
4401         for_each_root_subsys(root, ss) {
4402                 struct cgroup_subsys_state *css = cgrp->subsys[ss->subsys_id];
4403 
4404                 if (css) {
4405                         percpu_ref_cancel_init(&css->refcnt);
4406                         ss->css_free(cgrp);
4407                 }
4408         }
4409         mutex_unlock(&cgroup_mutex);
4410         /* Release the reference count that we took on the superblock */
4411         deactivate_super(sb);
4412 err_free_id:
4413         ida_simple_remove(&root->cgroup_ida, cgrp->id);
4414 err_free_name:
4415         kfree(rcu_dereference_raw(cgrp->name));
4416 err_free_cgrp:
4417         kfree(cgrp);
4418         return err;
4419 
4420 err_destroy:
4421         cgroup_destroy_locked(cgrp);
4422         mutex_unlock(&cgroup_mutex);
4423         mutex_unlock(&dentry->d_inode->i_mutex);
4424         return err;
4425 }
4426 
4427 static int cgroup_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
4428 {
4429         struct cgroup *c_parent = dentry->d_parent->d_fsdata;
4430 
4431         /* the vfs holds inode->i_mutex already */
4432         return cgroup_create(c_parent, dentry, mode | S_IFDIR);
4433 }
4434 
4435 static void cgroup_css_killed(struct cgroup *cgrp)
4436 {
4437         if (!atomic_dec_and_test(&cgrp->css_kill_cnt))
4438                 return;
4439 
4440         /* percpu ref's of all css's are killed, kick off the next step */
4441         INIT_WORK(&cgrp->destroy_work, cgroup_offline_fn);
4442         schedule_work(&cgrp->destroy_work);
4443 }
4444 
4445 static void css_ref_killed_fn(struct percpu_ref *ref)
4446 {
4447         struct cgroup_subsys_state *css =
4448                 container_of(ref, struct cgroup_subsys_state, refcnt);
4449 
4450         cgroup_css_killed(css->cgroup);
4451 }
4452 
4453 /**
4454  * cgroup_destroy_locked - the first stage of cgroup destruction
4455  * @cgrp: cgroup to be destroyed
4456  *
4457  * css's make use of percpu refcnts whose killing latency shouldn't be
4458  * exposed to userland and are RCU protected.  Also, cgroup core needs to
4459  * guarantee that css_tryget() won't succeed by the time ->css_offline() is
4460  * invoked.  To satisfy all the requirements, destruction is implemented in
4461  * the following two steps.
4462  *
4463  * s1. Verify @cgrp can be destroyed and mark it dying.  Remove all
4464  *     userland visible parts and start killing the percpu refcnts of
4465  *     css's.  Set up so that the next stage will be kicked off once all
4466  *     the percpu refcnts are confirmed to be killed.
4467  *
4468  * s2. Invoke ->css_offline(), mark the cgroup dead and proceed with the
4469  *     rest of destruction.  Once all cgroup references are gone, the
4470  *     cgroup is RCU-freed.
4471  *
4472  * This function implements s1.  After this step, @cgrp is gone as far as
4473  * the userland is concerned and a new cgroup with the same name may be
4474  * created.  As cgroup doesn't care about the names internally, this
4475  * doesn't cause any problem.
4476  */
4477 static int cgroup_destroy_locked(struct cgroup *cgrp)
4478         __releases(&cgroup_mutex) __acquires(&cgroup_mutex)
4479 {
4480         struct dentry *d = cgrp->dentry;
4481         struct cgroup_event *event, *tmp;
4482         struct cgroup_subsys *ss;
4483         struct cgroup *child;
4484         bool empty;
4485 
4486         lockdep_assert_held(&d->d_inode->i_mutex);
4487         lockdep_assert_held(&cgroup_mutex);
4488 
4489         /*
4490          * css_set_lock synchronizes access to ->cset_links and prevents
4491          * @cgrp from being removed while __put_css_set() is in progress.
4492          */
4493         read_lock(&css_set_lock);
4494         empty = list_empty(&cgrp->cset_links);
4495         read_unlock(&css_set_lock);
4496         if (!empty)
4497                 return -EBUSY;
4498 
4499         /*
4500          * Make sure there's no live children.  We can't test ->children
4501          * emptiness as dead children linger on it while being destroyed;
4502          * otherwise, "rmdir parent/child parent" may fail with -EBUSY.
4503          */
4504         empty = true;
4505         rcu_read_lock();
4506         list_for_each_entry_rcu(child, &cgrp->children, sibling) {
4507                 empty = cgroup_is_dead(child);
4508                 if (!empty)
4509                         break;
4510         }
4511         rcu_read_unlock();
4512         if (!empty)
4513                 return -EBUSY;
4514 
4515         /*
4516          * Block new css_tryget() by killing css refcnts.  cgroup core
4517          * guarantees that, by the time ->css_offline() is invoked, no new
4518          * css reference will be given out via css_tryget().  We can't
4519          * simply call percpu_ref_kill() and proceed to offlining css's
4520          * because percpu_ref_kill() doesn't guarantee that the ref is seen
4521          * as killed on all CPUs on return.
4522          *
4523          * Use percpu_ref_kill_and_confirm() to get notifications as each
4524          * css is confirmed to be seen as killed on all CPUs.  The
4525          * notification callback keeps track of the number of css's to be
4526          * killed and schedules cgroup_offline_fn() to perform the rest of
4527          * destruction once the percpu refs of all css's are confirmed to
4528          * be killed.
4529          */
4530         atomic_set(&cgrp->css_kill_cnt, 1);
4531         for_each_root_subsys(cgrp->root, ss) {
4532                 struct cgroup_subsys_state *css = cgrp->subsys[ss->subsys_id];
4533 
4534                 /*
4535                  * Killing would put the base ref, but we need to keep it
4536                  * alive until after ->css_offline.
4537                  */
4538                 percpu_ref_get(&css->refcnt);
4539 
4540                 atomic_inc(&cgrp->css_kill_cnt);
4541                 percpu_ref_kill_and_confirm(&css->refcnt, css_ref_killed_fn);
4542         }
4543         cgroup_css_killed(cgrp);
4544 
4545         /*
4546          * Mark @cgrp dead.  This prevents further task migration and child
4547          * creation by disabling cgroup_lock_live_group().  Note that
4548          * CGRP_DEAD assertion is depended upon by cgroup_next_sibling() to
4549          * resume iteration after dropping RCU read lock.  See
4550          * cgroup_next_sibling() for details.
4551          */
4552         set_bit(CGRP_DEAD, &cgrp->flags);
4553 
4554         /* CGRP_DEAD is set, remove from ->release_list for the last time */
4555         raw_spin_lock(&release_list_lock);
4556         if (!list_empty(&cgrp->release_list))
4557                 list_del_init(&cgrp->release_list);
4558         raw_spin_unlock(&release_list_lock);
4559 
4560         /*
4561          * Remove @cgrp directory.  The removal puts the base ref but we
4562          * aren't quite done with @cgrp yet, so hold onto it.
4563          */
4564         dget(d);
4565         cgroup_d_remove_dir(d);
4566 
4567         /*
4568          * Unregister events and notify userspace.
4569          * Notify userspace about cgroup removing only after rmdir of cgroup
4570          * directory to avoid race between userspace and kernelspace.
4571          */
4572         spin_lock(&cgrp->event_list_lock);
4573         list_for_each_entry_safe(event, tmp, &cgrp->event_list, list) {
4574                 list_del_init(&event->list);
4575                 schedule_work(&event->remove);
4576         }
4577         spin_unlock(&cgrp->event_list_lock);
4578 
4579         return 0;
4580 };
4581 
4582 /**
4583  * cgroup_offline_fn - the second step of cgroup destruction
4584  * @work: cgroup->destroy_free_work
4585  *
4586  * This function is invoked from a work item for a cgroup which is being
4587  * destroyed after the percpu refcnts of all css's are guaranteed to be
4588  * seen as killed on all CPUs, and performs the rest of destruction.  This
4589  * is the second step of destruction described in the comment above
4590  * cgroup_destroy_locked().
4591  */
4592 static void cgroup_offline_fn(struct work_struct *work)
4593 {
4594         struct cgroup *cgrp = container_of(work, struct cgroup, destroy_work);
4595         struct cgroup *parent = cgrp->parent;
4596         struct dentry *d = cgrp->dentry;
4597         struct cgroup_subsys *ss;
4598 
4599         mutex_lock(&cgroup_mutex);
4600 
4601         /*
4602          * css_tryget() is guaranteed to fail now.  Tell subsystems to
4603          * initate destruction.
4604          */
4605         for_each_root_subsys(cgrp->root, ss)
4606                 offline_css(ss, cgrp);
4607 
4608         /*
4609          * Put the css refs from cgroup_destroy_locked().  Each css holds
4610          * an extra reference to the cgroup's dentry and cgroup removal
4611          * proceeds regardless of css refs.  On the last put of each css,
4612          * whenever that may be, the extra dentry ref is put so that dentry
4613          * destruction happens only after all css's are released.
4614          */
4615         for_each_root_subsys(cgrp->root, ss)
4616                 css_put(cgrp->subsys[ss->subsys_id]);
4617 
4618         /* delete this cgroup from parent->children */
4619         list_del_rcu(&cgrp->sibling);
4620 
4621         dput(d);
4622 
4623         set_bit(CGRP_RELEASABLE, &parent->flags);
4624         check_for_release(parent);
4625 
4626         mutex_unlock(&cgroup_mutex);
4627 }
4628 
4629 static int cgroup_rmdir(struct inode *unused_dir, struct dentry *dentry)
4630 {
4631         int ret;
4632 
4633         mutex_lock(&cgroup_mutex);
4634         ret = cgroup_destroy_locked(dentry->d_fsdata);
4635         mutex_unlock(&cgroup_mutex);
4636 
4637         return ret;
4638 }
4639 
4640 static void __init_or_module cgroup_init_cftsets(struct cgroup_subsys *ss)
4641 {
4642         INIT_LIST_HEAD(&ss->cftsets);
4643 
4644         /*
4645          * base_cftset is embedded in subsys itself, no need to worry about
4646          * deregistration.
4647          */
4648         if (ss->base_cftypes) {
4649                 ss->base_cftset.cfts = ss->base_cftypes;
4650                 list_add_tail(&ss->base_cftset.node, &ss->cftsets);
4651         }
4652 }
4653 
4654 static void __init cgroup_init_subsys(struct cgroup_subsys *ss)
4655 {
4656         struct cgroup_subsys_state *css;
4657         printk(KERN_INFO "Hello World From Kernel (CS350F: David Ma, Mukund Rathi, Mark Sandan)");
4658         printk(KERN_INFO "Initializing cgroup subsys %s\n", ss->name);
4659 
4660         mutex_lock(&cgroup_mutex);
4661 
4662         /* init base cftset */
4663         cgroup_init_cftsets(ss);
4664 
4665         /* Create the top cgroup state for this subsystem */
4666         list_add(&ss->sibling, &cgroup_dummy_root.subsys_list);
4667         ss->root = &cgroup_dummy_root;
4668         css = ss->css_alloc(cgroup_dummy_top);
4669         /* We don't handle early failures gracefully */
4670         BUG_ON(IS_ERR(css));
4671         init_cgroup_css(css, ss, cgroup_dummy_top);
4672 
4673         /* Update the init_css_set to contain a subsys
4674          * pointer to this state - since the subsystem is
4675          * newly registered, all tasks and hence the
4676          * init_css_set is in the subsystem's top cgroup. */
4677         init_css_set.subsys[ss->subsys_id] = css;
4678 
4679         need_forkexit_callback |= ss->fork || ss->exit;
4680 
4681         /* At system boot, before all subsystems have been
4682          * registered, no tasks have been forked, so we don't
4683          * need to invoke fork callbacks here. */
4684         BUG_ON(!list_empty(&init_task.tasks));
4685 
4686         BUG_ON(online_css(ss, cgroup_dummy_top));
4687 
4688         mutex_unlock(&cgroup_mutex);
4689 
4690         /* this function shouldn't be used with modular subsystems, since they
4691          * need to register a subsys_id, among other things */
4692         BUG_ON(ss->module);
4693 }
4694 
4695 /**
4696  * cgroup_load_subsys: load and register a modular subsystem at runtime
4697  * @ss: the subsystem to load
4698  *
4699  * This function should be called in a modular subsystem's initcall. If the
4700  * subsystem is built as a module, it will be assigned a new subsys_id and set
4701  * up for use. If the subsystem is built-in anyway, work is delegated to the
4702  * simpler cgroup_init_subsys.
4703  */
4704 int __init_or_module cgroup_load_subsys(struct cgroup_subsys *ss)
4705 {
4706         struct cgroup_subsys_state *css;
4707         int i, ret;
4708         struct hlist_node *tmp;
4709         struct css_set *cset;
4710         unsigned long key;
4711 
4712         /* check name and function validity */
4713         if (ss->name == NULL || strlen(ss->name) > MAX_CGROUP_TYPE_NAMELEN ||
4714             ss->css_alloc == NULL || ss->css_free == NULL)
4715                 return -EINVAL;
4716 
4717         /*
4718          * we don't support callbacks in modular subsystems. this check is
4719          * before the ss->module check for consistency; a subsystem that could
4720          * be a module should still have no callbacks even if the user isn't
4721          * compiling it as one.
4722          */
4723         if (ss->fork || ss->exit)
4724                 return -EINVAL;
4725 
4726         /*
4727          * an optionally modular subsystem is built-in: we want to do nothing,
4728          * since cgroup_init_subsys will have already taken care of it.
4729          */
4730         if (ss->module == NULL) {
4731                 /* a sanity check */
4732                 BUG_ON(cgroup_subsys[ss->subsys_id] != ss);
4733                 return 0;
4734         }
4735 
4736         /* init base cftset */
4737         cgroup_init_cftsets(ss);
4738 
4739         mutex_lock(&cgroup_mutex);
4740         cgroup_subsys[ss->subsys_id] = ss;
4741 
4742         /*
4743          * no ss->css_alloc seems to need anything important in the ss
4744          * struct, so this can happen first (i.e. before the dummy root
4745          * attachment).
4746          */
4747         css = ss->css_alloc(cgroup_dummy_top);
4748         if (IS_ERR(css)) {
4749                 /* failure case - need to deassign the cgroup_subsys[] slot. */
4750                 cgroup_subsys[ss->subsys_id] = NULL;
4751                 mutex_unlock(&cgroup_mutex);
4752                 return PTR_ERR(css);
4753         }
4754 
4755         list_add(&ss->sibling, &cgroup_dummy_root.subsys_list);
4756         ss->root = &cgroup_dummy_root;
4757 
4758         /* our new subsystem will be attached to the dummy hierarchy. */
4759         init_cgroup_css(css, ss, cgroup_dummy_top);
4760         /* init_idr must be after init_cgroup_css because it sets css->id. */
4761         if (ss->use_id) {
4762                 ret = cgroup_init_idr(ss, css);
4763                 if (ret)
4764                         goto err_unload;
4765         }
4766 
4767         /*
4768          * Now we need to entangle the css into the existing css_sets. unlike
4769          * in cgroup_init_subsys, there are now multiple css_sets, so each one
4770          * will need a new pointer to it; done by iterating the css_set_table.
4771          * furthermore, modifying the existing css_sets will corrupt the hash
4772          * table state, so each changed css_set will need its hash recomputed.
4773          * this is all done under the css_set_lock.
4774          */
4775         write_lock(&css_set_lock);
4776         hash_for_each_safe(css_set_table, i, tmp, cset, hlist) {
4777                 /* skip entries that we already rehashed */
4778                 if (cset->subsys[ss->subsys_id])
4779                         continue;
4780                 /* remove existing entry */
4781                 hash_del(&cset->hlist);
4782                 /* set new value */
4783                 cset->subsys[ss->subsys_id] = css;
4784                 /* recompute hash and restore entry */
4785                 key = css_set_hash(cset->subsys);
4786                 hash_add(css_set_table, &cset->hlist, key);
4787         }
4788         write_unlock(&css_set_lock);
4789 
4790         ret = online_css(ss, cgroup_dummy_top);
4791         if (ret)
4792                 goto err_unload;
4793 
4794         /* success! */
4795         mutex_unlock(&cgroup_mutex);
4796         return 0;
4797 
4798 err_unload:
4799         mutex_unlock(&cgroup_mutex);
4800         /* @ss can't be mounted here as try_module_get() would fail */
4801         cgroup_unload_subsys(ss);
4802         return ret;
4803 }
4804 EXPORT_SYMBOL_GPL(cgroup_load_subsys);
4805 
4806 /**
4807  * cgroup_unload_subsys: unload a modular subsystem
4808  * @ss: the subsystem to unload
4809  *
4810  * This function should be called in a modular subsystem's exitcall. When this
4811  * function is invoked, the refcount on the subsystem's module will be 0, so
4812  * the subsystem will not be attached to any hierarchy.
4813  */
4814 void cgroup_unload_subsys(struct cgroup_subsys *ss)
4815 {
4816         struct cgrp_cset_link *link;
4817 
4818         BUG_ON(ss->module == NULL);
4819 
4820         /*
4821          * we shouldn't be called if the subsystem is in use, and the use of
4822          * try_module_get in parse_cgroupfs_options should ensure that it
4823          * doesn't start being used while we're killing it off.
4824          */
4825         BUG_ON(ss->root != &cgroup_dummy_root);
4826 
4827         mutex_lock(&cgroup_mutex);
4828 
4829         offline_css(ss, cgroup_dummy_top);
4830 
4831         if (ss->use_id)
4832                 idr_destroy(&ss->idr);
4833 
4834         /* deassign the subsys_id */
4835         cgroup_subsys[ss->subsys_id] = NULL;
4836 
4837         /* remove subsystem from the dummy root's list of subsystems */
4838         list_del_init(&ss->sibling);
4839 
4840         /*
4841          * disentangle the css from all css_sets attached to the dummy
4842          * top. as in loading, we need to pay our respects to the hashtable
4843          * gods.
4844          */
4845         write_lock(&css_set_lock);
4846         list_for_each_entry(link, &cgroup_dummy_top->cset_links, cset_link) {
4847                 struct css_set *cset = link->cset;
4848                 unsigned long key;
4849 
4850                 hash_del(&cset->hlist);
4851                 cset->subsys[ss->subsys_id] = NULL;
4852                 key = css_set_hash(cset->subsys);
4853                 hash_add(css_set_table, &cset->hlist, key);
4854         }
4855         write_unlock(&css_set_lock);
4856 
4857         /*
4858          * remove subsystem's css from the cgroup_dummy_top and free it -
4859          * need to free before marking as null because ss->css_free needs
4860          * the cgrp->subsys pointer to find their state. note that this
4861          * also takes care of freeing the css_id.
4862          */
4863         ss->css_free(cgroup_dummy_top);
4864         cgroup_dummy_top->subsys[ss->subsys_id] = NULL;
4865 
4866         mutex_unlock(&cgroup_mutex);
4867 }
4868 EXPORT_SYMBOL_GPL(cgroup_unload_subsys);
4869 
4870 /**
4871  * cgroup_init_early - cgroup initialization at system boot
4872  *
4873  * Initialize cgroups at system boot, and initialize any
4874  * subsystems that request early init.
4875  */
4876 int __init cgroup_init_early(void)
4877 {
4878         struct cgroup_subsys *ss;
4879         int i;
4880 
4881         atomic_set(&init_css_set.refcount, 1);
4882         INIT_LIST_HEAD(&init_css_set.cgrp_links);
4883         INIT_LIST_HEAD(&init_css_set.tasks);
4884         INIT_HLIST_NODE(&init_css_set.hlist);
4885         css_set_count = 1;
4886         init_cgroup_root(&cgroup_dummy_root);
4887         cgroup_root_count = 1;
4888         RCU_INIT_POINTER(init_task.cgroups, &init_css_set);
4889 
4890         init_cgrp_cset_link.cset = &init_css_set;
4891         init_cgrp_cset_link.cgrp = cgroup_dummy_top;
4892         list_add(&init_cgrp_cset_link.cset_link, &cgroup_dummy_top->cset_links);
4893         list_add(&init_cgrp_cset_link.cgrp_link, &init_css_set.cgrp_links);
4894 
4895         /* at bootup time, we don't worry about modular subsystems */
4896         for_each_builtin_subsys(ss, i) {
4897                 BUG_ON(!ss->name);
4898                 BUG_ON(strlen(ss->name) > MAX_CGROUP_TYPE_NAMELEN);
4899                 BUG_ON(!ss->css_alloc);
4900                 BUG_ON(!ss->css_free);
4901                 if (ss->subsys_id != i) {
4902                         printk(KERN_ERR "cgroup: Subsys %s id == %d\n",
4903                                ss->name, ss->subsys_id);
4904                         BUG();
4905                 }
4906 
4907                 if (ss->early_init)
4908                         cgroup_init_subsys(ss);
4909         }
4910         return 0;
4911 }
4912 
4913 /**
4914  * cgroup_init - cgroup initialization
4915  *
4916  * Register cgroup filesystem and /proc file, and initialize
4917  * any subsystems that didn't request early init.
4918  */
4919 int __init cgroup_init(void)
4920 {
4921         struct cgroup_subsys *ss;
4922         unsigned long key;
4923         int i, err;
4924 
4925         err = bdi_init(&cgroup_backing_dev_info);
4926         if (err)
4927                 return err;
4928 
4929         for_each_builtin_subsys(ss, i) {
4930                 if (!ss->early_init)
4931                         cgroup_init_subsys(ss);
4932                 if (ss->use_id)
4933                         cgroup_init_idr(ss, init_css_set.subsys[ss->subsys_id]);
4934         }
4935 
4936         /* allocate id for the dummy hierarchy */
4937         mutex_lock(&cgroup_mutex);
4938         mutex_lock(&cgroup_root_mutex);
4939 
4940         /* Add init_css_set to the hash table */
4941         key = css_set_hash(init_css_set.subsys);
4942         hash_add(css_set_table, &init_css_set.hlist, key);
4943 
4944         BUG_ON(cgroup_init_root_id(&cgroup_dummy_root, 0, 1));
4945 
4946         mutex_unlock(&cgroup_root_mutex);
4947         mutex_unlock(&cgroup_mutex);
4948 
4949         cgroup_kobj = kobject_create_and_add("cgroup", fs_kobj);
4950         if (!cgroup_kobj) {
4951                 err = -ENOMEM;
4952                 goto out;
4953         }
4954 
4955         err = register_filesystem(&cgroup_fs_type);
4956         if (err < 0) {
4957                 kobject_put(cgroup_kobj);
4958                 goto out;
4959         }
4960 
4961         proc_create("cgroups", 0, NULL, &proc_cgroupstats_operations);
4962 
4963 out:
4964         if (err)
4965                 bdi_destroy(&cgroup_backing_dev_info);
4966 
4967         return err;
4968 }
4969 
4970 /*
4971  * proc_cgroup_show()
4972  *  - Print task's cgroup paths into seq_file, one line for each hierarchy
4973  *  - Used for /proc/<pid>/cgroup.
4974  *  - No need to task_lock(tsk) on this tsk->cgroup reference, as it
4975  *    doesn't really matter if tsk->cgroup changes after we read it,
4976  *    and we take cgroup_mutex, keeping cgroup_attach_task() from changing it
4977  *    anyway.  No need to check that tsk->cgroup != NULL, thanks to
4978  *    the_top_cgroup_hack in cgroup_exit(), which sets an exiting tasks
4979  *    cgroup to top_cgroup.
4980  */
4981 
4982 /* TODO: Use a proper seq_file iterator */
4983 int proc_cgroup_show(struct seq_file *m, void *v)
4984 {
4985         struct pid *pid;
4986         struct task_struct *tsk;
4987         char *buf;
4988         int retval;
4989         struct cgroupfs_root *root;
4990 
4991         retval = -ENOMEM;
4992         buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
4993         if (!buf)
4994                 goto out;
4995 
4996         retval = -ESRCH;
4997         pid = m->private;
4998         tsk = get_pid_task(pid, PIDTYPE_PID);
4999         if (!tsk)
5000                 goto out_free;
5001 
5002         retval = 0;
5003 
5004         mutex_lock(&cgroup_mutex);
5005 
5006         for_each_active_root(root) {
5007                 struct cgroup_subsys *ss;
5008                 struct cgroup *cgrp;
5009                 int count = 0;
5010 
5011                 seq_printf(m, "%d:", root->hierarchy_id);
5012                 for_each_root_subsys(root, ss)
5013                         seq_printf(m, "%s%s", count++ ? "," : "", ss->name);
5014                 if (strlen(root->name))
5015                         seq_printf(m, "%sname=%s", count ? "," : "",
5016                                    root->name);
5017                 seq_putc(m, ':');
5018                 cgrp = task_cgroup_from_root(tsk, root);
5019                 retval = cgroup_path(cgrp, buf, PAGE_SIZE);
5020                 if (retval < 0)
5021                         goto out_unlock;
5022                 seq_puts(m, buf);
5023                 seq_putc(m, '\n');
5024         }
5025 
5026 out_unlock:
5027         mutex_unlock(&cgroup_mutex);
5028         put_task_struct(tsk);
5029 out_free:
5030         kfree(buf);
5031 out:
5032         return retval;
5033 }
5034 
5035 /* Display information about each subsystem and each hierarchy */
5036 static int proc_cgroupstats_show(struct seq_file *m, void *v)
5037 {
5038         struct cgroup_subsys *ss;
5039         int i;
5040 
5041         seq_puts(m, "#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
5042         /*
5043          * ideally we don't want subsystems moving around while we do this.
5044          * cgroup_mutex is also necessary to guarantee an atomic snapshot of
5045          * subsys/hierarchy state.
5046          */
5047         mutex_lock(&cgroup_mutex);
5048 
5049         for_each_subsys(ss, i)
5050                 seq_printf(m, "%s\t%d\t%d\t%d\n",
5051                            ss->name, ss->root->hierarchy_id,
5052                            ss->root->number_of_cgroups, !ss->disabled);
5053 
5054         mutex_unlock(&cgroup_mutex);
5055         return 0;
5056 }
5057 
5058 static int cgroupstats_open(struct inode *inode, struct file *file)
5059 {
5060         return single_open(file, proc_cgroupstats_show, NULL);
5061 }
5062 
5063 static const struct file_operations proc_cgroupstats_operations = {
5064         .open = cgroupstats_open,
5065         .read = seq_read,
5066         .llseek = seq_lseek,
5067         .release = single_release,
5068 };
5069 
5070 /**
5071  * cgroup_fork - attach newly forked task to its parents cgroup.
5072  * @child: pointer to task_struct of forking parent process.
5073  *
5074  * Description: A task inherits its parent's cgroup at fork().
5075  *
5076  * A pointer to the shared css_set was automatically copied in
5077  * fork.c by dup_task_struct().  However, we ignore that copy, since
5078  * it was not made under the protection of RCU or cgroup_mutex, so
5079  * might no longer be a valid cgroup pointer.  cgroup_attach_task() might
5080  * have already changed current->cgroups, allowing the previously
5081  * referenced cgroup group to be removed and freed.
5082  *
5083  * At the point that cgroup_fork() is called, 'current' is the parent
5084  * task, and the passed argument 'child' points to the child task.
5085  */
5086 void cgroup_fork(struct task_struct *child)
5087 {
5088         task_lock(current);
5089         get_css_set(task_css_set(current));
5090         child->cgroups = current->cgroups;
5091         task_unlock(current);
5092         INIT_LIST_HEAD(&child->cg_list);
5093 }
5094 
5095 /**
5096  * cgroup_post_fork - called on a new task after adding it to the task list
5097  * @child: the task in question
5098  *
5099  * Adds the task to the list running through its css_set if necessary and
5100  * call the subsystem fork() callbacks.  Has to be after the task is
5101  * visible on the task list in case we race with the first call to
5102  * cgroup_iter_start() - to guarantee that the new task ends up on its
5103  * list.
5104  */
5105 void cgroup_post_fork(struct task_struct *child)
5106 {
5107         struct cgroup_subsys *ss;
5108         int i;
5109 
5110         /*
5111          * use_task_css_set_links is set to 1 before we walk the tasklist
5112          * under the tasklist_lock and we read it here after we added the child
5113          * to the tasklist under the tasklist_lock as well. If the child wasn't
5114          * yet in the tasklist when we walked through it from
5115          * cgroup_enable_task_cg_lists(), then use_task_css_set_links value
5116          * should be visible now due to the paired locking and barriers implied
5117          * by LOCK/UNLOCK: it is written before the tasklist_lock unlock
5118          * in cgroup_enable_task_cg_lists() and read here after the tasklist_lock
5119          * lock on fork.
5120          */
5121         if (use_task_css_set_links) {
5122                 write_lock(&css_set_lock);
5123                 task_lock(child);
5124                 if (list_empty(&child->cg_list))
5125                         list_add(&child->cg_list, &task_css_set(child)->tasks);
5126                 task_unlock(child);
5127                 write_unlock(&css_set_lock);
5128         }
5129 
5130         /*
5131          * Call ss->fork().  This must happen after @child is linked on
5132          * css_set; otherwise, @child might change state between ->fork()
5133          * and addition to css_set.
5134          */
5135         if (need_forkexit_callback) {
5136                 /*
5137                  * fork/exit callbacks are supported only for builtin
5138                  * subsystems, and the builtin section of the subsys
5139                  * array is immutable, so we don't need to lock the
5140                  * subsys array here. On the other hand, modular section
5141                  * of the array can be freed at module unload, so we
5142                  * can't touch that.
5143                  */
5144                 for_each_builtin_subsys(ss, i)
5145                         if (ss->fork)
5146                                 ss->fork(child);
5147         }
5148 }
5149 
5150 /**
5151  * cgroup_exit - detach cgroup from exiting task
5152  * @tsk: pointer to task_struct of exiting process
5153  * @run_callback: run exit callbacks?
5154  *
5155  * Description: Detach cgroup from @tsk and release it.
5156  *
5157  * Note that cgroups marked notify_on_release force every task in
5158  * them to take the global cgroup_mutex mutex when exiting.
5159  * This could impact scaling on very large systems.  Be reluctant to
5160  * use notify_on_release cgroups where very high task exit scaling
5161  * is required on large systems.
5162  *
5163  * the_top_cgroup_hack:
5164  *
5165  *    Set the exiting tasks cgroup to the root cgroup (top_cgroup).
5166  *
5167  *    We call cgroup_exit() while the task is still competent to
5168  *    handle notify_on_release(), then leave the task attached to the
5169  *    root cgroup in each hierarchy for the remainder of its exit.
5170  *
5171  *    To do this properly, we would increment the reference count on
5172  *    top_cgroup, and near the very end of the kernel/exit.c do_exit()
5173  *    code we would add a second cgroup function call, to drop that
5174  *    reference.  This would just create an unnecessary hot spot on
5175  *    the top_cgroup reference count, to no avail.
5176  *
5177  *    Normally, holding a reference to a cgroup without bumping its
5178  *    count is unsafe.   The cgroup could go away, or someone could
5179  *    attach us to a different cgroup, decrementing the count on
5180  *    the first cgroup that we never incremented.  But in this case,
5181  *    top_cgroup isn't going away, and either task has PF_EXITING set,
5182  *    which wards off any cgroup_attach_task() attempts, or task is a failed
5183  *    fork, never visible to cgroup_attach_task.
5184  */
5185 void cgroup_exit(struct task_struct *tsk, int run_callbacks)
5186 {
5187         struct cgroup_subsys *ss;
5188         struct css_set *cset;
5189         int i;
5190 
5191         /*
5192          * Unlink from the css_set task list if necessary.
5193          * Optimistically check cg_list before taking
5194          * css_set_lock
5195          */
5196         if (!list_empty(&tsk->cg_list)) {
5197                 write_lock(&css_set_lock);
5198                 if (!list_empty(&tsk->cg_list))
5199                         list_del_init(&tsk->cg_list);
5200                 write_unlock(&css_set_lock);
5201         }
5202 
5203         /* Reassign the task to the init_css_set. */
5204         task_lock(tsk);
5205         cset = task_css_set(tsk);
5206         RCU_INIT_POINTER(tsk->cgroups, &init_css_set);
5207 
5208         if (run_callbacks && need_forkexit_callback) {
5209                 /*
5210                  * fork/exit callbacks are supported only for builtin
5211                  * subsystems, see cgroup_post_fork() for details.
5212                  */
5213                 for_each_builtin_subsys(ss, i) {
5214                         if (ss->exit) {
5215                                 struct cgroup *old_cgrp = cset->subsys[i]->cgroup;
5216                                 struct cgroup *cgrp = task_cgroup(tsk, i);
5217 
5218                                 ss->exit(cgrp, old_cgrp, tsk);
5219                         }
5220                 }
5221         }
5222         task_unlock(tsk);
5223 
5224         put_css_set_taskexit(cset);
5225 }
5226 
5227 static void check_for_release(struct cgroup *cgrp)
5228 {
5229         if (cgroup_is_releasable(cgrp) &&
5230             list_empty(&cgrp->cset_links) && list_empty(&cgrp->children)) {
5231                 /*
5232                  * Control Group is currently removeable. If it's not
5233                  * already queued for a userspace notification, queue
5234                  * it now
5235                  */
5236                 int need_schedule_work = 0;
5237 
5238                 raw_spin_lock(&release_list_lock);
5239                 if (!cgroup_is_dead(cgrp) &&
5240                     list_empty(&cgrp->release_list)) {
5241                         list_add(&cgrp->release_list, &release_list);
5242                         need_schedule_work = 1;
5243                 }
5244                 raw_spin_unlock(&release_list_lock);
5245                 if (need_schedule_work)
5246                         schedule_work(&release_agent_work);
5247         }
5248 }
5249 
5250 /*
5251  * Notify userspace when a cgroup is released, by running the
5252  * configured release agent with the name of the cgroup (path
5253  * relative to the root of cgroup file system) as the argument.
5254  *
5255  * Most likely, this user command will try to rmdir this cgroup.
5256  *
5257  * This races with the possibility that some other task will be
5258  * attached to this cgroup before it is removed, or that some other
5259  * user task will 'mkdir' a child cgroup of this cgroup.  That's ok.
5260  * The presumed 'rmdir' will fail quietly if this cgroup is no longer
5261  * unused, and this cgroup will be reprieved from its death sentence,
5262  * to continue to serve a useful existence.  Next time it's released,
5263  * we will get notified again, if it still has 'notify_on_release' set.
5264  *
5265  * The final arg to call_usermodehelper() is UMH_WAIT_EXEC, which
5266  * means only wait until the task is successfully execve()'d.  The
5267  * separate release agent task is forked by call_usermodehelper(),
5268  * then control in this thread returns here, without waiting for the
5269  * release agent task.  We don't bother to wait because the caller of
5270  * this routine has no use for the exit status of the release agent
5271  * task, so no sense holding our caller up for that.
5272  */
5273 static void cgroup_release_agent(struct work_struct *work)
5274 {
5275         BUG_ON(work != &release_agent_work);
5276         mutex_lock(&cgroup_mutex);
5277         raw_spin_lock(&release_list_lock);
5278         while (!list_empty(&release_list)) {
5279                 char *argv[3], *envp[3];
5280                 int i;
5281                 char *pathbuf = NULL, *agentbuf = NULL;
5282                 struct cgroup *cgrp = list_entry(release_list.next,
5283                                                     struct cgroup,
5284                                                     release_list);
5285                 list_del_init(&cgrp->release_list);
5286                 raw_spin_unlock(&release_list_lock);
5287                 pathbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
5288                 if (!pathbuf)
5289                         goto continue_free;
5290                 if (cgroup_path(cgrp, pathbuf, PAGE_SIZE) < 0)
5291                         goto continue_free;
5292                 agentbuf = kstrdup(cgrp->root->release_agent_path, GFP_KERNEL);
5293                 if (!agentbuf)
5294                         goto continue_free;
5295 
5296                 i = 0;
5297                 argv[i++] = agentbuf;
5298                 argv[i++] = pathbuf;
5299                 argv[i] = NULL;
5300 
5301                 i = 0;
5302                 /* minimal command environment */
5303                 envp[i++] = "HOME=/";
5304                 envp[i++] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
5305                 envp[i] = NULL;
5306 
5307                 /* Drop the lock while we invoke the usermode helper,
5308                  * since the exec could involve hitting disk and hence
5309                  * be a slow process */
5310                 mutex_unlock(&cgroup_mutex);
5311                 call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
5312                 mutex_lock(&cgroup_mutex);
5313  continue_free:
5314                 kfree(pathbuf);
5315                 kfree(agentbuf);
5316                 raw_spin_lock(&release_list_lock);
5317         }
5318         raw_spin_unlock(&release_list_lock);
5319         mutex_unlock(&cgroup_mutex);
5320 }
5321 
5322 static int __init cgroup_disable(char *str)
5323 {
5324         struct cgroup_subsys *ss;
5325         char *token;
5326         int i;
5327 
5328         while ((token = strsep(&str, ",")) != NULL) {
5329                 if (!*token)
5330                         continue;
5331 
5332                 /*
5333                  * cgroup_disable, being at boot time, can't know about
5334                  * module subsystems, so we don't worry about them.
5335                  */
5336                 for_each_builtin_subsys(ss, i) {
5337                         if (!strcmp(token, ss->name)) {
5338                                 ss->disabled = 1;
5339                                 printk(KERN_INFO "Disabling %s control group"
5340                                         " subsystem\n", ss->name);
5341                                 break;
5342                         }
5343                 }
5344         }
5345         return 1;
5346 }
5347 __setup("cgroup_disable=", cgroup_disable);
5348 
5349 /*
5350  * Functons for CSS ID.
5351  */
5352 
5353 /* to get ID other than 0, this should be called when !cgroup_is_dead() */
5354 unsigned short css_id(struct cgroup_subsys_state *css)
5355 {
5356         struct css_id *cssid;
5357 
5358         /*
5359          * This css_id() can return correct value when somone has refcnt
5360          * on this or this is under rcu_read_lock(). Once css->id is allocated,
5361          * it's unchanged until freed.
5362          */
5363         cssid = rcu_dereference_raw(css->id);
5364 
5365         if (cssid)
5366                 return cssid->id;
5367         return 0;
5368 }
5369 EXPORT_SYMBOL_GPL(css_id);
5370 
5371 /**
5372  *  css_is_ancestor - test "root" css is an ancestor of "child"
5373  * @child: the css to be tested.
5374  * @root: the css supporsed to be an ancestor of the child.
5375  *
5376  * Returns true if "root" is an ancestor of "child" in its hierarchy. Because
5377  * this function reads css->id, the caller must hold rcu_read_lock().
5378  * But, considering usual usage, the csses should be valid objects after test.
5379  * Assuming that the caller will do some action to the child if this returns
5380  * returns true, the caller must take "child";s reference count.
5381  * If "child" is valid object and this returns true, "root" is valid, too.
5382  */
5383 
5384 bool css_is_ancestor(struct cgroup_subsys_state *child,
5385                     const struct cgroup_subsys_state *root)
5386 {
5387         struct css_id *child_id;
5388         struct css_id *root_id;
5389 
5390         child_id  = rcu_dereference(child->id);
5391         if (!child_id)
5392                 return false;
5393         root_id = rcu_dereference(root->id);
5394         if (!root_id)
5395                 return false;
5396         if (child_id->depth < root_id->depth)
5397                 return false;
5398         if (child_id->stack[root_id->depth] != root_id->id)
5399                 return false;
5400         return true;
5401 }
5402 
5403 void free_css_id(struct cgroup_subsys *ss, struct cgroup_subsys_state *css)
5404 {
5405         struct css_id *id = rcu_dereference_protected(css->id, true);
5406 
5407         /* When this is called before css_id initialization, id can be NULL */
5408         if (!id)
5409                 return;
5410 
5411         BUG_ON(!ss->use_id);
5412 
5413         rcu_assign_pointer(id->css, NULL);
5414         rcu_assign_pointer(css->id, NULL);
5415         spin_lock(&ss->id_lock);
5416         idr_remove(&ss->idr, id->id);
5417         spin_unlock(&ss->id_lock);
5418         kfree_rcu(id, rcu_head);
5419 }
5420 EXPORT_SYMBOL_GPL(free_css_id);
5421 
5422 /*
5423  * This is called by init or create(). Then, calls to this function are
5424  * always serialized (By cgroup_mutex() at create()).
5425  */
5426 
5427 static struct css_id *get_new_cssid(struct cgroup_subsys *ss, int depth)
5428 {
5429         struct css_id *newid;
5430         int ret, size;
5431 
5432         BUG_ON(!ss->use_id);
5433 
5434         size = sizeof(*newid) + sizeof(unsigned short) * (depth + 1);
5435         newid = kzalloc(size, GFP_KERNEL);
5436         if (!newid)
5437                 return ERR_PTR(-ENOMEM);
5438 
5439         idr_preload(GFP_KERNEL);
5440         spin_lock(&ss->id_lock);
5441         /* Don't use 0. allocates an ID of 1-65535 */
5442         ret = idr_alloc(&ss->idr, newid, 1, CSS_ID_MAX + 1, GFP_NOWAIT);
5443         spin_unlock(&ss->id_lock);
5444         idr_preload_end();
5445 
5446         /* Returns error when there are no free spaces for new ID.*/
5447         if (ret < 0)
5448                 goto err_out;
5449 
5450         newid->id = ret;
5451         newid->depth = depth;
5452         return newid;
5453 err_out:
5454         kfree(newid);
5455         return ERR_PTR(ret);
5456 
5457 }
5458 
5459 static int __init_or_module cgroup_init_idr(struct cgroup_subsys *ss,
5460                                             struct cgroup_subsys_state *rootcss)
5461 {
5462         struct css_id *newid;
5463 
5464         spin_lock_init(&ss->id_lock);
5465         idr_init(&ss->idr);
5466 
5467         newid = get_new_cssid(ss, 0);
5468         if (IS_ERR(newid))
5469                 return PTR_ERR(newid);
5470 
5471         newid->stack[0] = newid->id;
5472         RCU_INIT_POINTER(newid->css, rootcss);
5473         RCU_INIT_POINTER(rootcss->id, newid);
5474         return 0;
5475 }
5476 
5477 static int alloc_css_id(struct cgroup_subsys *ss, struct cgroup *parent,
5478                         struct cgroup *child)
5479 {
5480         int subsys_id, i, depth = 0;
5481         struct cgroup_subsys_state *parent_css, *child_css;
5482         struct css_id *child_id, *parent_id;
5483 
5484         subsys_id = ss->subsys_id;
5485         parent_css = parent->subsys[subsys_id];
5486         child_css = child->subsys[subsys_id];
5487         parent_id = rcu_dereference_protected(parent_css->id, true);
5488         depth = parent_id->depth + 1;
5489 
5490         child_id = get_new_cssid(ss, depth);
5491         if (IS_ERR(child_id))
5492                 return PTR_ERR(child_id);
5493 
5494         for (i = 0; i < depth; i++)
5495                 child_id->stack[i] = parent_id->stack[i];
5496         child_id->stack[depth] = child_id->id;
5497         /*
5498          * child_id->css pointer will be set after this cgroup is available
5499          * see cgroup_populate_dir()
5500          */
5501         rcu_assign_pointer(child_css->id, child_id);
5502 
5503         return 0;
5504 }
5505 
5506 /**
5507  * css_lookup - lookup css by id
5508  * @ss: cgroup subsys to be looked into.
5509  * @id: the id
5510  *
5511  * Returns pointer to cgroup_subsys_state if there is valid one with id.
5512  * NULL if not. Should be called under rcu_read_lock()
5513  */
5514 struct cgroup_subsys_state *css_lookup(struct cgroup_subsys *ss, int id)
5515 {
5516         struct css_id *cssid = NULL;
5517 
5518         BUG_ON(!ss->use_id);
5519         cssid = idr_find(&ss->idr, id);
5520 
5521         if (unlikely(!cssid))
5522                 return NULL;
5523 
5524         return rcu_dereference(cssid->css);
5525 }
5526 EXPORT_SYMBOL_GPL(css_lookup);
5527 
5528 /*
5529  * get corresponding css from file open on cgroupfs directory
5530  */
5531 struct cgroup_subsys_state *cgroup_css_from_dir(struct file *f, int id)
5532 {
5533         struct cgroup *cgrp;
5534         struct inode *inode;
5535         struct cgroup_subsys_state *css;
5536 
5537         inode = file_inode(f);
5538         /* check in cgroup filesystem dir */
5539         if (inode->i_op != &cgroup_dir_inode_operations)
5540                 return ERR_PTR(-EBADF);
5541 
5542         if (id < 0 || id >= CGROUP_SUBSYS_COUNT)
5543                 return ERR_PTR(-EINVAL);
5544 
5545         /* get cgroup */
5546         cgrp = __d_cgrp(f->f_dentry);
5547         css = cgrp->subsys[id];
5548         return css ? css : ERR_PTR(-ENOENT);
5549 }
5550 
5551 #ifdef CONFIG_CGROUP_DEBUG
5552 static struct cgroup_subsys_state *debug_css_alloc(struct cgroup *cgrp)
5553 {
5554         struct cgroup_subsys_state *css = kzalloc(sizeof(*css), GFP_KERNEL);
5555 
5556         if (!css)
5557                 return ERR_PTR(-ENOMEM);
5558 
5559         return css;
5560 }
5561 
5562 static void debug_css_free(struct cgroup *cgrp)
5563 {
5564         kfree(cgrp->subsys[debug_subsys_id]);
5565 }
5566 
5567 static u64 debug_taskcount_read(struct cgroup *cgrp, struct cftype *cft)
5568 {
5569         return cgroup_task_count(cgrp);
5570 }
5571 
5572 static u64 current_css_set_read(struct cgroup *cgrp, struct cftype *cft)
5573 {
5574         return (u64)(unsigned long)current->cgroups;
5575 }
5576 
5577 static u64 current_css_set_refcount_read(struct cgroup *cgrp,
5578                                          struct cftype *cft)
5579 {
5580         u64 count;
5581 
5582         rcu_read_lock();
5583         count = atomic_read(&task_css_set(current)->refcount);
5584         rcu_read_unlock();
5585         return count;
5586 }
5587 
5588 static int current_css_set_cg_links_read(struct cgroup *cgrp,
5589                                          struct cftype *cft,
5590                                          struct seq_file *seq)
5591 {
5592         struct cgrp_cset_link *link;
5593         struct css_set *cset;
5594 
5595         read_lock(&css_set_lock);
5596         rcu_read_lock();
5597         cset = rcu_dereference(current->cgroups);
5598         list_for_each_entry(link, &cset->cgrp_links, cgrp_link) {
5599                 struct cgroup *c = link->cgrp;
5600                 const char *name;
5601 
5602                 if (c->dentry)
5603                         name = c->dentry->d_name.name;
5604                 else
5605                         name = "?";
5606                 seq_printf(seq, "Root %d group %s\n",
5607                            c->root->hierarchy_id, name);
5608         }
5609         rcu_read_unlock();
5610         read_unlock(&css_set_lock);
5611         return 0;
5612 }
5613 
5614 #define MAX_TASKS_SHOWN_PER_CSS 25
5615 static int cgroup_css_links_read(struct cgroup *cgrp,
5616                                  struct cftype *cft,
5617                                  struct seq_file *seq)
5618 {
5619         struct cgrp_cset_link *link;
5620 
5621         read_lock(&css_set_lock);
5622         list_for_each_entry(link, &cgrp->cset_links, cset_link) {
5623                 struct css_set *cset = link->cset;
5624                 struct task_struct *task;
5625                 int count = 0;
5626                 seq_printf(seq, "css_set %p\n", cset);
5627                 list_for_each_entry(task, &cset->tasks, cg_list) {
5628                         if (count++ > MAX_TASKS_SHOWN_PER_CSS) {
5629                                 seq_puts(seq, "  ...\n");
5630                                 break;
5631                         } else {
5632                                 seq_printf(seq, "  task %d\n",
5633                                            task_pid_vnr(task));
5634                         }
5635                 }
5636         }
5637         read_unlock(&css_set_lock);
5638         return 0;
5639 }
5640 
5641 static u64 releasable_read(struct cgroup *cgrp, struct cftype *cft)
5642 {
5643         return test_bit(CGRP_RELEASABLE, &cgrp->flags);
5644 }
5645 
5646 static struct cftype debug_files[] =  {
5647         {
5648                 .name = "taskcount",
5649                 .read_u64 = debug_taskcount_read,
5650         },
5651 
5652         {
5653                 .name = "current_css_set",
5654                 .read_u64 = current_css_set_read,
5655         },
5656 
5657         {
5658                 .name = "current_css_set_refcount",
5659                 .read_u64 = current_css_set_refcount_read,
5660         },
5661 
5662         {
5663                 .name = "current_css_set_cg_links",
5664                 .read_seq_string = current_css_set_cg_links_read,
5665         },
5666 
5667         {
5668                 .name = "cgroup_css_links",
5669                 .read_seq_string = cgroup_css_links_read,
5670         },
5671 
5672         {
5673                 .name = "releasable",
5674                 .read_u64 = releasable_read,
5675         },
5676 
5677         { }     /* terminate */
5678 };
5679 
5680 struct cgroup_subsys debug_subsys = {
5681         .name = "debug",
5682         .css_alloc = debug_css_alloc,
5683         .css_free = debug_css_free,
5684         .subsys_id = debug_subsys_id,
5685         .base_cftypes = debug_files,
5686 };
5687 #endif /* CONFIG_CGROUP_DEBUG */
5688 
