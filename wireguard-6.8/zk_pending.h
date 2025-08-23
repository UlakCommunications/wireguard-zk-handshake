#ifndef ZK_PENDING_H
#define ZK_PENDING_H

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include "peer.h"

struct zk_pending_entry {
    u32 sender_index;
    struct wg_peer *peer;
    struct wg_device *wg;        /* needed to re-consume */
    void *raw;                   /* kmemdup of initiation */
    size_t len;                  /* length of raw */
	struct hlist_node node;
	u64 created_ns;
};

extern struct hlist_head zk_pending_table[];
extern spinlock_t zk_lock;
int zk_pending_get_count(void);
void zk_pending_add(u32 sender_index,
					struct wg_peer *peer,
                    struct wg_device *wg,
                    const void *raw,
                    size_t len);
struct wg_peer *zk_pending_get(u32 sender_index);
void zk_pending_cleanup_expired(void);
void zk_pending_init_cleanup_timer(void);
void zk_pending_cleanup_timer_exit(void);
/* Remove entry by sender_index and return it (caller must kfree()) */
struct zk_pending_entry *zk_pending_take(u32 sender_index);
/* For debugfs/procfs: pretty-print pending entries without exposing the table */
int zk_pending_seq_show(struct seq_file *m, void *v);
#endif
