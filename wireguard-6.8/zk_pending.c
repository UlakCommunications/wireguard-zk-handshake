#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/printk.h>

#include "peer.h"
#include "zk_pending.h"

#define ZK_HASH_BITS 8
#define ZK_PENDING_TIMEOUT_NS (30 * NSEC_PER_SEC)

DEFINE_HASHTABLE(zk_pending_table, ZK_HASH_BITS);
DEFINE_SPINLOCK(zk_lock);

static struct timer_list zk_cleanup_timer;
static atomic_t zk_pending_count = ATOMIC_INIT(0);

int zk_pending_get_count(void)
{
    return atomic_read(&zk_pending_count);
}

int zk_pending_seq_show(struct seq_file *m, void *v)
{
    struct zk_pending_entry *entry;
    int bkt;
    u64 now = ktime_get_coarse_boottime_ns();

    seq_printf(m, "Total pending entries: %d\n", zk_pending_get_count());
    seq_printf(m, "Index\tAge (ms)\n");

    spin_lock_bh(&zk_lock);
    hash_for_each(zk_pending_table, bkt, entry, node) {
        u64 age_ms = div_u64(now - entry->created_ns, NSEC_PER_MSEC);
        seq_printf(m, "%u\t%llu ms\n", entry->sender_index, age_ms);
    }
    spin_unlock_bh(&zk_lock);
    return 0;
}

void zk_pending_add(u32 sender_index, struct wg_peer *peer,
                    struct wg_device *wg, const void *raw,
                    size_t len)
{
	struct zk_pending_entry *e;

	// Cleanup before adding
	zk_pending_cleanup_expired();

	e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e)
        return;

    e->sender_index = sender_index;
    e->peer = peer;
    e->wg = wg;
    e->raw = kmemdup(raw, len, GFP_ATOMIC);
    e->len = e->raw ? len : 0;
    e->created_ns = ktime_get_coarse_boottime_ns();

	spin_lock_bh(&zk_lock);
    hash_add(zk_pending_table, &e->node, sender_index);
	spin_unlock_bh(&zk_lock);
    atomic_inc(&zk_pending_count);
	pr_info("WG-ZK: Added pending peer index=%u\n", sender_index);
}

struct wg_peer *zk_pending_get(u32 sender_index)
{
    struct zk_pending_entry *entry;
    struct wg_peer *peer = NULL;

	spin_lock_bh(&zk_lock);
    hash_for_each_possible(zk_pending_table, entry, node, sender_index) {
        if (entry->sender_index == sender_index) {
			hash_del(&entry->node);
            peer = entry->peer;
            kfree(entry->raw);
            kfree(entry);
            break;
        }
    }
	spin_unlock_bh(&zk_lock);

    return peer;
}

void zk_pending_cleanup_expired(void)
{
    struct zk_pending_entry *entry;
	struct hlist_node *tmp;
    int bkt;

    u64 now = ktime_get_coarse_boottime_ns();
    int removed = 0;

    spin_lock_bh(&zk_lock);
	hash_for_each_safe(zk_pending_table, bkt, tmp, entry, node) {
        if ((s64)(now - entry->created_ns) > ZK_PENDING_TIMEOUT_NS) {
			pr_info("WG-ZK: Expired pending index=%u\n", entry->sender_index);
            hash_del(&entry->node);
            kfree(entry->raw);
            kfree(entry);
            removed++;
        }
    }
    spin_unlock_bh(&zk_lock);
    if (removed)
        atomic_sub(removed, &zk_pending_count);
}

// Background cleanup timer

static void zk_timer_fn(struct timer_list *t)
{
    zk_pending_cleanup_expired();
    mod_timer(&zk_cleanup_timer, jiffies + msecs_to_jiffies(1000));
}

void zk_pending_init_cleanup_timer(void)
{
    timer_setup(&zk_cleanup_timer, zk_timer_fn, 0);
    mod_timer(&zk_cleanup_timer, jiffies + msecs_to_jiffies(1000));
}

void zk_pending_cleanup_timer_exit(void)
{
    del_timer_sync(&zk_cleanup_timer);
}
struct zk_pending_entry *zk_pending_take(u32 sender_index)
{
    struct zk_pending_entry *entry;
    bool found = false;

    spin_lock_bh(&zk_lock);
    hash_for_each_possible(zk_pending_table, entry, node, sender_index) {
        if (entry->sender_index == sender_index) {
            hash_del(&entry->node);
            atomic_dec(&zk_pending_count);
            found = true;
            break;
        }
    }
    spin_unlock_bh(&zk_lock);

    return found ? entry : NULL;
}