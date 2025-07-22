#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include "peer.h"
#include "zk_pending.h"

#define ZK_PENDING_BITS 4  // 2⁴ = 16 buckets

struct zk_pending_entry {
    u32 sender_index;
    struct wg_peer *peer;
    struct hlist_node node;
};

static DEFINE_HASHTABLE(zk_pending_table, ZK_PENDING_BITS);
static DEFINE_SPINLOCK(zk_pending_lock);

void zk_pending_add(u32 sender_index, struct wg_peer *peer)
{
    struct zk_pending_entry *entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->sender_index = sender_index;
    entry->peer = peer;

    spin_lock_bh(&zk_pending_lock);
    hash_add(zk_pending_table, &entry->node, sender_index);
    spin_unlock_bh(&zk_pending_lock);
}

struct wg_peer *zk_pending_get(u32 sender_index)
{
    struct zk_pending_entry *entry;
    struct wg_peer *peer = NULL;

    spin_lock_bh(&zk_pending_lock);
    hash_for_each_possible(zk_pending_table, entry, node, sender_index) {
        if (entry->sender_index == sender_index) {
            peer = entry->peer;
            hash_del(&entry->node);
            kfree(entry);
            break;
        }
    }
    spin_unlock_bh(&zk_pending_lock);

    return peer;
}
