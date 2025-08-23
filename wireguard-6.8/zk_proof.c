// zk_proof.c
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "zk_proof.h"

#define ZK_PROOF_BITS 8

struct zk_proof_entry {
    u64 peer_id;
    u8  r[32];
    u8  s[32];
    struct hlist_node node;
};

static DEFINE_HASHTABLE(zk_proof_table, ZK_PROOF_BITS);
static DEFINE_SPINLOCK(zk_proof_lock);

void zk_proof_set(u64 peer_id, const u8 r[32], const u8 s[32])
{
    struct zk_proof_entry *e;
    unsigned long flags;

    spin_lock_irqsave(&zk_proof_lock, flags);
    hash_for_each_possible(zk_proof_table, e, node, peer_id) {
        if (e->peer_id == peer_id) {
            memcpy(e->r, r, 32);
            memcpy(e->s, s, 32);
            spin_unlock_irqrestore(&zk_proof_lock, flags);
            return;
        }
    }
    e = kmalloc(sizeof(*e), GFP_ATOMIC);
    if (e) {
        e->peer_id = peer_id;
        memcpy(e->r, r, 32);
        memcpy(e->s, s, 32);
        hash_add(zk_proof_table, &e->node, peer_id);
    }
    spin_unlock_irqrestore(&zk_proof_lock, flags);
}

bool zk_proof_get_and_clear(u64 peer_id, u8 r[32], u8 s[32])
{
    struct zk_proof_entry *e;
    bool ok = false;
    unsigned long flags;

    spin_lock_irqsave(&zk_proof_lock, flags);
    hash_for_each_possible(zk_proof_table, e, node, peer_id) {
        if (e->peer_id == peer_id) {
            memcpy(r, e->r, 32);
            memcpy(s, e->s, 32);
            hash_del(&e->node);
            kfree(e);
            ok = true;
            break;
        }
    }
    spin_unlock_irqrestore(&zk_proof_lock, flags);
    return ok;
}
