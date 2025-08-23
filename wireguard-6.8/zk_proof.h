// zk_proof.h
#ifndef _WGZK_PROOF_H
#define _WGZK_PROOF_H
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <linux/printk.h>

bool zk_proof_get_and_clear(u64 peer_id, u8 r[32], u8 s[32]);
void zk_proof_set(u64 peer_id, const u8 r[32], const u8 s[32]);

#endif
