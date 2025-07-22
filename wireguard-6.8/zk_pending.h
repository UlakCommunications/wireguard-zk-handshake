#ifndef WG_ZK_PENDING_H
#define WG_ZK_PENDING_H

#include "peer.h"

void zk_pending_add(u32 sender_index, struct wg_peer *peer);
struct wg_peer *zk_pending_get(u32 sender_index);

#endif
