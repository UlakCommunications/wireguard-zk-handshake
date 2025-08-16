/* wgzk_genl.h - WireGuard ZK Generic Netlink interface */
#ifndef _WGZK_GENL_H
#define _WGZK_GENL_H

/* Initialize the wg-zk Generic Netlink family */
int wgzk_genl_init(void);

/* Tear down the wg-zk Generic Netlink family */
void wgzk_genl_exit(void);

#endif /* _WGZK_GENL_H */
