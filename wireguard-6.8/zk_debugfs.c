#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include "zk_pending.h"
#include "zk_debugfs.h"

#define ZK_BUF_SIZE 256
#define ZK_LEN 96

//static char zk_handshake_buffer[ZK_BUF_SIZE];
//static size_t zk_handshake_len = 0;


//static DEFINE_MUTEX(zk_lock);
//static u8 zk_buf[ZK_LEN];
/* Separate mutex for debugfs buffer; don't clash with pending's spinlock */
static DEFINE_MUTEX(wgzk_dbgfs_mutex);
static u8 zk_buf[ZK_LEN];


static ssize_t zk_read(struct file *file, char __user *ubuf, size_t len, loff_t *ppos);
static const struct file_operations zk_fops = {
        .owner = THIS_MODULE,
        .read  = zk_read,
        .llseek = no_llseek,
};

static struct dentry *zk_debugfs_file;
static struct dentry *zk_pending_file;

/* Forward declare before first use */
static int zk_pending_open(struct inode *inode, struct file *file);

static const struct file_operations zk_pending_fops;

static const struct file_operations zk_pending_fops = {
        .owner = THIS_MODULE,
        .open = zk_pending_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};

///* lazy init: creates /sys/kernel/debug/wireguard/zk_handshake on first publish */
//static void zk_debugfs_lazy_init(void)
//{
//	if (atomic_xchg(&zk_init_once, 1))
//		return;
//
//	/* make sure /sys/kernel/debug is mounted */
//	/* parent dir under debugfs */
//	wg_dir = debugfs_create_dir("wireguard", NULL);
//	if (IS_ERR_OR_NULL(wg_dir)) {
//		wg_dir = NULL;
//		return;
//	}
//	zk_file = debugfs_create_blob("zk_handshake", 0444, wg_dir, &zk_blob);
//	if (IS_ERR_OR_NULL(zk_file))
//		zk_file = NULL;
//}
//static struct dentry *wg_dir;
//static struct dentry *zk_file;
//
///* [0..96) last handshake blob */
//static struct debugfs_blob_wrapper zk_blob = {.data = zk_buf, .size = ZK_LEN};
//static atomic_t zk_init_once = ATOMIC_INIT(0);

static ssize_t zk_read(struct file *file, char __user *ubuf, size_t len, loff_t *ppos)
{
    ssize_t ret;
    size_t n;

    if (*ppos >= sizeof(zk_buf))
        return 0;

    mutex_lock(&wgzk_dbgfs_mutex);
    n = min(len, sizeof(zk_buf) - (size_t) * ppos);
    ret = copy_to_user(ubuf, zk_buf + *ppos, n) ? -EFAULT : (ssize_t) n;
    if (ret > 0) *ppos +=
        ret;
    mutex_unlock(&wgzk_dbgfs_mutex);
    return ret;
}

int zk_debugfs_init(struct dentry *parent) {
    zk_debugfs_file = debugfs_create_file("zk_handshake", 0444, parent, NULL, &zk_fops);
    if (!zk_debugfs_file)
        return -ENOMEM;

    zk_pending_file = debugfs_create_file("zk_pending", 0444, parent, NULL, &zk_pending_fops);
    if (IS_ERR_OR_NULL(zk_pending_file)) {
        debugfs_remove(zk_debugfs_file);
        zk_debugfs_file = NULL;
        return -ENOMEM;
    }

    return 0;
}

void zk_debugfs_cleanup(void) {
    debugfs_remove(zk_pending_file);
    debugfs_remove(zk_debugfs_file);
    zk_pending_file = NULL;
    zk_debugfs_file = NULL;
}

/* Optional helper if you want to update from other code paths */
void zk_debugfs_update(const void *msg, size_t len) {
    if (len > ZK_LEN)
        len = ZK_LEN;
    mutex_lock(&wgzk_dbgfs_mutex);
    memcpy(zk_buf, msg, len);
    mutex_unlock(&wgzk_dbgfs_mutex);
}
//
//static int zk_pending_show(struct seq_file *m, void *v)
//{
//    struct zk_pending_entry *entry;
//    int bkt;
//    u64 now = ktime_get_coarse_boottime_ns();
//
//    seq_printf(m, "Total pending entries: %d\n", zk_pending_get_count());
//    seq_printf(m, "Index\tAge (ms)\n");
//
//    spin_lock_bh(&zk_lock);
//    hash_for_each(zk_pending_table, bkt, entry, node) {
//        u64 age_ms = div_u64(now - entry->created_ns, NSEC_PER_MSEC);
//        seq_printf(m, "%u\t%llu ms\n", entry->sender_index, age_ms);
//    }
//    spin_unlock_bh(&zk_lock);
//
//    return 0;
//}
static int zk_pending_open(struct inode *inode, struct file *file) {
    return single_open(file, zk_pending_seq_show, NULL);
}


/* Exported API: publish 96 bytes for userspace to read. Safe to call anytime. */
void zk_publish_handshake(const u8 in96[ZK_LEN]) {
//    zk_debugfs_lazy_init();
    mutex_lock(&wgzk_dbgfs_mutex);
    memcpy(zk_buf, in96, ZK_LEN);
    mutex_unlock(&wgzk_dbgfs_mutex);
}

EXPORT_SYMBOL_GPL(zk_publish_handshake);