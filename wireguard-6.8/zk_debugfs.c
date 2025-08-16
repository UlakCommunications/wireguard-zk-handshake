#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include "zk_pending.h"
#include "zk_debugfs.h"

#define ZK_BUF_SIZE 256

static char zk_handshake_buffer[ZK_BUF_SIZE];
static size_t zk_handshake_len = 0;
static DEFINE_MUTEX(zk_buffer_lock);

static ssize_t zk_read(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
ssize_t ret;

mutex_lock(&zk_buffer_lock);
ret = simple_read_from_buffer(buf, len, ppos, zk_handshake_buffer, zk_handshake_len);
mutex_unlock(&zk_buffer_lock);

return ret;
}

static const struct file_operations zk_fops = {
        .owner = THIS_MODULE,
        .read = zk_read,
};

static struct dentry *zk_debugfs_file;
/* Forward declare before first use */
static int zk_pending_open(struct inode *inode, struct file *file);
static const struct file_operations zk_pending_fops;

int zk_debugfs_init(struct dentry *parent)
{
    zk_debugfs_file = debugfs_create_file("zk_handshake", 0444, parent, NULL, &zk_fops);
    if (!zk_debugfs_file)
        return -ENOMEM;

    debugfs_create_file("zk_pending", 0444, parent, NULL, &zk_pending_fops);

    return 0;
}

void zk_debugfs_cleanup(void)
{
    debugfs_remove(zk_debugfs_file);
}

void zk_debugfs_update(const void *msg, size_t len)
{
    if (len > ZK_BUF_SIZE)
        len = ZK_BUF_SIZE;

    mutex_lock(&zk_buffer_lock);
    memcpy(zk_handshake_buffer, msg, len);
    zk_handshake_len = len;
    mutex_unlock(&zk_buffer_lock);
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
static int zk_pending_open(struct inode *inode, struct file *file)
{
    return single_open(file, zk_pending_seq_show, NULL);
}

static const struct file_operations zk_pending_fops = {
        .owner = THIS_MODULE,
        .open = zk_pending_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};
