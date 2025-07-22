#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

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

int zk_debugfs_init(struct dentry *parent)
{
    zk_debugfs_file = debugfs_create_file("zk_handshake", 0444, parent, NULL, &zk_fops);
    if (!zk_debugfs_file)
        return -ENOMEM;
    return 0;
}

void zk_debugfs_exit(void)
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
