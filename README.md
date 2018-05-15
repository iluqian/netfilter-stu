# netfilter-stu
## 学习netfilter

有关移植时解决办法，有些函数的使用，可以参考内核中其他函数是怎么获取协议类型的就可以了

以下代码是当我需要获取协议类型的时候，作的参考 /drivers/net/ethernet/realtek/8139cp.c
````
		//首先我搜索的关键字是 IPPROTO_TCP,看看现有内核代码是如何调用的
		const struct iphdr *ip = ip_hdr(skb);
			if (ip->protocol == IPPROTO_TCP)
				flags |= IPCS | TCPCS;
			else if (ip->protocol == IPPROTO_UDP)
				flags |= IPCS | UDPCS;
			else
				WARN_ON(1);	/* we need a WARN() */
````

## 关于 /proc
   netfiler 中实现向/proc 文件系统写文件，是利用 proc_create(),   
   
   https://elixir.bootlin.com/linux/v3.10.87/source/net/netfilter/nf_conntrack_expect.c
````
static inline struct proc_dir_entry *proc_create(
				const char *name, umode_t mode, struct proc_dir_entry *parent,
				const struct file_operations *proc_fops)
{
			return proc_create_data(name, mode, parent, proc_fops, NULL);
}
````
## 内核文件读写
````
//打开文件
strcut file* filp_open(const char* filename, int open_mode, int mode);
//该函数返回strcut file*结构指针，供后继函数操作使用，该返回值用IS_ERR()来检验其有效性。

//读写文件
ssize_t vfs_read(struct file* filp, char __user* buffer, size_t len, loff_t* pos);
ssize_t vfs_write(struct file* filp, const char __user* buffer, size_t len, loff_t* pos);

//关闭文件
int filp_close(struct file*filp, fl_owner_t id);
````
## 内核模块
//内核模块名是obj-m := hell.o 确定的
## 一种内核调试方法(dump_stack)
需要两个头文件
#include <linux/kprobes.h>
#include <asm/traps.h>

在需要的地方加入
dump_stack()


