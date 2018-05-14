# netfilter-stu
## 学习netfilter

有关移植时解决办法，有些函数的使用，可以参考内核中其他函数是怎么获取协议类型的就可以了

以下代码是当我需要获取协议类型的时候，作的参考 /drivers/net/ethernet/realtek/8139cp.c
````
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

