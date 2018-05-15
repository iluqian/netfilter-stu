# netfilter-stu
## 学习netfilter
````
//五个hook点
enum nf_inet_hooks {  
		    NF_INET_PRE_ROUTING,  
		    NF_INET_LOCAL_IN,  
		    NF_INET_FORWARD,  
		    NF_INET_LOCAL_OUT,  
		    NF_INET_POST_ROUTING,  
		    NF_INET_NUMHOOKS  
};
//支持的协议类型
enum {  
		    NFPROTO_UNSPEC = 0,  
		    NFPROTO_IPV4 = 2,  
		    NFPROTO_ARP = 3,  
		    NFPROTO_BRIDGE = 7,  
		    NFPROTO_IPV6 = 10,  
		    NFPROTO_DECNET = 12,  
		    NFPROTO_NUMPROTO,  
}; 
//钩子函数
typedef unsigned int nf_hookfn(unsigned int hooknum,  
				                 struct sk_buff *skb,  
								  const struct net_device *in,  
								    const struct net_device *out,  
								        int (*okfn) (struct sk_buff *));  
  
/* 处理函数返回值 */  
#define NF_DROP 0 /* drop the packet, don't continue traversal */  
#define NF_ACCEPT 1 /* continue traversal as normal */  
#define NF_STOLEN 2 /* I've taken over the packet, don't continue traversal */  
#define NF_QUEUE 3 /* queue the packet (usually for userspace handling) */  
#define NF_REPEAT 4 /* call this hook again */  
#define NF_STOP 5  
#define NF_MAX_VERDICT NF_STOP  
//netfilter 实例
struct nf_hook_ops {  
		    struct list_head list;  
		    /* User fills in from here down. */  
		    nf_hookfn *hook; /* 要注册的钩子函数 */  
		    struct module *owner;  
		    u_int8_t pf; /* 协议类型 */  
		    unsigned int hooknum; /* 哪个钓鱼台 */  
		    /* Hooks are ordered in asending priority. */  
		    int priority; /* 数值越小，优先级越高 */  
};  
//注册和注销
/* Functions to register/unregister hook points. */  
int nf_register_hook(struct nf_hook_ops *reg);  
void nf_unregister_hook(struct nf_hook_ops *reg); 

//实现，定义了一个全局链表
struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];  
EXPORT_SYMBOL(nf_hooks);  
static DEFINE_MUTEX(nf_hook_mutex);

//1.注册函数 注册函数会把nf_hook_ops放入nf_hooks相应的位置中。
int nf_register_hook(struct nf_hook_ops *reg)  
{  
		    struct nf_hook_ops *elem;  
		    int err;  
		    err = mutex_lock_interruptible(&nf_hook_mutex);  
		    if (err < 0)  
			        return err;  
		  
		    list_for_each_entry(elem, &nf_hooks[reg->pf][reg->hooknum], list) {  
		        if (reg->priority < elem->priority)  
				            break;  
		    }  
		    list_add_rcu(&reg->list, elem->list.prev); /* 把netfilter实例添加到队列中 */  
		    mutex_unlock(&nf_hook_mutex);  
			return 0;  
}
//2. 注销函数，把netfiler实例从队列中删除
void nf_unregister_hook(struct nf_hook_ops *reg)  
{  
		    mutex_lock(&nf_hook_mutex);  
		    list_del_rcu(&reg->list); /* 把netfilter实例从队列中删除 */  
		    mutex_unlock(&nf_hook_mutex);  
		    synchronize_net();  
}  
````
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


