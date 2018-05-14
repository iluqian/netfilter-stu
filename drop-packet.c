
#define __KERNEL__
#define MODULE
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
static struct nf_hook_ops netfilter_ops_in; /* NF_IP_PRE_ROUTING */
static struct nf_hook_ops netfilter_ops_out; /* NF_IP_POST_ROUTING */
/* Function prototype in <linux/netfilter> */
unsigned int main_hook(unsigned int hooknum,  
                  struct sk_buff **skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
return NF_DROP; /* Drop ALL Packets */
}

//插入模块报错module license 'unspecified' taints kernel
//因为其中一个xxx.o和模块目标文件重名了
int init_module()
{
        netfilter_ops_in.hook                   =       main_hook;
        netfilter_ops_in.pf                     =       PF_INET;
        netfilter_ops_in.hooknum                =       NF_INET_PRE_ROUTING;
        netfilter_ops_in.priority               =       NF_IP_PRI_FIRST;
        netfilter_ops_out.hook                  =       main_hook;
        netfilter_ops_out.pf                    =       PF_INET;
        netfilter_ops_out.hooknum               =       NF_INET_POST_ROUTING;
        netfilter_ops_out.priority              =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops_in); /* register NF_IP_PRE_ROUTING hook */
        nf_register_hook(&netfilter_ops_out); /* register NF_IP_POST_ROUTING hook */
return 0;
}
//void cleanup() 如果写成这样模块将无法卸载
void cleanup_module()
{
	nf_unregister_hook(&netfilter_ops_in); /*unregister NF_IP_PRE_ROUTING hook*/
	nf_unregister_hook(&netfilter_ops_out); /*unregister NF_IP_POST_ROUTING hook*/
}
