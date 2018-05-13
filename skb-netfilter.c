//'Hello World' netfilter hooks example
//For any packet, we drop it, and log fact to /var/log/messages

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
static struct nf_hook_ops nfho;         //struct holding set of hook function options

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  //struct sk_buff *pskb = *skb;
  //不能使用 pskb->nh.iph->protocol  应为内核升级之后，sk_buff的这个nh共用体没有了
  const struct iphdr *iph = ip_hdr(skb);
  switch(iph->protocol)
  {
  	case IPPROTO_ICMP:
			{
			printk("ICMP packet:DROP\n");
			return NF_DROP;
			}
	case IPPROTO_TCP:
			{
			printk("TCP packet:ACCEPT\n");
			return NF_ACCEPT;
			}
	case IPPROTO_UDP:
			{
			printk("UDP packet:ACCEPT\n");
			return NF_ACCEPT;
			}
	default:
			{
			printk("Unknow packet:DROP\n");
			return NF_DROP;
			}

  
  }
  //printk(KERN_INFO "================packet dropped\n");                              //log to var/log/messages
  //return NF_DROP;                                                                   //drops the packet
}

//Called when module loaded using 'insmod'
int init_module()
{
  nfho.hook = hook_func;                       //function to call when conditions below met

//在内核2.6.22之后的内核中，NF_IP_PRE_ROUTING和NF_IP6_PRE_ROUTING 都被放在用户态，内核态统一使用NF_INET_PRE_ROUTING
  nfho.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho);                     //register hook

  return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);                     //cleanup – unregister hook
}
