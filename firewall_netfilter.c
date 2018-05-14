
#define __KERNEL__
#define MODULE
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
static struct nf_hook_ops netfilter_ops;
static unsigned char *ip_address = "\xC0\xA8\x00\x01";
static char *interface ="lo";
unsigned char *port ="\x00\x17";
struct sk_buff *sock_buff;
struct udphdr *udp_header;

/* Function prototype in <linux/netfilter> */
unsigned int main_hook(unsigned int hooknum,  
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{
	const struct iphdr *iph = ip_hdr(skb);
	if(strcmp(in->name,interface) == 0){ return NF_DROP; }     
	//sock_buff = skb;
    if(!skb){ return NF_ACCEPT; }                   
	if(!(iph->protocol)){ return NF_ACCEPT; }              
	if(iph->saddr == *(unsigned int*)ip_address){ return NF_DROP; }
		   
	if(iph->protocol != 17){ return NF_ACCEPT; }                 
	udp_header = (struct udphdr *)(skb->data + (iph->ihl *4)); 
	if((udp_header->dest) == *(unsigned short*)port){ return NF_DROP; }
return NF_ACCEPT;
}
int init_module()
{
        netfilter_ops.hook                   =       main_hook;
        netfilter_ops.pf                     =       PF_INET;
        netfilter_ops.hooknum                =       NF_INET_PRE_ROUTING;
        netfilter_ops.priority               =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops); /* register NF_INET_PRE_ROUTING hook */
return 0;
}
void cleanup_module()
{
	nf_unregister_hook(&netfilter_ops); /*unregister NF_IP_PRE_ROUTING hook*/
}
