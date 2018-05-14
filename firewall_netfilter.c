/*
We start with the #define and #include statements. Next, we declare an nf_hook_ops and an IP address (192.168.0.1) in network byte 
order. We also declare a char* called "lo" for the loopback interface, which we want to block. We also declare a char* for port 23,
the telnet port. The last globals are a pointer to a socket kernel buffer and a pointer to a UDP header.

 The hook function is where we do the real work. In our first statement, we compare the name of the device the packet came from to
 our char* interface. If the device is the loopback device, we return NF_DROP. In other words, we drop the packet. 
 That's all that is involved with filtering by interface. We easily could have filtered packets from the Ethernet device 
 by replacing <coe>lo with eth0 in the char* interface declaration.

 Next, we filter by IP address and use the sk_buff to check for an IP address. We first check to see if we have a valid sk_buff, 
 then we validate the IP packet, and finally we compare IP addresses.

 Our last filtering technique is by protocol and/or port. Here we decide to filter by UDP port. First we check to see if we have a 
 valid UDP packet. If we do, we copy the packet's UDP struct to our own. Finally, 
 we compare the packet's UDP port with port 23 (telnet). 
 If all else fails, the hook function returns NF_ACCEPT and the packet goes on its merry way through the network stack. 
  */
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
