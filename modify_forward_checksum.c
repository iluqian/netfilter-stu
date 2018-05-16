#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <net/tcp.h>

#define ETHLEN 14 

MODULE_LICENSE("GPL");
MOUULE_AUTHOR("liujie");

static struct nf_hook_ops nfho;

//回调函数的处理
unsigned int checksum(unsigned int hooknum, struct sk_buff * __skb, const struct net_device * in,
				const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	struct sk_buff *skb;
	struct net_device *dev;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int tol_len;
	int iph_len;
	int tcph_Len;
	int ret;

	skb = __skb;
	if(skb == NULL)
			return NF_ACCEPT;
	iph = ip_hdr(skb);
	if(iph == NULL)
			return NF_ACCEPT;
	tol_len = ntohs(iph->tot_len);
	
	if(iph->daddr == in_aton("192.168.26.9"))
	{
		iph_len = ip_hdrlen(skb);// ip.h
		skb_pull(skb, iph_len);//skb_data 指针指到了传输层,去掉skb的ip协议头部
		skb_reset_transport_header(skb);
		if (iph->protocol == IPPROTO_TCP)
		{
			tcph = tcp_hdr(skb);
			tcph_len = tcp_hdrlen(skb);
			 if (tcph->dest == htons(80)) //根据自己得需求来进行过滤数据包
			 {
					 iph->saddr = in_aton("192.168.0.10");
					 dev = dev_get_by_name(&init_net, "eth0");
					 /*
					  *参考net/sched/act_csum.c
					  static int tcf_csum_ipv4_icmp(struct sk_buff *skb,
					  			      unsigned int ihl, unsigned int ipl)
					 	icmph->checksum = 0;
						skb->csum = csum_partial(icmph, ipl - ihl, 0);
						icmph->checksum = csum_fold(skb->csum);
					 */
					 tcph->check = 0;
					 skb->csum = csum_partial((unsigned char *)tcph, tot_len - iph_len, 0);
					 tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr,ntohs(iph->tot_len) - iph_len, iph->protocol,skb->csum);
					 iph->check = 0;
					 iph->check = ip_fast_csum(iph, iph->ihl);
					 skb->ip_summed = CHECKSUM_NONE;
					 skb->pkt_type = PACKET_OTHERHOST;
					 skb->dev = dev;
					 skb_push(skb, iph_len); /*在返回之前，先将skb中得信息恢复至原始L3层状态*/
					 skb_push(skb, ETHALEN);//将skb->data指向l2层，之后将数据包通过 dev_queue_xmit()发出

					  ret = dev_queue_xmit(skb);
					  if (ret < 0)
					  {
					  
					  printk("dev_queue_xmit() error\n");
					  goto out;
					  }
						return NF_STOLEN;
			 }

		}
		skb_push(skb, iph_len);//在返回之前先将skb中的信息恢复至原始3层状态
		skb_reset_transport_header(skb);

	
	}
	return NF_ACCPET;
out:
	dev_put(dev);
	
	return NF_DROP;
}

static int __init filter_init(void)
{
	int ret;
	nfho.hook = checksum;
	nfho.pf = PF_INET;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.priority = NF_IP_PRI_FIRST;

	ret = nf_register_hook(&nfho);
	if(ret < 0){
		printk("can't modify skb hook\n");
		return ret;
	}

	return 0;
}
static void filter_fini(void)
{
	nf_unregister_hook(&nfho);

}

moudule_init(filter_init);
moudule_exit(filter_fini);




