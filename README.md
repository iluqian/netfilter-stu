# netfilter-stu
学习netfilter

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
