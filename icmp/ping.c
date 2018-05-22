#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <errno.h>  
#include <sys/socket.h>/*recvfrom() & sendto()*/  
#include <signal.h>/*信号处理*/  
#include <netinet/in.h>/*protocol参数形如IPPROTO_XXX的常值*/  
#include <netinet/ip.h>/*ip帧头定义*/  
#include <netinet/ip_icmp.h>/*icmp帧头定义*/  
#include <sys/time.h>/*gettimeofday()*/  
#include <time.h>/**/  
  
#define uchar unsigned char  
#define ushort unsigned short  
#define MAXLINE 2048  


#define PERIOD 3
#define MAXLINE 2048
#define DEFAULT_LEN 56
unsigned char sendBuf[MAXLINE] ;
unsigned char recvBuf[MAXLINE];
struct sockaddr_in destAddr;
unsigned int seq = 0;
int sockfd;
void alarm_send(int signo);
void send_pack();
void receive_pack(int sockfd);
void icmp_pack();
unsigned short checksum(unsigned char*buf, unsigned int len);//对每16位进行反码求和（高位溢出位会加到低位），即先对每16位求和，在将得到的和转为反码
int main(int argc, char *argv[])
{
	if( argc < 2)
	{
		printf("need ip to ping\n");
		exit(1);
	}
	if( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		perror("socket:"); 	
		exit(1);
	}

	memset(&destAddr, 0, sizeof(destAddr));
	destAddr.sin_family = AF_INET;
	if( inet_pton(AF_INET, argv[1], &destAddr.sin_addr) != 1)//只能ping ip，不能ping地址。
	{
		perror("inet_pton:");
		exit(1);
	}

	//下面这句开启的话，发送之前就要自己造ip首部。
	//int on = 1;
	//setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(int));
	
	//信号处理
	struct sigaction newact, oldact;
	newact.sa_handler = alarm_send;
	sigemptyset(&newact.sa_mask);
	newact.sa_flags = 0;
	sigaction(SIGALRM, &newact, &oldact);
	alarm(PERIOD);

	receive_pack(sockfd);
	
}

void icmp_pack()
{
	int i;
	struct icmp *icmp;
	pid_t pid = getpid();
	memset(sendBuf, 0, MAXLINE);
	icmp = (struct icmp*)sendBuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = seq++;
	struct timeval *tvstart;
	tvstart = (struct timeval*)icmp->icmp_data;
	gettimeofday(tvstart, NULL);
	icmp->icmp_cksum = checksum((unsigned char*)icmp, DEFAULT_LEN+8);

}
void send_pack()
{
	icmp_pack();
	sendto(sockfd, sendBuf, DEFAULT_LEN+8, 0, (struct sockaddr*)&destAddr, sizeof(destAddr));

}
void receive_pack(int sockfd)
{
	int n = 0;
	struct ip *p_ip;
	struct icmp *p_icmp;
	unsigned short len_iphd, len_icmp;
	char ip_source[INET_ADDRSTRLEN];
	unsigned short sum_recv, sum_cal;
	struct timeval *tvstart, *tvend;
	tvend = malloc(sizeof( sizeof(struct timeval)) );
	double delt_sec;
	while(1)
	{

		memset(recvBuf, 0, MAXLINE);	
		n = recvfrom(sockfd, recvBuf, MAXLINE, 0, NULL, NULL);//接收通过网卡的信息。
		if(n < 0)
		{
			if(errno == EINTR)//interrupted system call
				continue;
			else
			{
				perror("recvform");
				exit(1);	
			}
		}
		gettimeofday(tvend, NULL);

		p_ip = (struct ip*)recvBuf;
		len_iphd = (p_ip->ip_hl)*4;

		len_icmp =  ntohs(p_ip->ip_len)-len_iphd;

		p_icmp = (struct icmp*)((unsigned char*)p_ip + len_iphd);//必须强制转换
		sum_recv = p_icmp->icmp_cksum;
		p_icmp->icmp_cksum = 0;

		sum_cal = checksum( (unsigned char*)p_icmp, len_icmp);
		if(sum_cal != sum_recv)
		{
			printf("checksum error\tsum_recv = %d\tsum_cal = %d\n",sum_recv, sum_cal);
		}
		else
		{
			
			switch(p_icmp->icmp_type)
			{
				case ICMP_ECHOREPLY:
					{

						pid_t pid_now, pid_rev;
						pid_rev = (p_icmp->icmp_id);
						pid_now = getpid();
						if(pid_rev != pid_now )
						{
							printf("pid not match!pin_now = %d, pin_rev = %d\n", pid_now, pid_rev);
						}
						inet_ntop(AF_INET, (void*)&(p_ip->ip_src), ip_source, INET_ADDRSTRLEN);
						tvstart = (struct timeval*)p_icmp->icmp_data;
						delt_sec = (tvend->tv_sec - tvstart->tv_sec) + (tvend->tv_usec - tvstart->tv_usec)/1000000.0;
						printf("%d bytes from %s: icmp_req=%d ttl=%d time=%4.2f ms\n", len_icmp, ip_source, p_icmp->icmp_seq, p_ip->ip_ttl, delt_sec*1000);//想用整型打印的话必须强制转换！
						break;
					}
				case ICMP_TIME_EXCEEDED:
					{
						printf("time out!\n");
						break;
					}
				case ICMP_DEST_UNREACH:
					{
						inet_ntop(AF_INET, (void*)&(p_ip->ip_src), ip_source, INET_ADDRSTRLEN);
						printf("From %s icmp_seq=%d Destination Host Unreachable\n", ip_source, p_icmp->icmp_seq);
						break;
					}
			}
		}
	}


}
unsigned short checksum(unsigned char*buf, unsigned int len)//对每16位进行反码求和（高位溢出位会加到低位），即先对每16位求和，在将得到的和转为反码
{
	unsigned long sum = 0; 
	unsigned short *pbuf;
	pbuf = (unsigned short*)buf;//转化成指向16位的指针
	while(len > 1)//求和
	{
		sum+=*pbuf++;
		len-=2;
	}
	if(len)//如果len为奇数，则最后剩一位要求和
		sum += *(unsigned char*)pbuf;
	sum = (sum>>16)+(sum & 0xffff);//
	sum += (sum>>16);//上一步可能产生溢出
	return (unsigned short)(~sum);
}
void alarm_send(int signo)
{
	send_pack();
	alarm(PERIOD);
	return;
}