//程序1：检测接口的 inet_addr,netmask,broad_addr 
#include <stdio.h> 
#include <string.h> 
#include <stdlib.h> 
#include <errno.h> 
#include <unistd.h> 
 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
 
#include <sys/ioctl.h> 
#include <net/if.h> 
 
static void usage(){ 
        printf("usage : ipconfig interface\n"); 
        exit(0); 
} 
 
int main(int argc,char **argv) 
{ 
        struct sockaddr_in *addr;       //套接字地址结构体 
        struct ifreq ifr;               //用于ioctl 
        char *name, *address;           //网络设备的名字，地址 
        int sockfd;                     //套接子描述符 
 
        if(argc != 2) //参数不够 
                usage(); 
        else 
                name = argv[1]; 
 
 
        sockfd = socket(AF_INET, SOCK_DGRAM, 0); //打开一个数据流套接子 
        strncpy(ifr.ifr_name, name, IFNAMSIZ-1); //限制设备名的长度并截断，防止溢出 
 
 
        if(ioctl(sockfd, SIOCGIFADDR, &ifr)  == -1)     //用 SIOCGIFADDR 来获得接口地址 
                perror("ioctl error"), exit(1);         //描述错误代码 
        addr = (struct sockaddr_in *)&(ifr.ifr_addr); 
        address = inet_ntoa(addr->sin_addr);            //地址转换 
        printf("inet addr: %s \n",address); 
 
 
        if(ioctl(sockfd, SIOCGIFBRDADDR, &ifr)  ==  -1) //用 SIOCGIFBRDADDR 来获得广播地址 
                perror("ioctl error"),exit(1); 
        addr = (struct sockaddr_in *)&ifr.ifr_broadaddr; 
        address = inet_ntoa(addr->sin_addr); 
        printf("broad addr: %s\n",address); 
 
 
        if(ioctl(sockfd, SIOCGIFNETMASK, &ifr) == -1) //用 SIOCGIFNETMASK 来获得掩码地址 
                perror("ioctl error"),exit(1); 
        addr = (struct sockaddr_in *)&ifr.ifr_addr; 
        address = inet_ntoa(addr->sin_addr); 
        printf("inet mask: %s ",address); 
 
        printf("\n"); 
        exit(0); 
} 
