/*****************************************************************************
Internet路由跟踪程序 Traceroute
    该程序使用UDP包发送一个试探数据报，连续递增改变数据报头的TTL值。TTL每一次“超
时”，都会向我们返回一条ICMP消息（传输超时错误或目的端口不可到达错误），我们只
要查看给我们发送ICMP消息的主机地址，即可知道该数据报经过了哪些主机（路由器）。
    程序中使用了两个套接字，一个是普通的UDP数据报套接字，用IP_TTL选项来改变发送时的
TTL值；另一个是原始套接字，用于接收返回来的ICMP消息。
******************************************************************************/
#include <windows.h>
#include <io.h>
#include <winsock.h>
#include <winsock2.h>
#pragma  comment(lib,"ws2_32.lib")
#pragma  comment(dll," Ws2_32.dll")
#pragma comment(lib,"Wsock32")
#pragma comment(lib,"ws2_32")
#include <WS2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#define MAXPACKET		65535	/* IP包的最大大小*/
#define UDPPACKETSIZE	36	/* UDP数据报的大小*/
#define SRCPORT		23156	/*UDP包的源端口*/
#define DSTPORT		58127	/*UDP包的目的端口*/
#define bzero(a, b)             memset(a, 0, b)
static const int ICMP_MINLEN = 8;
typedef unsigned char u_int8_t;
typedef unsigned int u_int16_t;
typedef unsigned long u_int32_t;
#include "ip_icmp.h"
struct ip
  {
/*#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;               //header length
    unsigned int ip_v:4;                //version
#endif
*/
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;                /* version */
    unsigned int ip_hl:4;               /* header length */
#endif
    u_int8_t ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_int8_t ip_ttl;                    /* time to live */
    u_int8_t ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
  };
struct udphdr
{
u_int16_t source;
u_int16_t dest;
u_int16_t len;
u_int16_t check;
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct icmp
{
  u_int8_t  icmp_type;  /* type of message, see below */
  u_int8_t  icmp_code;  /* type sub code */
  u_int16_t icmp_cksum; /* ones complement checksum of struct */
  union
  {
    u_char ih_pptr;     /* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;   /* gateway address */
    struct ih_idseq     /* echo datagram */
    {
      u_int16_t icd_id;
      u_int16_t icd_seq;
    } ih_idseq;
    u_int32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu
    {
      u_int16_t ipm_void;
      u_int16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv
    {
      u_int8_t irt_num_addrs;
      u_int8_t irt_wpa;
      u_int16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;
#define icmp_pptr   icmp_hun.ih_pptr
#define icmp_gwaddr icmp_hun.ih_gwaddr
#define icmp_id     icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void   icmp_hun.ih_void
#define icmp_pmvoid icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa    icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
  union
  {
    struct
    {
      u_int32_t its_otime;
      u_int32_t its_rtime;
      u_int32_t its_ttime;
    } id_ts;
    struct
    {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
//    struct icmp_ra_addr id_radv;
    u_int32_t   id_mask;
    u_int8_t    id_data[1];
  } icmp_dun;
#define icmp_otime  icmp_dun.id_ts.its_otime
#define icmp_rtime  icmp_dun.id_ts.its_rtime
#define icmp_ttime  icmp_dun.id_ts.its_ttime
#define icmp_ip     icmp_dun.id_ip.idi_ip
#define icmp_radv   icmp_dun.id_radv
#define icmp_mask   icmp_dun.id_mask
#define icmp_data   icmp_dun.id_data
};
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*函数声明*/
double deltaT(struct timeval *t1p,struct timeval *t2p);	/*计算时间差*/
int check_packet(u_char *buf,int  cc); /*检查一个IP包是否期望的ICMP数据报*/
void send_probe(int sndsock,struct sockaddr_in *whereto,int ttl); /*发送一个探测包*/
/*接收ICMP消息*/
int wait_for_reply(int rcvsock,struct sockaddr_in *from,char *databuf,int buflen);
/*主函数*/
int main(/*int argc, char * argv[]*/)
{
     WSADATA WSAData;		//WSADATA数据结构指针
	int WSAreturn;

	const int max_ttl=48;	/*默认的最大跳数*/
	const int nprobes=3;    /*默认的每跳探测次数*/
	//处理命令行，合法的命令行格式为： tracert 主机名或主机IP地址*/
	int argc = 2;
	char argv[2][32];
	//argv[0] = "tracert";
	//argv[1] = "222.20.40.25";
	strcpy(argv[1], "127.0.0.1");
	//argv[1] = "xiaomaju";
	if(argc!=2) {
		fprintf(stderr,"Usage: %s host\r\n",argv[0]);
		exit(-1);
	}
/* wliu comments: modified for windows socket programming */
	WSAreturn = WSAStartup(0x101,&WSAData);		//指定加载的Winsock版本
	if(WSAreturn)		//WSAStartup执行成功以后返回0，非0则打印错误
	{
		fprintf(stderr, " WSA error.\n");
		exit(1);
	}

	struct hostent *host;      /*主机名结构指针*/
	struct sockaddr_in haddr;  /*远程主机地址结构*/
	struct sockaddr_in loc_addr; /*本机地址结构，用于绑定UDP服务于指定的端口*/
	bzero(&haddr,sizeof(haddr));
	/*填充目的主机地址结构*/
	haddr.sin_family=AF_INET;
	haddr.sin_addr.s_addr=inet_addr(argv[1]);
	haddr.sin_port=htons(DSTPORT);
	/*如果是主机名，则查询DNS解析*/
	if(haddr.sin_addr.s_addr==INADDR_NONE){
		if(NULL==(host=gethostbyname(argv[1]))) {
			fprintf(stderr,"unknown host %s\r\n",argv[1]);
			exit(-1);
		}
		memcpy(&haddr.sin_addr,host->h_addr,host->h_length);
	}
	/*填充本机地址结构*/
	loc_addr.sin_family=AF_INET;
	loc_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	loc_addr.sin_port=htons(SRCPORT);
	int sndsock,rcvsock;
	/*创建UDP套接字*/
	if ((sndsock = socket(AF_INET, SOCK_DGRAM,IPPROTO_UDP)) < 0) {
		fprintf(stderr,"traceroute: udp socket\r\n");
		exit(-1);
	}
	/*创建RAW套接字，套接字的类型为IPPROTO_ICMP*/
	if ((rcvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		fprintf(stderr,"traceroute: raw socket\r\n");
		exit(-1);
	}
	/*绑定UDP套接字于指定的端口*/
	if(bind(sndsock,(struct sockaddr*)&loc_addr,sizeof(loc_addr))) {
		fprintf(stderr,"bind error\r\n");
		exit(-1);
	}

	fprintf(stdout, "traceroute to %s (%s)", argv[1],inet_ntoa(haddr.sin_addr));
	fprintf(stdout, ", %d hops max, %d byte packets\r\n", max_ttl,UDPPACKETSIZE+sizeof(struct ip)+sizeof(struct udphdr));

	char databuf[MAXPACKET];	/*接收ICMP数据报的缓冲区*/
	struct sockaddr_in from;	/*远程主机地址结构*/
	int ttl;
	//循环改变发送的UDP数据报的TTL值，发送探测数据包*/
	for (ttl = 1; ttl <= max_ttl; ++ttl) {
		u_long lastaddr = 0;	/*记录上一个接收到的数据包的源地址*/
		int got_there = 0;		/*记录是否到达了目的主机*/

		printf("%2d ", ttl);
		fflush(stdout);
		int  probe;
		/*每一跳（TTL值）循环发送nprobes个数据包*/
		for (probe = 0; probe < nprobes; ++probe) {
			int cc=0;
			struct timeval t1, t2;	/*记录发送和接收的时间*/
			struct timezone tz;
			struct ip *ip;

			gettimeofday(&t1, &tz);	/*记录发送时间*/
			send_probe(sndsock,&haddr,ttl); /*发送一个UDP数据包*/
			/*在指定的时间内等待回复的ICMP包，直到超时*/
			while (cc = wait_for_reply(rcvsock, &from,databuf,sizeof(databuf))) {
				gettimeofday(&t2, &tz); /*记录接收时间*/
				if (check_packet(databuf, cc)) { /*检查是否期待的ICMP数据报*/
					/*判断是否是上一跳主机返回的数据包，不是的话输出其IP地址*/
					if (from.sin_addr.s_addr != lastaddr) {
						printf("%s  ",inet_ntoa(from.sin_addr));
						lastaddr = from.sin_addr.s_addr;
					}
					/*计算发送和接收数据包之间的间隔，并显示出来*/
					printf("  %g ms  ", deltaT(&t1, &t2));
					/*判断是否到达最终的目的地，是 的话做出标记*/
					if(from.sin_addr.s_addr==haddr.sin_addr.s_addr)
						got_there++;
					break;
				}
			}
			if (cc == 0) /*cc等于零意味着等待超时，该跳主机没有回应*/
				printf("   *   ");
		}
		printf("\r\n");
		/*如果达到目的地，则退出循环*/
		if (got_there)
			break;
	}
	/* wliu comments: modified for windows socket programming */
	WSACleanup();
	system("pause");
	return 1;
}
/***********************************************************************************
函数：    等待ICMP消息
rcvsock:  接收消息的套接字句柄
from:     远程主机地址结构的地址
databuf:  接收消息的缓冲区首地址
buflen:   消息缓冲区的长度
***********************************************************************************/
 int wait_for_reply(int rcvsock,struct sockaddr_in *from,char *databuf,int buflen)
{
	const int waittime=4;		/*默认超时时间为 4 秒*/

	int cc = 0;
	int fromlen = sizeof (*from);
	/*套接字IO参数*/
	fd_set fds;  /* 套接字I/O集合*/
	FD_ZERO(&fds);
	FD_SET(rcvsock, &fds); /*把rcvsock加入到集合fds中*/
	/*（超时）时间结构*/
	struct timeval wait;
	wait.tv_sec = waittime;
	wait.tv_usec = 0;
	/*选择一个集合fds，并查看该集合中的套接字是否存在待决的I/O操作（我们这里是读取操作）*/
	/*默认等待时间为4秒*/
	if (select(rcvsock+1, &fds, (fd_set *)0, (fd_set *)0, &wait) > 0) {
		/*有数据可读，读取到指定的缓冲区中*/
		cc=recvfrom(rcvsock, databuf, buflen, 0,
			    (struct sockaddr *)from, &fromlen);
	}

	return(cc);
}
/**********************************************************************************
函数：    向指定的地址发送一个UDP数据报
sndsock:  发送数据报套接字
whereto:  目的主机地址结构指针
ttl:      发送数据包的TTL值
**********************************************************************************/
void send_probe(int sndsock,struct sockaddr_in *whereto,int ttl)
{
	char databuf[UDPPACKETSIZE];		/*发送数据包缓冲区（数据部分）*/
	bzero(databuf,sizeof(databuf));
	/*设置发送套接字的选项（IPPROTO_IP级，IP_TTL类型），更改IP包头中的TTL为指定值*/
	setsockopt(sndsock,IPPROTO_IP,IP_TTL,(char *)&ttl,sizeof(ttl));
	/*发送数据包（携带UDPPACKETSIZE个字节的零）*/
	int n = sendto(sndsock, databuf, sizeof(databuf), 0,(struct sockaddr *)whereto,
		   sizeof(struct sockaddr));
	if(n!=UDPPACKETSIZE) {
		fprintf(stderr,"Error in sendto\r\n");
	}
}
/**********************************************************************************
函数： 检查一个返回的IP包是否为期待的ICMP数据报（TTL超时或者目的端口不可到达）
buf:   数据缓冲区首地址
cc:    缓冲区中数据大小
**********************************************************************************/
int check_packet(u_char *buf,int  cc)
{
	/*处理IP包头*/
	struct ip *ip= (struct ip *) buf;
	/*计算IP头大小*/
	int hlen = ip->ip_hl << 2;
	/*从大小来判断是否是一个ICMP包*/
	if (cc < hlen + ICMP_MINLEN) {
		return 0;
	}
	cc -= hlen;
	/*处理ICMP头部*/
	struct icmp *icp= (struct icmp *)(buf + hlen);
	u_char type=icp->icmp_type;	/*ICMP消息类型*/
	u_char code=icp->icmp_code; /*ICMP消息代码*/
	/*期待的ICMP消息只有两种：传输超时（TTL变为0），目的端口不可到达（已经到了目的主机）*/
	if(type==ICMP_TIMXCEED || type==ICMP_UNREACH) {
		struct ip *hip=&icp->icmp_ip;
		hlen=hip->ip_hl<<2;
		/*ICMP数据报会发回出错的数据报的IP头部和该IP数据报的头8个字节
		我们检查该数据报的目的端口和源端口，看是否是我们发送的测试数据报*/
		struct udphdr *udp=(struct udphdr *)((u_char *)hip+hlen);
		if(hip->ip_p==IPPROTO_UDP && udp->dest==htons(DSTPORT) &&
			udp->source==htons(SRCPORT))
		/*if(hip->ip_p==IPPROTO_UDP && udp->uh_dport==htons(DSTPORT) &&
			udp->uh_sport==htons(SRCPORT))*/
				return 1;
	}
	return 0;
}
/**********************************************************************************
函数： 计算两个timeval结构表示的时间差值
**********************************************************************************/
double deltaT(struct timeval *t1p,struct timeval *t2p)
{
	double dt;

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
	     (double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
	return (dt);
}
