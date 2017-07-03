#define WIN32
#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#include <pcap/pcap.h>
#include <sys/types.h>
#include <pcap-bpf.h>
#define WIN32
#define HAVE_REMOTE
#include "pcap.h"
#include "Win32-Extensions.h"
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <pcap.h>
#include <winsock.h>
#include <time.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#include<iostream.h>
#define IPVER   4           //IP协议预定
#define MAX_BUFF_LEN 65500  //发送缓冲区最大值
#define DEST_PORT 5050    //目的端口号
#define SOUR_PORT 8080    //源端口号
#define LINE_LEN 16
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, ".\\wpdpack\\Packet.lib")
#pragma pack(push, 1)                        // 位移

#define ICMP_ECHOREPLY	0
#define ICMP_ECHOREQ	8
#define REQ_DATASIZE 32
//typedef  unsigned char u_char;
//typedef  unsigned short u_short;
// IP Header -- RFC 791
typedef struct tagIPHDR		//IP报头
{
	u_char  VIHL;			// Version and IHL
	u_char	TOS;			// Type Of Service
	u_short	TotLen;			// Total Length
	u_short	ID;				// Identification
	u_short	FlagOff;		// Flags and Fragment Offset
	u_char	TTL;			// Time To Live
	u_char	Protocol;		// Protocol
	u_short	Checksum;		// Checksum
	unsigned int iaSrc;	// Internet Address - Source
	unsigned int iaDst;	// Internet Address - Destination
}IPHDR, *PIPHDR;

// ICMP Header - RFC 792
typedef struct tagICMPHDR	//ICMP报头
{
	u_char	Type;			// Type
	u_char	Code;			// Code
	u_short	Checksum;		// Checksum
	u_short	ID;				// Identification
	u_short	Seq;			// Sequence
}ICMPHDR, *PICMPHDR;
/*
//定义ICMP首部
typedef struct _icmphdr{
unsigned char i_type; //8位类型
unsigned char i_code; //8位代码
unsigned short i_cksum; //16位校验和, 从TYPE开始,直到最后一位用户数据,如果为字节数为奇数则补充一位
unsigned short i_id ; //识别号（一般用进程号作为识别号）, 用于匹配ECHO和ECHO REPLY包
unsigned short i_seq ; //报文序列号, 用于标记ECHO报文顺序
unsigned int timestamp; //时间戳!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
}ICMP_HEADER;
 */
// ICMP Echo Reply
typedef struct tagICMPPACK		//ICMP报头+报文
{
	ICMPHDR icmpHdr;
	char	Data[REQ_DATASIZE];
}ICMPPACK,*PICMPPACK;

	// Echo Request Data size

// ICMP Echo Request
typedef struct tagECHOREQUEST		//发送数据格式
{   IPHDR   iphdr;
	ICMPPACK icmpPack;
}ECHOREQUEST, *PECHOREQUEST;

typedef struct tagRECHOREQUEST		//第二分片发送数据格式
	{   IPHDR   iphdr;
	    char	Data[REQ_DATASIZE/2];
}RECHOREQUEST, *PRECHOREQUEST;

typedef struct tagECHOREPLY			//接收
{
	IPHDR	ipHdr;
	ICMPHDR icmpHdr;
	char    cFiller[256];		//IP头+ICMP请求报文+填充数据
}ECHOREPLY, *PECHOREPLY;



u_short  in_cksum(u_short *addr, int len);
void genICMPPacket(pcap_t *_adhandle,int packetNumber);

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret=-1;
//以下为打开某个网卡
/* Retrieve the device list from the local machine */
if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,
&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
 /* Print the list */

    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }


    printf("Enter the interface number (1-%d):",i);

    int input_NetInterface_number;
    scanf("%d", &input_NetInterface_number);

    if(input_NetInterface_number < 1 || input_NetInterface_number > i)
    {
        printf("\nInterface number out of range.\n");

        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i< input_NetInterface_number-1 ;d=d->next, i++);
//adhandle is a adaptor handler
/* Open the output device */
if ( (adhandle= pcap_open(d->name, 65536,
PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL,errbuf) )
== NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    printf("input the number of packets\n");
    int packet_number;
    scanf("%d",&packet_number);
    genICMPPacket(adhandle,packet_number);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    pcap_close(adhandle);
    pcap_freealldevs(alldevs);

    return 0;
}

void genICMPPacket(pcap_t *_adhandle,int packetNumber)
{
char pDest[32];		//目的IP地址
char pSors[32];		//源IP地址
/*
printf("请输入本机IP地址:");
scanf("%s",&pSors);
printf("\n请输入目标的IP地址：");
scanf("%s",&pDest);
*/
strcpy(pSors , "222.20.40.25");
strcpy(pDest , "222.20.40.25");

static ECHOREQUEST echoReq;
static ICMPPACK icmpPack;
static RECHOREQUEST rEchoReq;
static int nId = 6;
static int nSeq = 6;
static int ipid=6;

int nRet=0;

echoReq.iphdr.VIHL=(4<<4 | sizeof(IPHDR)/sizeof(unsigned long));// 4位首部长度+4位IP版本号
echoReq.iphdr.TOS =0;						//8位的服务类型tos
echoReq.iphdr.TotLen=htons(sizeof(ECHOREQUEST)+REQ_DATASIZE/2);	//ip报文长度
echoReq.iphdr.ID	=ipid++;			//ip头的标识位
echoReq.iphdr.FlagOff=0x0000;				//标志和片偏移量
echoReq.iphdr.TTL=128;						//生存时间
echoReq.iphdr.Protocol=IPPROTO_ICMP;		//协议类型
echoReq.iphdr.Checksum=0;						//校验和，程序自动填充
echoReq.iphdr.iaSrc =inet_addr(pSors);	//本机IP
echoReq.iphdr.iaDst=inet_addr(pDest);	//目的IP
// Fill in echo request
echoReq.icmpPack.icmpHdr.Type		= ICMP_ECHOREQ;  //类型8是于ping的请求回显报文！！！！！type code不能写死，不同用途的icmp报文的不一样
echoReq.icmpPack.icmpHdr.Code		= 0;			 //代码0
echoReq.icmpPack.icmpHdr.Checksum	= 0;			 //校验和0，后面填充
echoReq.icmpPack.icmpHdr.ID			= nId++;		 //标识
echoReq.icmpPack.icmpHdr.Seq		= nSeq++;		 //序号
///////////////////////////////////
/*
struct timeval *sendtime;
sendtime = (struct timeval *)icmp->data;
struct timeval recvtime;
gettimeofday((struct timeval *)icmp_hdr->data, NULL);
gettimeofday(tval,NULL);    //记录发送时间
 gettimeofday(&tvrecv,NULL);  //记录接收时间
gettimeofday(&recvtime, NULL);//记录接收时间
/////////////////////
int gettimeofday(struct timeval *tp,void *tzp)
其中timeval结构如下：
		struct timeval{
			long tv_sec;
			long tv_usec;
		}
		tv_sec为秒数，tv_usec微秒数。在发送和接收报文时由gettimeofday分别生成两个timeval结构
		两者之差即为往返时间,即 ICMP报文发送与接收的时间差，
而timeval结构由ICMP数据报携带,tzp指针表示时区，一般都不使用，赋NULL值。
*/
/////////////////////////////////////////////////////
	// Fill in some data to send
	//分片部分
	int choice=1;
	if(choice==1)			//选择为1时，为分片发送
		{
			echoReq.iphdr.FlagOff=0x0020;
		for (nRet = 0; nRet < REQ_DATASIZE/2; nRet++)	  //填入可选数据,这里填入了16个字节
			echoReq.icmpPack.Data[nRet] = 'a';
		for (; nRet < REQ_DATASIZE; nRet++)	  //填入可选数据,这里填入了16个字节
			echoReq.icmpPack.Data[nRet] = 'b';
		echoReq.icmpPack.icmpHdr.Checksum= in_cksum((u_short *)&echoReq.icmpPack, sizeof(ICMPPACK));	//进行ICMP的校验和计算并填入，校验和覆盖整个ICMP报文，不包括伪首部
		/* nRet = sendto(s,						// socket
				 (LPSTR)&echoReq,			//buffer
				 sizeof(ECHOREQUEST)-16,
				 0,							// flags
				 (LPSOCKADDR)lpstToAddr, // destination
				 sizeof(SOCKADDR_IN));   // address length
		*/
	for(int k = 0; k < packetNumber; k++)
    if ( 0 != (pcap_sendpacket(_adhandle,(LPSTR)&echoReq, sizeof(ECHOREQUEST))) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send successfully without storing packets\n");
    }
    system("pause");
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		echoReq.iphdr.FlagOff=0x0300;
		rEchoReq.iphdr=echoReq.iphdr;
		for (nRet=0; nRet < REQ_DATASIZE/2; nRet++)	  //填入可选数据,这里填入了16个字节
			rEchoReq.Data[nRet]=echoReq.icmpPack.Data[nRet+16];
		/* nRet = sendto(s,						// socket
				 (LPSTR)&rEchoReq,			// buffer
				 sizeof(RECHOREQUEST),
				 0,							// flags
				 (LPSOCKADDR)lpstToAddr, // destination
				 sizeof(SOCKADDR_IN));   // address length
		*/
	for(int k = 0; k < packetNumber; k++)
    if ( 0 != (pcap_sendpacket(_adhandle,(LPSTR)&echoReq, sizeof(ECHOREQUEST))) )//！！！！！！！！！！！！！！！！！！
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send successfully without storing packets\n");
    }
    system("pause");
			}
		else if(choice==2)				//选择为2时，为分片重叠发送
			{
			echoReq.iphdr.FlagOff=0x0020;
			for (nRet = 0; nRet < REQ_DATASIZE/2; nRet++)	  //这里填入了16个字节
			echoReq.icmpPack.Data[nRet] = 'a';
			for (; nRet < REQ_DATASIZE; nRet++)	  //这里填入了16个字节
			echoReq.icmpPack.Data[nRet] = 'b';
			echoReq.icmpPack.icmpHdr.Checksum= in_cksum((u_short *)&echoReq.icmpPack, sizeof(ICMPPACK));	//进行ICMP的校验和计算并填入，校验和覆盖整个ICMP报文，不包括伪首部
		/*	nRet = sendto(s,						//socket
				 (LPSTR)&echoReq,			// buffer
				 sizeof(ECHOREQUEST)-8,
				 0,							// flags
				 (LPSOCKADDR)lpstToAddr, //destination
				 sizeof(SOCKADDR_IN));   // address length
		*/
			echoReq.iphdr.FlagOff=0x0300;
			rEchoReq.iphdr=echoReq.iphdr;
			for (nRet=0; nRet <REQ_DATASIZE/2; nRet++)	  //这里填入了16个字节
			rEchoReq.Data[nRet]=echoReq.icmpPack.Data[nRet+16];
		/*
		nRet = sendto(s,						// socket
				 (LPSTR)&rEchoReq,			// buffer
				 sizeof(RECHOREQUEST),
				 0,							// flags
				 (LPSOCKADDR)lpstToAddr, // destination
				 sizeof(SOCKADDR_IN));   // address length
		 */ }
}




/*
 *			I N _ C K S U M
 *
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 */
u_short in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;
	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while( nleft > 1 )  {
		sum += *w++;
		nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if( nleft == 1 ) {
		u_short	u = 0;

		*(u_char *)(&u) = *(u_char *)w ;
		sum += u;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

