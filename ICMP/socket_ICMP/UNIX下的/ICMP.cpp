//
// PING.C -- Ping program using ICMP and RAW Sockets
//

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/types.h>
#include <errno.h>
#include "ping.h"
#pragma comment(lib,"WS2_32.lib")

// Internal Functions
void Ping(LPCSTR pstrHost,int choice);
void ReportError(LPCSTR pstrFrom);
int  WaitForEchoReply(SOCKET s);
u_short in_cksum(u_short *addr, int len);

char pDest[30];		//目的IP地址
char pSors[30];		//源IP地址


// ICMP Echo Request/Reply functions
int		SendEchoRequest(SOCKET, LPSOCKADDR_IN,int choice);		//发送
void    RecvEchoReply(SOCKET, LPSOCKADDR_IN, u_char *);			//接收

// main()
int main(int argc, char **argv)
{
    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2,2);
    int nRet;
	int choice=0;

	// Init WinSock
    nRet = WSAStartup(wVersionRequested, &wsaData);
    if (nRet)
    {
		fprintf(stderr,"\nError initializing WinSock\n");
		return 0;
    }

	// Check version
	if (wsaData.wVersion != wVersionRequested)
	{
		fprintf(stderr,"\nWinSock version not supported\n");
		return 0;
	}
	printf("请输入本机IP地址:");
	scanf("%s",&pSors);
	printf("\n请输入目标的IP地址：");
	scanf("%s",&pDest);
	printf("\n****** 1：分片ICMP ECHO请求发送 2：重叠分片 ******\n");	printf("************************************************************\n");
	scanf("%d",&choice);
	Ping(pDest,choice);		//PING过程
	system("pause");
    WSACleanup();
    return 0;
}
// Ping()
// Calls SendEchoRequest() and
// RecvEchoReply() and prints results
void Ping(LPCSTR pstrHost,int choice)
{
	LPHOSTENT lpHost;
	struct    sockaddr_in saDest;
	struct    sockaddr_in saSrc;
	DWORD	  dwElapsed;
	u_char    cTTL;
	int       nLoop;
	int       nRet;
	DWORD  sTime=0;
	SOCKET rawSocket;
	rawSocket = socket(AF_INET,SOCK_RAW,IPPROTO_IP);
	BOOL blnFlag=TRUE;
	setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, (char *)&blnFlag, sizeof(blnFlag));

	lpHost = gethostbyname(pstrHost);
	if (lpHost == NULL)
	{
		fprintf(stderr,"\nHost not found: %s\n", pstrHost);
		return;
	}

	// Setup destination socket address
	saDest.sin_addr.s_addr = *((u_long FAR *) (lpHost->h_addr));
	saDest.sin_family = AF_INET;
	saDest.sin_port = 0;

	// Tell the user what we're doing


	printf("\nPinging %s [%s] with %d bytes of data:\n",
				pstrHost,
				inet_ntoa(saDest.sin_addr),
				REQ_DATASIZE);

	// Ping multiple times
	for (nLoop = 0; nLoop < 4; nLoop++)			//发送四个PING
	{
		sTime=GetTickCount();					//获得发送时间
		SendEchoRequest(rawSocket, &saDest,choice);


		// Use select() to wait for data to be received
		nRet = WaitForEchoReply(rawSocket);
		if (nRet == SOCKET_ERROR)
		{
			ReportError("select()");
			break;
		}
		if (!nRet)
		{
			printf("\nTimeOut");
			break;
		}

		// Receive reply
		RecvEchoReply(rawSocket, &saSrc, &cTTL);
		// Calculate elapsed time
		dwElapsed = GetTickCount() -sTime;			//获得时延
		printf("\nReply from: %s: bytes=%d time=%ldms TTL=%d",
               inet_ntoa(saSrc.sin_addr),
			   REQ_DATASIZE,
               dwElapsed,
               cTTL);
	}
	printf("\n");
	nRet = closesocket(rawSocket);
	if (nRet == SOCKET_ERROR)
		ReportError("closesocket()");
}
int SendEchoRequest(SOCKET s,LPSOCKADDR_IN lpstToAddr,int choice)
{
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
	echoReq.iphdr.iaDst=lpstToAddr->sin_addr.S_un.S_addr;	//目的IP


	// Fill in echo request
	echoReq.icmpPack.icmpHdr.Type		= ICMP_ECHOREQ;  //类型8
	echoReq.icmpPack.icmpHdr.Code		= 0;			 //代码0
	echoReq.icmpPack.icmpHdr.Checksum	= 0;			 //校验和0，后面填充
	echoReq.icmpPack.icmpHdr.ID			= nId++;		 //标识
	echoReq.icmpPack.icmpHdr.Seq			= nSeq++;		 //序号

	// Fill in some data to send
	//分片部分
	if(choice==1)			//选择为1时，为分片发送
		{
			echoReq.iphdr.FlagOff=0x0020;
		for (nRet = 0; nRet < REQ_DATASIZE/2; nRet++)	  //填入可选数据,这里填入了16个字节
			echoReq.icmpPack.Data[nRet] = 'a';
		for (; nRet < REQ_DATASIZE; nRet++)	  //填入可选数据,这里填入了16个字节
			echoReq.icmpPack.Data[nRet] = 'b';
		echoReq.icmpPack.icmpHdr.Checksum= in_cksum((u_short *)&echoReq.icmpPack, sizeof(ICMPPACK));	//进行ICMP的校验和计算并填入，校验和覆盖整个ICMP报文，不包括伪首部
		nRet = sendto(s,						/* socket */
				 (LPSTR)&echoReq,			/* buffer */
				 sizeof(ECHOREQUEST)-16,
				 0,							/* flags */
				 (LPSOCKADDR)lpstToAddr, /* destination */
				 sizeof(SOCKADDR_IN));   /* address length */
		echoReq.iphdr.FlagOff=0x0300;
		rEchoReq.iphdr=echoReq.iphdr;
		for (nRet=0; nRet < REQ_DATASIZE/2; nRet++)	  //填入可选数据,这里填入了16个字节
			rEchoReq.Data[nRet]=echoReq.icmpPack.Data[nRet+16];
		nRet = sendto(s,						/* socket */
				 (LPSTR)&rEchoReq,			/* buffer */
				 sizeof(RECHOREQUEST),
				 0,							/* flags */
				 (LPSOCKADDR)lpstToAddr, /* destination */
				 sizeof(SOCKADDR_IN));   /* address length */
			}
		else if(choice==2)				//选择为2时，为分片重叠发送
			{
			echoReq.iphdr.FlagOff=0x0020;
			for (nRet = 0; nRet < REQ_DATASIZE/2; nRet++)	  //这里填入了16个字节
			echoReq.icmpPack.Data[nRet] = 'a';
			for (; nRet < REQ_DATASIZE; nRet++)	  //这里填入了16个字节
			echoReq.icmpPack.Data[nRet] = 'b';
			echoReq.icmpPack.icmpHdr.Checksum= in_cksum((u_short *)&echoReq.icmpPack, sizeof(ICMPPACK));	//进行ICMP的校验和计算并填入，校验和覆盖整个ICMP报文，不包括伪首部
			nRet = sendto(s,						/* socket */
				 (LPSTR)&echoReq,			/* buffer */
				 sizeof(ECHOREQUEST)-8,
				 0,							/* flags */
				 (LPSOCKADDR)lpstToAddr, /* destination */
				 sizeof(SOCKADDR_IN));   /* address length */
			echoReq.iphdr.FlagOff=0x0300;
			rEchoReq.iphdr=echoReq.iphdr;
			for (nRet=0; nRet <REQ_DATASIZE/2; nRet++)	  //这里填入了16个字节
			rEchoReq.Data[nRet]=echoReq.icmpPack.Data[nRet+16];
			nRet = sendto(s,						/* socket */
				 (LPSTR)&rEchoReq,			/* buffer */
				 sizeof(RECHOREQUEST),
				 0,							/* flags */
				 (LPSOCKADDR)lpstToAddr, /* destination */
				 sizeof(SOCKADDR_IN));   /* address length */
	}


	if (nRet == SOCKET_ERROR)
		ReportError("sendto()");
	return (nRet);
}
// SendEchoRequest()
// Fill in echo request header
// and send to destination


// RecvEchoReply()
// Receive incoming data
// and parse out fields
void RecvEchoReply(SOCKET s, LPSOCKADDR_IN lpsaFrom, u_char *pTTL)
{
	ECHOREPLY echoReply;
	int nRet;
	int nAddrLen = sizeof(struct sockaddr_in);

	// Receive the echo reply
	nRet = recvfrom(s,					// socket
					(LPSTR)&echoReply,	// buffer
					sizeof(ECHOREPLY),	// size of buffer
					0,					// flags
					(LPSOCKADDR)lpsaFrom,	// From address
					&nAddrLen);			// pointer to address len

	// Check return value
	if (nRet == SOCKET_ERROR)
		ReportError("recvfrom()");

	// return time sent and IP TTL
	*pTTL = echoReply.ipHdr.TTL;
	//return(echoReply.dwTime);   		//获取发送时存入的系统时间tick，返回计算发送延时
}

// What happened?
void ReportError(LPCSTR pWhere)
{
	fprintf(stderr,"\n%s error: %d\n",
		WSAGetLastError());
}


// WaitForEchoReply()
// Use select() to determine when
// data is waiting to be read
int WaitForEchoReply(SOCKET s)
{
	struct timeval Timeout;	//timeval 是一种数据结构，用于表示时间，下面有两个变量time_t tv_sec;和suseconds tv_usec；秒和微秒，这里用timeout设置最长等待时间。在阻塞模式中，timeout为null
	fd_set readfds;		//fdset是winsock头文件里的一个数据结构，用来管理多个socket

	readfds.fd_count = 1;		//集合中包含的socket数量为1
	readfds.fd_array[0] = s;	//socket的名字装入指针
	Timeout.tv_sec = 5;			//超时设置为5秒
    Timeout.tv_usec = 0;

	return(select(1, &readfds, NULL, NULL, &Timeout));	//select函数见教材《网络编程》的第8.3节，这个函数的功能是管理多个socket状态。这个函数将超时设置为了5s
}


//
// Mike Muuss' in_cksum() function
// and his comments from the original
// ping program
//
// * Author -
// *	Mike Muuss
// *	U. S. Army Ballistic Research Laboratory
// *	December, 1983

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
