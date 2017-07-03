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

char pDest[30];		//Ŀ��IP��ַ
char pSors[30];		//ԴIP��ַ


// ICMP Echo Request/Reply functions
int		SendEchoRequest(SOCKET, LPSOCKADDR_IN,int choice);		//����
void    RecvEchoReply(SOCKET, LPSOCKADDR_IN, u_char *);			//����

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
	printf("�����뱾��IP��ַ:");
	scanf("%s",&pSors);
	printf("\n������Ŀ���IP��ַ��");
	scanf("%s",&pDest);
	printf("\n****** 1����ƬICMP ECHO������ 2���ص���Ƭ ******\n");	printf("************************************************************\n");
	scanf("%d",&choice);
	Ping(pDest,choice);		//PING����
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
	for (nLoop = 0; nLoop < 4; nLoop++)			//�����ĸ�PING
	{
		sTime=GetTickCount();					//��÷���ʱ��
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
		dwElapsed = GetTickCount() -sTime;			//���ʱ��
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

	echoReq.iphdr.VIHL=(4<<4 | sizeof(IPHDR)/sizeof(unsigned long));// 4λ�ײ�����+4λIP�汾��
	echoReq.iphdr.TOS =0;						//8λ�ķ�������tos
	echoReq.iphdr.TotLen=htons(sizeof(ECHOREQUEST)+REQ_DATASIZE/2);	//ip���ĳ���
	echoReq.iphdr.ID	=ipid++;			//ipͷ�ı�ʶλ
	echoReq.iphdr.FlagOff=0x0000;				//��־��Ƭƫ����
	echoReq.iphdr.TTL=128;						//����ʱ��
	echoReq.iphdr.Protocol=IPPROTO_ICMP;		//Э������
	echoReq.iphdr.Checksum=0;						//У��ͣ������Զ����
	echoReq.iphdr.iaSrc =inet_addr(pSors);	//����IP
	echoReq.iphdr.iaDst=lpstToAddr->sin_addr.S_un.S_addr;	//Ŀ��IP


	// Fill in echo request
	echoReq.icmpPack.icmpHdr.Type		= ICMP_ECHOREQ;  //����8
	echoReq.icmpPack.icmpHdr.Code		= 0;			 //����0
	echoReq.icmpPack.icmpHdr.Checksum	= 0;			 //У���0���������
	echoReq.icmpPack.icmpHdr.ID			= nId++;		 //��ʶ
	echoReq.icmpPack.icmpHdr.Seq			= nSeq++;		 //���

	// Fill in some data to send
	//��Ƭ����
	if(choice==1)			//ѡ��Ϊ1ʱ��Ϊ��Ƭ����
		{
			echoReq.iphdr.FlagOff=0x0020;
		for (nRet = 0; nRet < REQ_DATASIZE/2; nRet++)	  //�����ѡ����,����������16���ֽ�
			echoReq.icmpPack.Data[nRet] = 'a';
		for (; nRet < REQ_DATASIZE; nRet++)	  //�����ѡ����,����������16���ֽ�
			echoReq.icmpPack.Data[nRet] = 'b';
		echoReq.icmpPack.icmpHdr.Checksum= in_cksum((u_short *)&echoReq.icmpPack, sizeof(ICMPPACK));	//����ICMP��У��ͼ��㲢���룬У��͸�������ICMP���ģ�������α�ײ�
		nRet = sendto(s,						/* socket */
				 (LPSTR)&echoReq,			/* buffer */
				 sizeof(ECHOREQUEST)-16,
				 0,							/* flags */
				 (LPSOCKADDR)lpstToAddr, /* destination */
				 sizeof(SOCKADDR_IN));   /* address length */
		echoReq.iphdr.FlagOff=0x0300;
		rEchoReq.iphdr=echoReq.iphdr;
		for (nRet=0; nRet < REQ_DATASIZE/2; nRet++)	  //�����ѡ����,����������16���ֽ�
			rEchoReq.Data[nRet]=echoReq.icmpPack.Data[nRet+16];
		nRet = sendto(s,						/* socket */
				 (LPSTR)&rEchoReq,			/* buffer */
				 sizeof(RECHOREQUEST),
				 0,							/* flags */
				 (LPSOCKADDR)lpstToAddr, /* destination */
				 sizeof(SOCKADDR_IN));   /* address length */
			}
		else if(choice==2)				//ѡ��Ϊ2ʱ��Ϊ��Ƭ�ص�����
			{
			echoReq.iphdr.FlagOff=0x0020;
			for (nRet = 0; nRet < REQ_DATASIZE/2; nRet++)	  //����������16���ֽ�
			echoReq.icmpPack.Data[nRet] = 'a';
			for (; nRet < REQ_DATASIZE; nRet++)	  //����������16���ֽ�
			echoReq.icmpPack.Data[nRet] = 'b';
			echoReq.icmpPack.icmpHdr.Checksum= in_cksum((u_short *)&echoReq.icmpPack, sizeof(ICMPPACK));	//����ICMP��У��ͼ��㲢���룬У��͸�������ICMP���ģ�������α�ײ�
			nRet = sendto(s,						/* socket */
				 (LPSTR)&echoReq,			/* buffer */
				 sizeof(ECHOREQUEST)-8,
				 0,							/* flags */
				 (LPSOCKADDR)lpstToAddr, /* destination */
				 sizeof(SOCKADDR_IN));   /* address length */
			echoReq.iphdr.FlagOff=0x0300;
			rEchoReq.iphdr=echoReq.iphdr;
			for (nRet=0; nRet <REQ_DATASIZE/2; nRet++)	  //����������16���ֽ�
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
	//return(echoReply.dwTime);   		//��ȡ����ʱ�����ϵͳʱ��tick�����ؼ��㷢����ʱ
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
	struct timeval Timeout;	//timeval ��һ�����ݽṹ�����ڱ�ʾʱ�䣬��������������time_t tv_sec;��suseconds tv_usec�����΢�룬������timeout������ȴ�ʱ�䡣������ģʽ�У�timeoutΪnull
	fd_set readfds;		//fdset��winsockͷ�ļ����һ�����ݽṹ������������socket

	readfds.fd_count = 1;		//�����а�����socket����Ϊ1
	readfds.fd_array[0] = s;	//socket������װ��ָ��
	Timeout.tv_sec = 5;			//��ʱ����Ϊ5��
    Timeout.tv_usec = 0;

	return(select(1, &readfds, NULL, NULL, &Timeout));	//select�������̲ġ������̡��ĵ�8.3�ڣ���������Ĺ����ǹ�����socket״̬�������������ʱ����Ϊ��5s
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
