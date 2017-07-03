#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream.h>
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define ICMP_MIN 12
//packet (just header)
typedef struct iphdr {
unsigned char h_len:4;
unsigned char version:4;
unsigned char tos;
unsigned short total_len;
unsigned short ident;
unsigned short frag_and_flags;
unsigned char  ttl;
unsigned char proto;
unsigned short checksum;
unsigned int sourceIP;
unsigned int destIP;
}IpHeader;
typedef  struct _ihdr {
BYTE  i_type;
BYTE  i_code;
USHORT  i_cksum;
USHORT  i_id;
USHORT  i_seq;
ULONG  timestamp;
}IcmpHeader;

#define  STATUS_FAILED 0xFFFF
#define  MAX_PACKET 1024
#define xmalloc(s) (char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(s))
#define  xfree(p)   HeapFree(GetProcessHeap(),0,(p))

USHORT checksum(USHORT *, int);
void fill_icmp_head(char *);
void decode_resp(char *,int ,struct sockaddr_in *);
void Usage(char *progname)
{
fprintf(stderr,"Usage:\n");
fprintf(stderr,"%s <host>\n",progname);
ExitProcess(STATUS_FAILED);
}
int main(int argc, char **argv)
{
WSADATA wsaData;
SOCKET sockRaw;
struct sockaddr_in dest,from;
struct hostent *hp;
int bread,datasize;
int fromlen = sizeof(from);
char *dest_ip;
char *icmp_data;
char *recvbuf;
char host[256];
unsigned int addr=0;
USHORT seq_no = 0;
if (WSAStartup(0x0101,&wsaData) != 0)
{
fprintf(stderr,"WSAStartup failed: %d\n",GetLastError());
ExitProcess(STATUS_FAILED);
}

if (argc >1 )
strcpy(host,argv[1]);
else
{
printf("Please input hostname(Press enter key for localhost)\nInput:");
gets(host);
if(strlen(host)<1)
strcpy(host,"localhost");
}
if((sockRaw=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))==INVALID_SOCKET)
{
fprintf(stderr,"WSAStartup failed: %d\n",GetLastError());
ExitProcess(STATUS_FAILED);
}

memset(&dest,0,sizeof(dest));
hp = gethostbyname(host/*argv[1]*/);
if (hp!=NULL)
{
memcpy(&(dest.sin_addr),hp->h_addr,hp->h_length);
dest.sin_family = AF_INET;				        		dest_ip = inet_ntoa(dest.sin_addr);
}
else								           	{
fprintf(stderr,"Unable to resolve %s\n",argv[1]);
ExitProcess(STATUS_FAILED);
}
datasize=sizeof(IcmpHeader);
icmp_data = xmalloc(MAX_PACKET);
recvbuf = xmalloc(MAX_PACKET);	if (!icmp_data) 			{
fprintf(stderr,"HeapAlloc failed %d\n",GetLastError());
ExitProcess(STATUS_FAILED);
}

memset(icmp_data,0,MAX_PACKET);						fill_icmp_head(icmp_data);
while(1)
{
int bwrote;
((IcmpHeader*)icmp_data)->i_cksum = 0;
((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
((IcmpHeader*)icmp_data)->i_seq = seq_no++;
((IcmpHeader*)icmp_data)->i_cksum=checksum((USHORT*)icmp_data,  sizeof(IcmpHeader));
bwrote = sendto(sockRaw,icmp_data,datasize,0,(struct sockaddr*)&dest,sizeof(dest));
if (bwrote == SOCKET_ERROR)
{
fprintf(stderr,"sendto failed: %d\n",WSAGetLastError());
ExitProcess(STATUS_FAILED);
}
if (bwrote < datasize )
fprintf(stdout,"Wrote %d bytes\n",bwrote);
//bread=recvfrom(sockRaw,recvbuf,MAX_PACKET,0,(structsockaddr*)&from,&fromlen);
if (bread == SOCKET_ERROR)
{
if (WSAGetLastError() == WSAETIMEDOUT) 									{
printf("timed out\n");											continue;
}
fprintf(stderr,"recvfrom failed: %d\n",WSAGetLastError());			perror("revffrom failed.");
ExitProcess(STATUS_FAILED);
}
decode_resp(recvbuf,bread,&from);
Sleep(2000);										      	}
closesocket(sockRaw);		                               	xfree(icmp_data);	                                        	xfree(recvbuf );	                              	WSACleanup();
return 0;
}
void fill_icmp_head(char * icmp_data)                    {
IcmpHeader *icmp_hdr;
icmp_hdr = (IcmpHeader*)icmp_data;
icmp_hdr->i_type = ICMP_ECHO;                   	icmp_hdr->i_code = 0;

icmp_hdr->i_cksum = 0;
icmp_hdr->i_id= (USHORT)GetCurrentProcessId();    	icmp_hdr->i_seq = 0;
}
void decode_resp(char *buf, int bytes,struct sockaddr_in *from)      {
IpHeader *iphdr;
IcmpHeader *icmphdr;
unsigned short iphdrlen;

iphdr = (IpHeader *)buf;
iphdrlen = iphdr->h_len * 4 ;
if (bytes  < iphdrlen + ICMP_MIN)                     		printf("Too few bytes from %s\n",inet_ntoa(from->sin_addr));
icmphdr = (IcmpHeader*)(buf + iphdrlen);

if (icmphdr->i_type != ICMP_ECHOREPLY)          	{
fprintf(stderr,"non-echo type %d recvd\n",icmphdr->i_type);
return;
}
if (icmphdr->i_id != (USHORT)GetCurrentProcessId())          {
fprintf(stderr,"someone else's packet!\n");
return ;
}
printf("\n%d bytes from %s:",bytes, inet_ntoa(from->sin_addr));
printf(" icmp_seq = %d. ",icmphdr->i_seq);
printf(" time: %d ms ",GetTickCount()-icmphdr->timestamp);
}

USHORT checksum(USHORT *buffer, int size)
{
unsigned long cksum=0;
while(size >1) 										   	{
cksum+=*buffer++;
size -=sizeof(USHORT);
}
if(size) 										       		cksum += *(UCHAR*)buffer;
cksum = (cksum >> 16) + (cksum & 0xffff);
cksum += (cksum >>16);
return (USHORT)(~cksum);
}
