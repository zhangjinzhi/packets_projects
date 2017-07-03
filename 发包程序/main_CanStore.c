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

typedef struct   _ETHER_HEADER{
    u_char   et_dhost[6];
    u_char   et_shost[6];
    u_short   et_type;  //如果上一层为IP协议。则ether_type的值就是0x0800
} ETHER_HEADER;

typedef struct _IP_HEADER
{
    unsigned char   h_verlen;
    unsigned char   tos; //type of service
    unsigned short  total_len;
    unsigned short  ident;
    unsigned short  frag_and_flags;
    unsigned char   ttl;
    unsigned char   proto;
    unsigned short  checksum;
    unsigned int    sourceIP;
    unsigned int    destIP;
} IP_HEADER;

typedef struct _TCP_HEADER
{
    USHORT th_sport;
    USHORT th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_lenres;
    unsigned char th_flag;
    USHORT th_win;
    USHORT th_sum;
    USHORT th_urp;
} TCP_HEADER;

typedef struct _psdhdr
{
    unsigned long saddr;           //Source IP address; 32 bits
    unsigned long daddr;           //Destination IP address; 32 bits
    unsigned char mbz;           //padding
    unsigned char ptcl;           //Protocol; 8 bits
    unsigned short tcpl;           //TCP length; 16 bits
}PSDTCP_HEADER ;
//////////////////////////////////////////////////////////////////////
typedef struct ARPFrame                     
{
          unsigned short         HW_Type;           /* hardware address */
          unsigned short         Prot_Type;             /* protocol address */
          unsigned char      HW_Addr_Len;       /* length of hardware address */
          unsigned char      Prot_Addr_Len;         /* length of protocol address */
          unsigned short         Opcode;                /* ARP/RARP */
 
          unsigned char      Send_HW_Addr[6];     /* sender hardware address */
          unsigned long      Send_Prot_Addr;      /* sender protocol address */
          unsigned char      Targ_HW_Addr[6];     /* target hardware address */
          unsigned long      Targ_Prot_Addr;      /* target protocol address */
          unsigned char      padding[18];
} ARPFRAME, *PARPFRAME;
typedef struct ARPPacket                
{
     ETHER_HEADER ether_Header;
     ARPFRAME      arp_Frame;
} ARPPACKET, *PARPPACKET;


/////////////////////////////////////////////////////////////////////
USHORT CheckSum(USHORT *buffer, int size)
{
    unsigned long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }

    if (size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);

    return (USHORT)(~cksum);
}

int packet_number;   //指定发送的数据包数量
void send_stored_packet(pcap_t *store_adhandle,int send_stored_packet_packet_number);
void genTCPPacket(pcap_t *_adhandle,int packetNumber);
void simple_storePackets( pcap_t *store_adhandle,
                          char *store_ucSend,
                          int simple_store_datasize);
int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
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
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");

        pcap_freealldevs(alldevs);
        return -1;
    }


    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
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
//以上为打开某个网卡
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
       printf("input the number of packets\n");
       scanf("%d",&packet_number);
//////////////////////////////////////////////////////////////////////////////////////////
       printf("do you want to use previous packets you had used :Yes is 1 or NO is 0\n");
      int use_previous_packet;
      scanf("%d",&use_previous_packet);
      if(use_previous_packet == 1)
      {
        send_stored_packet(adhandle,packet_number);

      }
      if(use_previous_packet == 0)
    {
       printf("choose the type of packets you want to send \n");
       printf("input the name of packet in lower-case letters: tcp is 1 ..............\n");
       int type_of_packet;
       scanf("%d",&type_of_packet);
      if(type_of_packet == 1)
        {
          printf("begin to generate the TCP packets\n");
          genTCPPacket(adhandle,packet_number);
        }
      else
        {
          printf("the type of packets is wrong\n");
        }
     }
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
     pcap_close(adhandle);
    pcap_freealldevs(alldevs);

    return 0;
}

void genTCPPacket(pcap_t *_adhandle,int packetNumber)
{
    IP_HEADER ipHeader;
    TCP_HEADER tcpHeader;
    PSDTCP_HEADER psdHeader;
    ETHER_HEADER etherHeader;
    char scanf_szSrcIp[16] = "192.168.4.90";
    char scanf_szDstIp[16] = "192.168.4.90";
    char szSrcIp[16];
    char szDstIp[16];


    strcpy(szSrcIp,scanf_szSrcIp);
    strcpy(szDstIp,scanf_szDstIp);
    char *g_BehindString = "just a test";

    memset( &ipHeader, 0, sizeof ipHeader );
    memset( &tcpHeader, 0, sizeof tcpHeader );
    memset( &psdHeader, 0, sizeof psdHeader );
    memset( &etherHeader, 0, sizeof etherHeader );

    ipHeader.h_verlen = (IPVER<<4 | sizeof ipHeader / sizeof(unsigned long));//高四位IP版本号，低四位首部长度
    ipHeader.tos = 0;
    ipHeader.total_len = htons( sizeof ipHeader + sizeof tcpHeader + strlen( g_BehindString ) );//16位总长度（字节）
    ipHeader.ident = 0x14BB;//16位标识
    ipHeader.frag_and_flags = 0x0040;//3位标志位
    ipHeader.ttl = 128;//8位生存时间TTL
    ipHeader.proto = IPPROTO_TCP;//8位协议(TCP,UDP…)
    ipHeader.checksum = 0;//16位IP首部校验和
    ipHeader.sourceIP = inet_addr( szSrcIp );//32位源IP地址
    ipHeader.destIP = inet_addr( szDstIp );//32位目的IP地址
   //填充TCP
   // tcpHeader.th_sport = htons( rand()%60000 + 1024 );
    //tcpHeader.th_dport = htons( atoi(argv[2]) );
    tcpHeader.th_dport=htons(DEST_PORT); //16位目的端口号
    tcpHeader.th_sport=htons(SOUR_PORT); //16位源端口号 
    tcpHeader.th_seq = htonl( rand()%900000000 + 100000 );
    tcpHeader.th_ack = 0;
    tcpHeader.th_lenres = (sizeof(tcpHeader)/4<<4|0);
    tcpHeader.th_flag = 2; ///////////////////////////////////修改这里来实现不同的标志位探测，2是SYN，1是//FIN，16是ACK探测 等等 
    tcpHeader.th_win = htons((unsigned short)512);
    tcpHeader.th_sum = 0;
    tcpHeader.th_urp = 0;
    //填充TCP伪首部（用于计算校验和，并不真正发送）
    psdHeader.saddr = ipHeader.sourceIP;
    psdHeader.daddr = ipHeader.destIP; //目的地址
    psdHeader.mbz = 0;
    psdHeader.ptcl = IPPROTO_TCP; //协议类型
    psdHeader.tcpl = htons( sizeof tcpHeader ); //TCP首部长度

    printf("for example : 0x80 0xFA 0x5B 0x00 0xFC  0xD1 \n");
    unsigned char ucSrcMac[6]= { 0x80,0xFA ,0x5B ,0x00, 0xFC  ,0xD1 };
    unsigned char ucDstMac[6]= { 0x80 ,0xFA ,0x5B, 0x00 ,0xFC , 0xD1 };


    memcpy( etherHeader.et_dhost, &ucDstMac, sizeof ucDstMac );
    memcpy( etherHeader.et_shost, &ucSrcMac, sizeof ucSrcMac );
    etherHeader.et_type = 0x0008;

    char ucSend[1600];
    int datasize;
    //----------------Send SYN Packet----------------
    //计算TCP校验和
    memset( ucSend, 0, sizeof ucSend);
    memcpy( ucSend, &psdHeader,sizeof psdHeader );
    memcpy( ucSend + sizeof psdHeader, &tcpHeader, sizeof tcpHeader );
    memcpy( ucSend + sizeof psdHeader + sizeof tcpHeader, g_BehindString, strlen( g_BehindString ) );
    tcpHeader.th_sum = CheckSum((USHORT *)ucSend, sizeof psdHeader + sizeof tcpHeader + strlen( g_BehindString ) );
    tcpHeader.th_sum = htons( ntohs( tcpHeader.th_sum ) - (USHORT)strlen(g_BehindString));

    //计算IP校验和
    memset( ucSend, 0, sizeof ucSend );
    memcpy( ucSend, &ipHeader,sizeof  ipHeader);
    memcpy( ucSend + sizeof ipHeader, &tcpHeader, sizeof tcpHeader );
    memset( ucSend + sizeof ipHeader +sizeof tcpHeader, 0, 4 );
    ipHeader.checksum = CheckSum((USHORT *)ucSend,sizeof ipHeader );

    //填充发送缓冲区
    memset( ucSend, 0, sizeof ucSend );
    memcpy( ucSend, &etherHeader ,sizeof etherHeader );
    memcpy( ucSend + sizeof etherHeader, &ipHeader, sizeof ipHeader );
    memcpy( ucSend + sizeof etherHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader );
    memcpy( ucSend + sizeof etherHeader + sizeof ipHeader + sizeof tcpHeader, g_BehindString, strlen(g_BehindString) );
    datasize = sizeof ipHeader + sizeof tcpHeader + sizeof etherHeader + strlen( g_BehindString );
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
   printf("Do you want to store the data of packets in order to use it next time\ninput 0 or 1 to choose NO or YES\n");
   int store_or_not;
   scanf("%d",&store_or_not);
   printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
   if(store_or_not == 1)
   {
       simple_storePackets(_adhandle,
                        ucSend,
                        datasize);
   }
   if(store_or_not == 0)
   {
    for(int k = 0; k < packetNumber; k++)
    if ( 0 != pcap_sendpacket(_adhandle, (const unsigned char *)ucSend, datasize ) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send success.\n");
    }
    system("pause");
   }
   return ;
}

void simple_storePackets( pcap_t *store_adhandle,
                          char *store_ucSend,
                          int simple_store_datasize)
{
 FILE* wc =fopen("keep.dat","wb");
  if(wc==NULL) {
        printf("failed to open file\n");
        system("pause");
    }

 fwrite( store_ucSend, simple_store_datasize, 1, wc );
 fclose(wc);
 for(int k = 0; k < packet_number; k++)
    if ( 0 != pcap_sendpacket(store_adhandle, (const unsigned char *)store_ucSend, simple_store_datasize ) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send success.\n");
    }

}

void send_stored_packet(pcap_t *store_adhandle,int send_stored_packet_packet_number)
{   int simple_store_datasize;
    char use_store_ucSend[1600];
    FILE *fp=fopen( "keep.dat", "rb" );//b表示以二进制方式打开文件
    if( fp == NULL ) //打开文件失败，返回错误信息
    {
        printf("open file for read error\n");
        system("pause");
    }
    fseek (fp, 0, SEEK_END);
    simple_store_datasize=ftell(fp);
    printf("size=ftell (fp)=%d\n",simple_store_datasize);
    fclose(fp);//关闭文件

    fp=fopen( "keep.dat", "rb" );//b表示以二进制方式打开文件
    if( fp == NULL ) //打开文件失败，返回错误信息
    {
        printf("open file for read error\n");
        system("pause");
    }
    fread( use_store_ucSend, simple_store_datasize, 1, fp );
    fclose(fp);//关闭文件
    for(int k = 0; k < send_stored_packet_packet_number; k++)
    if ( 0 != pcap_sendpacket(store_adhandle, (const unsigned char *)use_store_ucSend, simple_store_datasize ) )
    {
        printf("use the storage to send failed.\n");
    }
    else
    {
        printf(" use the storage to send success.\n");
    }
}
