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

#define MAX_LEN 128

// DLC Header
typedef struct tagDLCHeader
{
   unsigned char       DesMAC[6];             /* destination HW addrress */
   unsigned char       SrcMAC[6];             /* source HW addresss */
   unsigned short      Ethertype;                /* ethernet type */
} DLCHEADER, *PDLCHEADER;
// ARP Frame
typedef struct tagARPFrame
{
          unsigned short          HW_Type;           /* hardware address */
          unsigned short          Prot_Type;             /* protocol address */
          unsigned char       HW_Addr_Len;       /* length of hardware address */
          unsigned char       Prot_Addr_Len;         /* length of protocol address */
          unsigned short          Opcode;                /* ARP/RARP */

          unsigned char       Send_HW_Addr[6];     /* sender hardware address */
          unsigned long       Send_Prot_Addr;      /* sender protocol address */
          unsigned char       Targ_HW_Addr[6];     /* target hardware address */
          unsigned long       Targ_Prot_Addr;      /* target protocol address */
          unsigned char       padding[18];
} ARPFRAME, *PARPFRAME;
// ARP Packet = DLC header + ARP Frame
typedef struct tagARPPacket
{
     DLCHEADER     dlcHeader;
     ARPFRAME      arpFrame;
} ARPPACKET, *PARPPACKET;



void genARPPacket(pcap_t *_adhandle,int packetNumber);
void formatARPPacket(char* srcDLC,char* desDLC,char* srcMAC,char* srcIP,char* desMAC,char* desIP,int arpType,pcap_t *ARP_adhandle,int ARP_packetNumber);

//pcap_t *adhandle;

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

    genARPPacket(adhandle,packet_number);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    pcap_close(adhandle);
    pcap_freealldevs(alldevs);

    return 0;
}

void genARPPacket(pcap_t *_adhandle,int packetNumber)
{
  printf("11111111111111111111\n");
//方法一
/*
char* srcDLC;
char* desDLC;
char* srcMAC;
char* srcIP ;
char* desMAC;
char* desIP ;
int arpType  = 1;
memset(srcDLC , 0, MAX_LEN);
memset(desDLC , 0, MAX_LEN);
memset(srcMAC , 0, MAX_LEN);
memset(desMAC,  0, MAX_LEN);
*/
char srcDLC[48];
char desDLC[48];
char srcMAC[48];
char srcIP [32];
char desMAC[48];
char desIP [32];
int arpType  = 1;
strcpy(srcDLC, "80FA5B00FCD1");
strcpy(desDLC, "FFFFFFFFFFFF");
strcpy(srcMAC, "80FA5B00FCD1");
strcpy(srcIP , "222.20.40.25");
strcpy(desMAC, "80FA5B00FCD1");
strcpy(desIP , "222.20.40.25");
printf("11111111111111111111\n");
formatARPPacket(srcDLC,desDLC,srcMAC,srcIP,desMAC,desIP,arpType,_adhandle,packetNumber);
/*
//方法二
char TempSrcDLC[MAX_LEN]={0};
char TempDesDLC[MAX_LEN]={0};
char TempSrcMAC[MAX_LEN]={0};
char TempSrcIP[MAX_LEN]={0};
char TempDesMAC[MAX_LEN]={0};
char TempDesIP[MAX_LEN]={0};
 // 如果选中"请求包"，则TempARPType为 1
 // 如果选中"应答包"，则TempARPType为 2
 int TempARPType=1;
 strcpy(TempSrcDLC, "6002B4FB7AD9");
 strcpy(TempDesDLC, "FFFFFFFFFFFF");
 strcpy(TempSrcMAC, "6002B4FB7AD9");
 strcpy(TempSrcIP , "222.20.95.17");
 strcpy(TempDesMAC, "6002B4FB7AD9");
 strcpy(TempDesIP , "222.20.95.17");
 //formatARPPacket(TempSrcDLC,TempDesDLC,TempSrcMAC,TempSrcIP,TempDesMAC,TempDesIP,TempARPType);   // 根据用户输入信息格式化数据包
*/
/*
     // 开始填充各个字段
  ARPPACKET ARPPacket;                                                                // 定义ARPPACKET结构体变量

  memset(&ARPPacket, 0, sizeof(ARPPACKET));                                          // 数据包初始化0

  formatStrToMAC(srcDLC,ARPPacket.dlcHeader.SrcMAC);                      // DLC帧头
  formatStrToMAC(desDLC,ARPPacket.dlcHeader.DesMAC);
  printf("%s\n", srcDLC);
  formatStrToMAC(srcMAC,ARPPacket.arpFrame.Send_HW_Addr);               // 源地址
  ARPPacket.arpFrame.Send_Prot_Addr = inet_addr(srcIP);
  formatStrToMAC(desMAC,ARPPacket.arpFrame.Targ_HW_Addr);              // 目的地址
  ARPPacket.arpFrame.Targ_Prot_Addr = inet_addr(desIP);

  ARPPacket.arpFrame.Opcode = htons((unsigned short)arpType);        // arp包类型

  // 自动填充常量
  ARPPacket.dlcHeader.Ethertype = htons((unsigned short)0x0806);     // DLC Header的以太网类型
  ARPPacket.arpFrame.HW_Type = htons((unsigned short)1);             // 硬件类型
  ARPPacket.arpFrame.Prot_Type = htons((unsigned short)0x0800);      // 上层协议类型
  ARPPacket.arpFrame.HW_Addr_Len = (unsigned char)6;                 // MAC地址长度
  ARPPacket.arpFrame.Prot_Addr_Len = (unsigned char)4;               // IP地址长度

 printf("Do you want to store the data of packets in order to use it next time\ninput 0 or 1 to choose NO or YES\n");
   int store_or_not;
   scanf("%d",&store_or_not);
   printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
   if(store_or_not == 1)
   {
     //  simple_storePackets(_adhandle,&ARPPacket, sizeof(ARPPacket));   // 其中的ARPPacket就是我们先前填充的ARP包
      // complicated_storePackets(_adhandle);

   }
   if(store_or_not == 0)
   {
    for(int k = 0; k < packetNumber; k++)
    if ( 0 != (pcap_sendpacket(_adhandle,&ARPPacket, sizeof(ARPPacket))) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send successfully without storing packets\n");
    }
    system("pause");
   }
   return ;
   */
}
void formatARPPacket(char* srcDLC,char* desDLC,char* srcMAC,char* srcIP,char* desMAC,char* desIP,int arpType,pcap_t *ARP_adhandle,int ARP_packetNumber)
{
       // 开始填充各个字段
  ARPPACKET ARPPacket;                                                                // 定义ARPPACKET结构体变量

  memset(&ARPPacket, 0, sizeof(ARPPACKET));                                          // 数据包初始化0

  formatStrToMAC(srcDLC,ARPPacket.dlcHeader.SrcMAC);                      // DLC帧头
  formatStrToMAC(desDLC,ARPPacket.dlcHeader.DesMAC);
  printf("%s\n", srcDLC);
  printf("%s\n", ARPPacket.dlcHeader.SrcMAC);
  formatStrToMAC(srcMAC,ARPPacket.arpFrame.Send_HW_Addr);               // 源地址
  ARPPacket.arpFrame.Send_Prot_Addr = inet_addr(srcIP);
  formatStrToMAC(desMAC,ARPPacket.arpFrame.Targ_HW_Addr);              // 目的地址
  ARPPacket.arpFrame.Targ_Prot_Addr = inet_addr(desIP);

  ARPPacket.arpFrame.Opcode = htons((unsigned short)arpType);        // arp包类型

  // 自动填充常量
  ARPPacket.dlcHeader.Ethertype = htons((unsigned short)0x0806);     // DLC Header的以太网类型
  ARPPacket.arpFrame.HW_Type = htons((unsigned short)1);             // 硬件类型
  ARPPacket.arpFrame.Prot_Type = htons((unsigned short)0x0800);      // 上层协议类型
  ARPPacket.arpFrame.HW_Addr_Len = (unsigned char)6;                 // MAC地址长度
  ARPPacket.arpFrame.Prot_Addr_Len = (unsigned char)4;               // IP地址长度

   printf("Do you want to store the data of packets in order to use it next time\ninput 0 or 1 to choose NO or YES\n");
   int store_or_not;
   scanf("%d",&store_or_not);
   printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
   if(store_or_not == 1)
   {
     //  simple_storePackets(_adhandle,&ARPPacket, sizeof(ARPPacket));   // 其中的ARPPacket就是我们先前填充的ARP包
      // complicated_storePackets(_adhandle);

   }
   if(store_or_not == 0)
   {
    for(int k = 0; k < ARP_packetNumber; k++)
    if ( 0 != (pcap_sendpacket(ARP_adhandle,&ARPPacket, sizeof(ARPPacket))) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send successfully without storing packets\n");
    }
    system("pause");
   }
   return ;


}

/****************************************************************************
 *   Name & Params::
 *             formatStrToMAC
 *             (
 *                 const LPSTR lpHWAddrStr : 用户输入的MAC地址字符串
 *                 unsigned char *HWAddr :   返回的MAC地址字符串(赋给数据包结构体)
 *             )
 *   Purpose:
 *             将用户输入的MAC地址字符转成数据包结构体需要的格式
 ****************************************************************************/
void formatStrToMAC(const LPSTR lpHWAddrStr, unsigned char *HWAddr)
{
       unsigned int i, index = 0, value, temp;
      unsigned char c;

      _strlwr(lpHWAddrStr);                                                   // 转换成小写

      for (i = 0; i < strlen(lpHWAddrStr); i++)
     {
           c = *(lpHWAddrStr + i);
            if (( c>='0' && c<='9' ) || ( c>='a' && c<='f' ))
           {
               if (c>='0' && c<='9')  temp = c - '0';                         // 数字
               if (c>='a' && c<='f')  temp = c - 'a' + 0xa;               // 字母
               if ( (index % 2) == 1 )
              {
                   value = value*0x10 + temp;
                   HWAddr[index/2] = value;
              }
              else value = temp;
              index++;
         }
               if (index == 12) break;
        }
}


