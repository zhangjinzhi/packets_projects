#include<iostream.h>
#include <stdio.h>   
#include <string.h>
#include <stdlib.h>
#include<winsock2.h>
#pragma comment(lib,"ws2_32.lib")
//数据结构及宏定义：
#define IPVER   4           //IP协议预定
#define MAX_BUFF_LEN 65500  //发送缓冲区最大值
#define DEST_PORT 5050    //目的端口号
#define SOUR_PORT 8080    //源端口号
typedef struct ip_hdr    //定义IP首部 
{ 
  UCHAR h_verlen;            //4位首部长度,4位IP版本号 
  UCHAR tos;                //8位服务类型TOS 
  USHORT total_len;        //16位总长度（字节） 
  USHORT ident;            //16位标识 
  USHORT frag_and_flags;    //3位标志位 
  UCHAR ttl;                //8位生存时间 TTL 
  UCHAR proto;            //8位协议 (TCP, UDP 或其他) 
  USHORT checksum;        //16位IP首部校验和 
  ULONG sourceIP;            //32位源IP地址 
  ULONG destIP;            //32位目的IP地址 
}IP_HEADER; 
typedef struct tsd_hdr //定义TCP伪首部 
{ 
  ULONG saddr;    //源地址
  ULONG daddr;    //目的地址 
  UCHAR mbz;        //没用
  UCHAR ptcl;        //协议类型 
  USHORT tcpl;    //TCP长度 
}PSD_HEADER; 
typedef struct tcp_hdr //定义TCP首部 
{ 
  USHORT th_sport;            //16位源端口 
  USHORT th_dport;            //16位目的端口 
  ULONG th_seq;                //32位序列号 
  ULONG th_ack;                //32位确认号 
  UCHAR th_lenres;            //4位首部长度/6位保留字 
  UCHAR th_flag;                //6位标志位 
  USHORT th_win;                //16位窗口大小 
  USHORT th_sum;                //16位校验和 
  USHORT th_urp;                //16位紧急数据偏移量 
}TCP_HEADER;
using namespace std;
//主要函数：
//CheckSum:计算校验和的子函数 
USHORT checksum(USHORT *buffer, int size) 
{ 
    unsigned long cksum=0; 
    while(size >1) 
    { 
        cksum+=*buffer++; 
        size -=sizeof(USHORT); 
    } 
    if(size) 
    { 
        cksum += *(UCHAR*)buffer; 
    } 
  
    cksum = (cksum >> 16) + (cksum & 0xffff); 
    cksum += (cksum >>16); 
    return (USHORT)(~cksum); 
} 
//主函数
int main(void)
{
  IP_HEADER ipHeader; 
    TCP_HEADER tcpHeader; 
    PSD_HEADER psdHeader; 
    char TCP_Buff[MAX_BUFF_LEN];  //发送缓冲区
    unsigned short check_Buff[MAX_BUFF_LEN]; //检验和缓冲区
    const char tcp_send_data[]={"This is test!"};
  //填充IP首部 
    ipHeader.h_verlen=(IPVER<<4 | sizeof(ipHeader)/sizeof(unsigned long)); 
    ipHeader.tos=(UCHAR)0; 
    ipHeader.total_len=htons((unsigned short)sizeof(ipHeader)+sizeof(tcpHeader)+sizeof(tcp_send_data)); 
    ipHeader.ident=0;       //16位标识
    ipHeader.frag_and_flags=0; //3位标志位
    ipHeader.ttl=128; //8位生存时间 
    ipHeader.proto=IPPROTO_TCP; //协议类型
    ipHeader.checksum=0; //检验和暂时为0
    ipHeader.sourceIP=inet_addr("127.0.0.1");  //32位源IP地址
    ipHeader.destIP=inet_addr("127.0.0.1");    //32位目的IP地址
    //计算IP头部检验和
    memset(check_Buff,0,MAX_BUFF_LEN);
    memcpy(check_Buff,&ipHeader,sizeof(IP_HEADER));
    ipHeader.checksum=checksum(check_Buff,sizeof(IP_HEADER));
    //构造TCP伪首部
    psdHeader.saddr=ipHeader.sourceIP;
    psdHeader.daddr=ipHeader.destIP;
    psdHeader.mbz=0;
    psdHeader.ptcl=ipHeader.proto;
    psdHeader.tcpl=htons(sizeof(TCP_HEADER)+sizeof(tcp_send_data)) ;
    //填充TCP首部 
    tcpHeader.th_dport=htons(DEST_PORT); //16位目的端口号
    tcpHeader.th_sport=htons(SOUR_PORT); //16位源端口号 
    tcpHeader.th_seq=0;                         //SYN序列号
    tcpHeader.th_ack=0;                         //ACK序列号置为0
    //TCP长度和保留位
    tcpHeader.th_lenres=(sizeof(tcpHeader)/sizeof(unsigned long)<<4|0); 
    tcpHeader.th_flag=2; //修改这里来实现不同的标志位探测，2是SYN，1是//FIN，16是ACK探测 等等 
    tcpHeader.th_win=htons((unsigned short)16384);     //窗口大小
    tcpHeader.th_urp=0;                            //偏移大小    
    tcpHeader.th_sum=0;                            //检验和暂时填为0
    //计算TCP校验和 
    memset(check_Buff,0,MAX_BUFF_LEN);
    memcpy(check_Buff,&psdHeader,sizeof(psdHeader)); 
    memcpy(check_Buff+sizeof(psdHeader),&tcpHeader,sizeof(tcpHeader)); 
    memcpy(check_Buff+sizeof(PSD_HEADER)+sizeof(TCP_HEADER),
    tcp_send_data,sizeof(tcp_send_data));
    tcpHeader.th_sum=checksum(check_Buff,sizeof(PSD_HEADER)+
    sizeof(TCP_HEADER)+sizeof(tcp_send_data)); 
    //填充TCP报文
    memset(TCP_Buff, 0, MAX_BUFF_LEN);
    memcpy(TCP_Buff, &tcpHeader, sizeof(TCP_HEADER));
    memcpy(TCP_Buff+sizeof(TCP_HEADER), tcp_send_data, sizeof(tcp_send_data));
    int datasize = sizeof(TCP_HEADER) + sizeof(tcp_send_data);

    
  printf("封装的TCP包如下：\n");
  char *decodeptr = TCP_Buff;
  printf("源端口号：%d\n",ntohs( *(unsigned short*)decodeptr ) );
  decodeptr += sizeof(unsigned short);
  printf("目的端口号：%d\n",ntohs( *(unsigned short*)decodeptr ) );
  decodeptr += sizeof(unsigned short);
  printf("序列号：%d\n", ntohl( *(unsigned int*)decodeptr ) );
  decodeptr += sizeof(unsigned int);
  printf("确认号：%d\n", ntohl( *(unsigned int*)decodeptr ) );
  decodeptr += sizeof(unsigned int);
  char headlen = ((*decodeptr) >> 4) * 4;
  printf("首部长度：%d\n", headlen);
  decodeptr += sizeof(unsigned char);
  printf("标志：");
  switch (*decodeptr)
  {
  case 32: printf("URG\n");break;
  case 16: printf("ACK\n");break;
  case 8: printf("PSH\n");break;
  case 4: printf("RST\n");break;
  case 2: printf("SYN\n");break;
  case 1: printf("FIN\n");break;
  default: printf("未知\n");
  }
  decodeptr += sizeof(unsigned char);
  printf("窗口大小：%d\n", ntohs(*(unsigned short *)decodeptr));
  decodeptr += sizeof(unsigned short);
  printf("校验和：%d\n", ntohs(*(unsigned short *)decodeptr));
  decodeptr += sizeof(unsigned short);
  printf("紧急指针：%d\n", ntohs(*(unsigned short *)decodeptr));
  decodeptr += sizeof(unsigned short);
  printf("数据区：%s\n", decodeptr);
  //将TCP包写入二进制文件
  FILE *fp = NULL;
  if ((fp = fopen("TCP_dat", "wb")) == NULL)
  {
    printf("can't open file\n");
    return -1;
  }
  fwrite(TCP_Buff, datasize, 1, fp);
  return 0;
}


