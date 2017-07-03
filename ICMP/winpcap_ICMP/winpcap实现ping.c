#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream.h>
#include <pcap.h>
typedef struct _ethhdr
{
u_char daddr[6]; //6字节目的MAC地址
u_char saddr[6]; //6字节本地MAC地址
unsigned short ptype; //2字节协议类型
}ETH_HEADER;
typedef struct IPHDR
{
u_char VIHL; // 版本和首部长度
u_char TOS; // 服务类型
u_short TotLen; // 总长度
u_short ID; // 标识符
u_short FlagOff; // 标志和数据报偏移量
u_char TTL; // 生存时间
u_char Protocol; // 协议
u_short checksum;
u_char sourceIP[4];
u_char destIP[4];
}IPHDR;
// ICMP Header - RFC 792
typedef struct ICMPHDR
{
u_char Type; // Type
u_char Code; // Code
u_short Checksum; // Checksum
u_short ID; // Identification
u_short Seq; // Sequence
u_short Data; // Data
}ICMPHDR;
void main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
u_char packet[100];
u_long cal;
u_long cal2;
int i=0;
int inum;
ETH_HEADER eth_header;
IPHDR iphdr;
ICMPHDR icmphdr;
pcap_if_t *alldevs;
pcap_if_t *d;
argc=2;
/* 检查命令行参数的合法性 */
if (argc != 2)
{
printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
return ;
}

/* 获取本机设备列表 */
if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
{
fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
exit(1);
}
/* 打印列表 */
for(d=alldevs; d; d=d->next)
{
printf("%d. %s\n", ++i, d->name);
if (d->description)
printf(" (%s)\n", d->description);
else
printf(" (No description available)\n");
}

if(i==0)
{
printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
return ;
}

printf("Enter the interface number (1-%d):\n",i);
scanf("%d", &inum);

if(inum < 1 || inum > i)
{
printf("\nInterface number out of range.\n");
/* 释放设备列表 */
pcap_freealldevs(alldevs);
return ;
}

/* 跳转到选中的适配器 */
for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

if ( ( fp= pcap_open(d->name, // 设备名
65536, // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
1000, // 读取超时时间
NULL, // 远程机器验证
errbuf // 错误缓冲池
) ) == NULL)
{
fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

pcap_freealldevs(alldevs);
return ;
}
///////////////////////////////////////////////////////
////////////具体参数配置自己设置，不懂留言
//////////////////////////////////////////////////
memset(packet, 0, 64);
memcpy(packet, &eth_header, sizeof(eth_header));//0-13
memcpy(packet + sizeof(eth_header), &iphdr, sizeof(iphdr));//14-23
memcpy(packet + sizeof(eth_header)+sizeof(iphdr), &icmphdr, sizeof(icmphdr));//24-43
int datasize = sizeof(iphdr)+sizeof(icmphdr)+sizeof(iphdr);
printf("datasize=%d\n",datasize);
int l=0;
for(;l<485;l++)
{
Sleep(400);
if(pcap_sendpacket(fp, packet, datasize) == 0)
{
printf("\nSend the first part\n");
};

} ;
getchar();
getchar();
return ;
}
