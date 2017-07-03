#include<stdio.h>
#include<string.h>
#include<stdlib.h>
//#include<netinet/in.h>
#include<time.h>
#include <winsock2.h>
#pragma  comment(lib,"ws2_32.lib")
#define BUFSIZE 10240
#define STRSIZE 1024
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef long bpf_int32;

typedef unsigned long bpf_u_int32;

typedef unsigned short  u_short;

typedef unsigned long u_int32;

typedef unsigned short u_int16;

typedef unsigned char u_int8;

//pacp文件头结构体

struct pcap_file_header

{

bpf_u_int32 magic;       /* 0xa1b2c3d4 */

u_short version_major;   /* magjor Version 2 */

u_short version_minor;   /* magjor Version 4 */

bpf_int32 thiszone;      /* gmt to local correction */

bpf_u_int32 sigfigs;     /* accuracy of timestamps */

bpf_u_int32 snaplen;     /* max length saved portion of each pkt */

bpf_u_int32 linktype;    /* data link type (LINKTYPE_*) */

};

//时间戳

struct time_val

{

long tv_sec;         /* seconds 含义同 time_t 对象的值 */

long tv_usec;        /* and microseconds */

};

//pcap数据包头结构体

struct pcap_pkthdr

{

struct time_val ts;  /* time stamp */

bpf_u_int32 caplen; /* length of portion present */

bpf_u_int32 len;    /* length this packet (off wire) */

};

//数据帧头

typedef struct FramHeader_t

{ //Pcap捕获的数据帧头

u_int8 DstMAC[6]; //目的MAC地址

u_int8 SrcMAC[6]; //源MAC地址

u_short FrameType;    //帧类型

} FramHeader_t;

//IP数据报头

typedef struct IPHeader_t

{ //IP数据报头

u_int8 Ver_HLen;       //版本+报头长度

u_int8 TOS;            //服务类型

u_int16 TotalLen;       //总长度

u_int16 ID; //标识

u_int16 Flag_Segment;   //标志+片偏移

u_int8 TTL;            //生存周期

u_int8 Protocol;       //协议类型

u_int16 Checksum;       //头部校验和

u_int32 SrcIP; //源IP地址

u_int32 DstIP; //目的IP地址

} IPHeader_t;

//TCP数据报头

typedef struct TCPHeader_t

{ //TCP数据报头

u_int16 SrcPort; //源端口

u_int16 DstPort; //目的端口

u_int32 SeqNO; //序号

u_int32 AckNO; //确认号

u_int8 HeaderLen; //数据报头的长度(4 bit) + 保留(4 bit)

u_int8 Flags; //标识TCP不同的控制消息

u_int16 Window; //窗口大小

u_int16 Checksum; //校验和

u_int16 UrgentPointer;  //紧急指针

}TCPHeader_t;

//

void match_http(FILE *fp, char *head_str, char *tail_str, char *buf, int total_len); //查找 http 信息函数

//

int main()

{

struct pcap_file_header *file_header;

struct pcap_pkthdr *ptk_header;

IPHeader_t *ip_header;

TCPHeader_t *tcp_header;

FILE *fp, *output;

int   pkt_offset, i=0;

int ip_len, http_len, ip_proto;

int src_port, dst_port, tcp_flags;

char buf[BUFSIZE], my_time[STRSIZE];

char src_ip[STRSIZE], dst_ip[STRSIZE];

char  host[STRSIZE], uri[BUFSIZE];

//初始化

file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));

ptk_header  = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));

ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));

tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));

memset(buf, 0, sizeof(buf));

//

if((fp = fopen("test.pcap","r")) == NULL)

{

printf("error: can not open pcap file\n");

exit(0);

}

if((output = fopen("output.txt","w+")) == NULL)

{

printf("error: can not open output file\n");

exit(0);

}

//开始读数据包

pkt_offset = 24; //pcap文件头结构 24个字节

while(fseek(fp, pkt_offset, SEEK_SET) == 0) //遍历数据包

{

i++;

//pcap_pkt_header 16 byte

if(fread(ptk_header, 16, 1, fp) != 1) //读pcap数据包头结构

{

printf("\nread end of pcap file\n");

break;

}

pkt_offset += 16 + ptk_header->caplen;   //下一个数据包的偏移值

strftime(my_time, sizeof(my_time), "%Y-%m-%d %T", localtime(&(ptk_header->ts.tv_sec))); //获取时间

// printf("%d: %s\n", i, my_time);

//数据帧头 14字节

fseek(fp, 14, SEEK_CUR); //忽略数据帧头

//IP数据报头 20字节

if(fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1)

{

printf("%d: can not read ip_header\n", i);

break;

}
inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
//inet_ntop(AF_INET, (void *)&(ip_header->SrcIP),src_ip,16);
inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);

ip_proto = ip_header->Protocol;

ip_len = ip_header->TotalLen; //IP数据报总长度

// printf("%d:  src=%s\n", i, src_ip);

if(ip_proto != 0x06) //判断是否是 TCP 协议

{

continue;

}

//TCP头 20字节

if(fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1)

{

printf("%d: can not read ip_header\n", i);

break;

}

src_port = ntohs(tcp_header->SrcPort);

dst_port = ntohs(tcp_header->DstPort);

tcp_flags = tcp_header->Flags;

// printf("%d:  src=%x\n", i, tcp_flags);

if(tcp_flags == 0x18) // (PSH, ACK) 3路握手成功后

{

if(dst_port == 80) // HTTP GET请求

{

http_len = ip_len - 40; //http 报文长度

match_http(fp, "Host: ", "\r\n", host, http_len); //查找 host 值

match_http(fp, "GET ", "HTTP", uri, http_len); //查找 uri 值

sprintf(buf, "%d:  %s  src=%s:%d  dst=%s:%d  %s%s\r\n", i, my_time, src_ip, src_port, dst_ip, dst_port, host, uri);

//printf("%s", buf);

if(fwrite(buf, strlen(buf), 1, output) != 1)

{

printf("output file can not write");

break;

}

}

}

} // end while

fclose(fp);

fclose(output);

return 0;

}

//查找 HTTP 信息

void match_http(FILE *fp, char *head_str, char *tail_str, char *buf, int total_len)

{

int i;

int http_offset;

int head_len, tail_len, val_len;

char head_tmp[STRSIZE], tail_tmp[STRSIZE];

//初始化

memset(head_tmp, 0, sizeof(head_tmp));

memset(tail_tmp, 0, sizeof(tail_tmp));

head_len = strlen(head_str);

tail_len = strlen(tail_str);

//查找 head_str

http_offset = ftell(fp); //记录下HTTP报文初始文件偏移

while((head_tmp[0] = fgetc(fp)) != EOF) //逐个字节遍历

{

if((ftell(fp) - http_offset) > total_len) //遍历完成

{

sprintf(buf, "can not find %s \r\n", head_str);

exit(0);

}

if(head_tmp[0] == *head_str) //匹配到第一个字符

{

for(i=1; i<head_len; i++) //匹配 head_str 的其他字符

{

head_tmp[i]=fgetc(fp);

if(head_tmp[i] != *(head_str+i))

break;

}

if(i == head_len) //匹配 head_str 成功，停止遍历

break;

}

}

// printf("head_tmp=%s \n", head_tmp);

//查找 tail_str

val_len = 0;

while((tail_tmp[0] = fgetc(fp)) != EOF) //遍历

{
//if((ftell(fp) – http_offset) > total_len) //遍历完成
if((ftell(fp) - http_offset) > total_len) //遍历完成
{

sprintf(buf, "can not find %s \r\n", tail_str);

exit(0);

}

buf[val_len++] = tail_tmp[0]; //用buf 存储 value 直到查找到 tail_str

if(tail_tmp[0] == *tail_str) //匹配到第一个字符

{

for(i=1; i<tail_len; i++) //匹配 head_str 的其他字符

{

tail_tmp[i]=fgetc(fp);

if(tail_tmp[i] != *(tail_str+i))

break;

}

if(i == tail_len) //匹配 head_str 成功，停止遍历

{

buf[val_len-1] = 0; //清除多余的一个字符

break;

}

}

}

// printf("val=%s\n", buf);

fseek(fp, http_offset, SEEK_SET); //将文件指针 回到初始偏移

}
