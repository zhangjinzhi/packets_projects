#include <stdio.h>
#include <pcap.h>
#include <winsock.h>
#include <stdio.h>
#include "pcap.h"
#include "Win32-Extensions.h"
#include <time.h>
#include <pcap-stdinc.h>
#define WIN32
#define HAVE_REMOTE
#define LINE_LEN 16

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void genPacket(unsigned char *buf,int len);

int main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
char source[PCAP_BUF_SIZE];
argc = 2;
argv[0] = "E:\codeblockProject\test\readFile\bin\Debug\readFile.exe";
argv[1] = "dumpfile.cap";
//要是提前赋值，则不能再cmd中执行。
//如果没有提前赋值，则可以在cmd中执行。
    if(argc != 2){

        printf("usage: %s filename", argv[0]);
        return -1;

    }

    /* 根据新WinPcap语法创建一个源字符串 */
    if ( pcap_createsrcstr( source,         // 源字符串
                            PCAP_SRC_FILE,  // 我们要打开的文件   //dumpfile.cap
                            NULL,           // 远程主机
                            NULL,           // 远程主机端口
                            argv[1],        // 我们要打开的文件名
                            errbuf          // 错误缓冲区
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }

    /* 打开捕获文件 */
    if ( (fp= pcap_open(source,         // 设备名               //所用函数不一样！！！！！！！！！！！！！！！！！！！  
                        65536,          // 要捕捉的数据包的部分
                                        // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                         PCAP_OPENFLAG_PROMISCUOUS,     // 混杂模式
                         1000,              // 读取超时时间
                         NULL,              // 远程机器验证
                         errbuf         // 错误缓冲池
                         ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s.\n", source);
        return -1;
    }

    // 读取并解析数据包，直到EOF为真
    pcap_loop(fp, 0, dispatcher_handler, NULL);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



    return 0;
}

/*struct pcap_pkthdr
{
struct tim         ts;
      DWORD              caplen;
      DWORD              len;
}
1、时间戳，包括：
秒计时：32位，一个UNIX格式的精确到秒时间值，用来记录数据包抓获的时间，记录方式是记录从格林尼治时间的1970年1月1日 00:00:00 到抓包时经过的秒数；
微秒计时：32位， 抓取数据包时的微秒值。
a time stamp, consisting of:
a UNIX-format time-in-seconds when the packet was captured, i.e. the number of seconds since January 1,1970, 00:00:00 GMT (that GMT, *NOT* local time!);  
the number of microseconds since that second when the packet was captured;
 
2、数据包长度：32位 ，标识所抓获的数据包保存在pcap文件中的实际长度，以字节为单位。
a 32-bit value giving the number of bytes of packet data that were captured;
 
3、数据包实际长度： 所抓获的数据包的真实长度，如果文件中保存不是完整的数据包，那么这个值可能要比前面的数据包长度的值大。
a 32-bit value giving the actual length of the packet, in bytes (which may be greater than the previous number, if you are not saving the entire packet).
*/
void dispatcher_handler(u_char *temp1,
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    int i=0;

    /* 打印pkt时间戳和pkt长度 */
    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

    /* 打印数据包 */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }

    printf("\n\n");
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret=-1;

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



//header->len  还是 header->caplen  
//http://www.cnblogs.com/kernel0815/p/3803304.html
    int MaxPacketLen=header->len;              //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    unsigned char *pBuf= (unsigned char *)malloc(MaxPacketLen);
    memset(pBuf,0x0,MaxPacketLen);
//生成的数据包，长度为MaxPacketLen
//////////////////////////////////////////////////////
   // genPacket(pBuf,MaxPacketLen); 
      for (int k = 0; k < header->caplen; k++)
    {
        pBuf[k] = pkt_data[k];
    }
     for(int j=header->caplen;j<MaxPacketLen;j++)
    {
           pBuf[j]=1;
    }
 ////////////////////////////////////////////////////////////
    if ( (ret=pcap_sendpacket(adhandle,pBuf,MaxPacketLen))
==-1)
    {
       printf("发送失败\n");
       pcap_close(adhandle);
        pcap_freealldevs(alldevs);
        return -1;
    }

     free(pBuf);
     pcap_close(adhandle);
     pcap_freealldevs(alldevs);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



}
/*
void genPacket(unsigned char *buf,int len)
{    
     for (int i = 0; i < header->caplen; i++)
    {
        pBuf[i] = pkt_data[i];
    }
     for(int j=header->caplen;j<MaxPacketLen;j++)
    {
           buf[j]=1;
    }
}
*/