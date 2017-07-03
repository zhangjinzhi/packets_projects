咱们先来看看一个小程序，它实现的功能就是捕获用户指定设备的网络数据包并保存至文件。

#define HAVE_REMOTE
#include <pcap.h>
 
/* 回调函数原型 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
 
int main(int argc, char **argv)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t *dumpfile;
 
 
 
    /* 检查程序输入参数 */
    if(argc != 2)
    {
        printf("usage: %s filename", argv[0]);
        return -1;
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
        /* 释放列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
 
    /* 跳转到选中的适配器 */
    for(d=alldevs, i=0; i< inum-1 ; d=d->next, i++);
 
 
    /* 打开适配器 */
    if ( (adhandle= pcap_open(d->name,          // 设备名
                              65536,            // 要捕捉的数据包的部分
                              // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                             ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
 
    /* 打开堆文件 */
    dumpfile = pcap_dump_open(adhandle, argv[1]);
 
    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }
 
    printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);
 
    /* 释放设备列表 */
    pcap_freealldevs(alldevs);
 
    /* 开始捕获 */
    pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);
 
    return 0;
}
 
/* 回调函数，用来处理数据包 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /* 保存数据包到堆文件 */
    pcap_dump(dumpfile, header, pkt_data);
}
　
这个程序看起来不是那么地吃力，如果看过我之前写过的博客的话。dumpfile它是一个pcap_dumper结构体指针，
我们无从看到pcap_dumper结构体的定义，它也是WinPcap内核的一部分。文档上介绍它是一个libpcap文件描述符。
调用pcap_dump_open()函数只需要给两个参数，一个是接口指针，另一个是文件名，返回的是文件指针。
通过调用pcap_dump_open()这个函数我们就可以将文件和接口关联起来。
pcap_loop()回调函数里只有一行代码，pcap_dump()，它的作用是将网络数据写入文件。
这里我们需要注意一下pcap_loop()函数的给定，大致可以知道pcap_loop()最后一个参数是回调函数的一个用户参数。
看完了一个简单的写文件操作，下面咱们再看看如何从dump文件中将数据读取出来，仍然是给出一个实例。

#define HAVE_REMOTE
#include <stdio.h>
#include <pcap.h>
 
#define LINE_LEN 16
 
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
 
int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
 
    if(argc != 2)
    {
 
        printf("usage: %s filename", argv[0]);
        return -1;
 
    }
 
    /* 根据新WinPcap语法创建一个源字符串 */
    if ( pcap_createsrcstr( source,         // 源字符串
                            PCAP_SRC_FILE,  // 我们要打开的文件
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
    if ( (fp= pcap_open(source,         // 设备名
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
 
    return 0;
}
 
 
 
void dispatcher_handler(u_char *temp1,
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int i=0;
 
    /* 打印pkt时间戳和pkt长度 */
    printf("%ld:%ld (%u)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
 
    /* 打印数据包 */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }
 
    printf("\n\n");
 
}