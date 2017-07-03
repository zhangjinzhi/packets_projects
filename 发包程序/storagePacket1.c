#define _CRT_SECURE_NO_WARNINGS
#include <winsock.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>
#include "pcap.h"
#include <pcap/pcap.h>
#include <sys/types.h>
#include <pcap-bpf.h>
/* 回调函数原型 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

main(int argc, char **argv)
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
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    
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
    
    pcap_dump_close(dumpfile);
    return 0;
}

/* 回调函数，用来处理数据包 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /* 保存数据包到堆文件 */
    pcap_dump(dumpfile, header, pkt_data);
}