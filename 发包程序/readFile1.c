#include <stdio.h>
#include <pcap.h>
#include <winsock.h>
#include <stdio.h>
#include "pcap.h"
#include "Win32-Extensions.h"
#include <time.h>
#include <pcap-stdinc.h>

#define LINE_LEN 16

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char **argv)
{
    char *err;
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
char source[PCAP_BUF_SIZE];
argc = 2;
argv[0] = "E:\codeblockProject\test\readFile\bin\Debug\readFile.exe";
argv[1] = "dumpfile.cap";
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

     fp=pcap_open_offline("dumpfile.cap",err);                         //所用函数不一样！！！！！！！！！！！！！！！！！！！
    // 读取并解析数据包，直到EOF为真
    pcap_loop(fp, 0, dispatcher_handler, NULL);

    return 0;
}



void dispatcher_handler(u_char *temp1,
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int i=0;

    /* 打印pkt时间戳和pkt长度 */
    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

    /* 打印数据包 */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }

    printf("\n\n");

}
