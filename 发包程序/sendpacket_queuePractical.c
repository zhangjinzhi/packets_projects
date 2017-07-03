#define WIN32
#define HAVE_REMOTE
#include <winsock.h>
#include <stdio.h>
#include "pcap.h"
#include "Win32-Extensions.h"
#include <time.h>

void send_queue(pcap_t *fp,unsigned int npacks,unsigned int dus);
void genPacket(unsigned char *buf,int len);
//timeval add_stamp(timeval *ptv,unsigned int dus);

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;          //定义文件句柄
    char errbuf[PCAP_ERRBUF_SIZE];


if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,
&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs:%s\n", errbuf);
        exit(1);
    }


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
        printf("\nNo interfaces found!Make sure WinPcap is installed.\n");
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


if ( (adhandle= pcap_open(d->name, 65536,
     PCAP_OPENFLAG_PROMISCUOUS, 1000,NULL, errbuf  ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter.%s is not supported by WinPcap\n", d->name);

        pcap_freealldevs(alldevs);
        return -1;
    }


    printf("\nlistening on %s...\n", d->description);


    send_queue(adhandle,100,20);

     pcap_close(adhandle);
    pcap_freealldevs(alldevs);

    return 0;
}

void send_queue(pcap_t *fp,unsigned int npacks,unsigned int dus)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;
    unsigned int res;


    pcap_send_queue *squeue;        //发送队列
    const int MaxPacketLen=100;     //数据包长度

    struct pcap_pkthdr mpktheader;  //数据包的包头
    struct pcap_pkthdr *pktheader;
    pktheader=&mpktheader;

 /*  timeval tv;                   //时间戳
    tv.tv_sec=0;
    tv.tv_usec=0;
 */
    //分配发送队列
    squeue=pcap_sendqueue_alloc(
        (unsigned int)(
(MaxPacketLen+sizeof(struct pcap_pkthdr))*npacks));

    //用数据包填充发送队列
  //  unsigned char *pBuf= unsigned char[MaxPacketLen];
        unsigned char *pBuf= (unsigned char *)malloc(MaxPacketLen);
    for(i=0;i<npacks;i++)
    {
       memset(pBuf,0x0,MaxPacketLen);
//获得生成的数据包，长度为MaxPacketLen
       genPacket(pBuf,MaxPacketLen);
       //设置数据包的包头
//       pktheader->ts=tv;
       pktheader->caplen = MaxPacketLen;
       pktheader->len = MaxPacketLen;
       if (pcap_sendqueue_queue(squeue, pktheader, pBuf) == -1)
        {
            printf("警告: 数据包缓冲区太小，不是所有的数据包被发送.\n");
            return;
        }
 //      add_stamp(&tv,dus);  //增加时间戳
   //    pktheader->ts=tv;    //更新数据包头的时间戳
    }
   // delete [] pBuf;
    free(pBuf);
    //发送数据包
if ((res = pcap_sendqueue_transmit(fp, squeue, 1))
 < squeue->len)//同步发送
        {
        printf("发送数据包时出现错误：%s. 仅%d字节被发送\n",
           pcap_geterr(fp), res);
       return;
    }

    //释放发送队列
    pcap_sendqueue_destroy(squeue);

    return;
}

void genPacket(unsigned char *buf,int len)
{
       int i;
       //设置目标MAC地址为60:02:B4:FB:7A:D9
           buf[0]=0x80;
           buf[1]=0xFA;
           buf[2]=0x5B;
           buf[3]=0x00;
           buf[4]=0xFC;
           buf[5]=0xD1;

       //设置源MAC地址为60:02:B4:FB:7A:D9
            buf[6]=0x80;
            buf[7]=0xFA;
            buf[8]=0x5B;
            buf[9]=0x00;
           buf[10]=0xFC;
           buf[11]=0xD1;
       //设置协议标识为xc0xd，无任何实际意义
       buf[12]=0xc;
       buf[13]=0xd;
       //填充数据包的内容
       for(i=14;i<len;i++)
       {
           buf[i]=i-14;
       }
}

/*timeval add_stamp(timeval *ptv,unsigned int dus)
{
    ptv->tv_usec=ptv->tv_usec+dus;
    if(ptv->tv_usec>=1000000)
    {
       ptv->tv_sec=ptv->tv_sec+1;
       ptv->tv_usec=ptv->tv_usec-1000000;
    }
    return *ptv;
}
*/
