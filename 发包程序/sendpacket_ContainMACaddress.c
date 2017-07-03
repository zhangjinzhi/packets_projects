#define WIN32
#define HAVE_REMOTE

#include <stdio.h>
#include "pcap.h"
#include "Win32-Extensions.h"

void genPacket(unsigned char *buf,int len);

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
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




    int MaxPacketLen=100;
    unsigned char *pBuf= (unsigned char *)malloc(MaxPacketLen);
    memset(pBuf,0x0,MaxPacketLen);
//获得生成的数据包，长度为MaxPacketLen
    genPacket(pBuf,MaxPacketLen);

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

    return 0;
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
