#define _CRT_SECURE_NO_WARNINGS
#include <winsock.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>
#include "pcap.h"
#include <pcap/pcap.h>
#include <sys/types.h>
#include <pcap-bpf.h>
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);

int main()
{
	pcap_t *cap_ins_des;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char source[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	int inum;
    int i=0;
	u_int netmask;
	char packet_filter[] = "ip and udp";	// the filter
	struct bpf_program fcode;	// used in pcap_compile()
	pcap_dumper_t *dumpfile;

	/* set the source */
	if (pcap_createsrcstr(source, PCAP_SRC_IFLOCAL, NULL, NULL, NULL, errbuf) == -1) {
		printf("%s\n", errbuf);
		exit(-1);
	}
	printf("source: %s\n", source);

	/* find all devices */
	if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == -1) {
		printf("%s\n", errbuf);
		exit(-1);
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
 
	printf("selected device: %s\n", d->name);

	/* open one device */ 
	cap_ins_des = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (cap_ins_des == NULL) {
		printf("%s\n", errbuf);
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	/* get the netmask, used at compiling the filter */
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;	/*@#$%^&*!*/
	else
		netmask = 0xffffff;	/* 255.25.255.0 */

	// netmask = 0;

	/* compile the filter */       //char packet_filter[] = "ip and udp";  if (pcap_compile(cap_ins_des, &fcode, "ip and udp", 1, netmask) < 0)
	if (pcap_compile(cap_ins_des, &fcode, packet_filter, 1, netmask) < 0) {  
		printf("Error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	/* set the filter */
	if (pcap_setfilter(cap_ins_des, &fcode) < 0) {
		printf("Error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	/* open a file to dump data */
	dumpfile = pcap_dump_open(cap_ins_des, "dumpfile5.cap");     //！！！！！！！！！！！！！！！！！！！！！
	if( dumpfile == NULL) {
		printf("Error on opening output file\n");
		exit(-1);
	}

	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(cap_ins_des, 30, packet_handler, (u_char *)dumpfile);

	pcap_dump_close(dumpfile);

	return 0;
}
/* 回调函数，用来处理数据包 */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{   
	printf("in packet handler\n");
	 /* 保存数据包到堆文件 */
	pcap_dump((unsigned char*)dumpfile, pkt_header, pkt_data);
	return;
}