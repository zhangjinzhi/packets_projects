#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
int main(void)
{
	pcap_if_t *alldevs;
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filter = NULL;
	int PakLen = 1036;
	struct bpf_program fcode;
	bpf_u_int32 NetMask;
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;//=(unsigned char*)malloc(PakLen+12);
	FILE *fout;
	int valied=1;
	int PakErrIdx=0;
	int j;
	int i;
	fout=fopen("F:\\1\\5.doc","wb");
 	fseek(fout,0,SEEK_END);
// 	int a=ftell(fout);
	pcap_findalldevs(&alldevs, errbuf);
	/* 打开网卡 */
	fp = pcap_open_live(alldevs->name,65536,1,20,errbuf);

	filter ="(ether src 00:1B:38:9D:0B:95)and(ether dst 90:E6:BA:90:E1:01)";
	//filter ="(ether src 80:FA:5B:00:FC:D1)and(ether dst 80:FA:5B:00:FC:D1)";
	NetMask=0xffffff;
	//compile the filer
	pcap_compile(fp, &fcode, filter, 1, NetMask);
	//set the filter
	pcap_setfilter(fp, &fcode);

	while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
	{
		if(res==0)
			continue;
		//pcap_dump((unsigned char *) dumpfile, header, pkt_data);
		//printf("%0x,%0x,%d,%d\n",header->ts.tv_sec,header->ts.tv_usec,header->caplen,header->len);
        PakErrIdx = PakErrIdx+1;
		if (header->caplen==100)
		{
			valied=0;
			printf("%s\n","end?");
			for (j=12;j<100;j++)
			{
				valied+=pkt_data[j];
			}
		}
 		if((header->caplen)<PakLen)
		{
			printf("samll:%d,%d\n",PakErrIdx,header->caplen);
 			memset((void*)pkt_data,0,PakLen+12);
 			 		}
		if (!valied)
			break;
 		for(j=12;j<(header->caplen);j++)
 			fputc(pkt_data[j],fout);
// 		if(header->caplen<PakLen)
// 		{
// 			for (i=0;i<PakLen-header->caplen;i++)
// 				fputc(0,fout);
// 		}
		//memset((void*)pkt_data,0,PakLen+12);
	}
	printf("The number of packets received: %d",PakErrIdx);
	fclose(fout);
	pcap_close(fp);
	getchar();
	return 0;
}

