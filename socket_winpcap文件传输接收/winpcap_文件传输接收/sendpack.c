#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <remote-ext.h>
int main(void)
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *outdesc;//输出设备
    FILE *inFile;//操作的文件
    long int fileLen;//文件长度
    pcap_send_queue *squeue;//发送队列
    struct pcap_pkthdr pktheader;//包的头部结构
	u_int res;
    int PakLen = 1036;//包长，包括12个字节的MAC头部
	int DataLen = PakLen-12;//每个包的原始数据长度
	int PakNumTxPerTimes = 100;//每次发这么多个包
	int Times=0;//总共发多少次
	int LastTimeSendPackNum;
    u_char *pktdata = (u_char*)malloc(PakLen);//分配存放数据的内存
	float cpu_time;
	int errorCnt=0;
	int totalPakNum; //总包数=文件总长/每个包的长度
	int LastDataLen;
	int t;
	int p;
	int j;
    /* Retrieve the length of the capture file */
    inFile=fopen("F:\\1\\2.doc","rb");//打开文件
	//outFile = fopen("D:\\2.mp4","wb");
    fseek(inFile , 0, SEEK_END);//打开文件末尾
    fileLen= ftell(inFile);//文件长度
	fseek(inFile,0,0);//返回文件头部

//////////////////////////////////////////////////////////////
//    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
//    pcap_t *outdesc;
//    char errbuf[PCAP_ERRBUF_SIZE];
    int ret=-1;
//以下为打开某个网卡
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

    int input_NetInterface_number;
    scanf("%d", &input_NetInterface_number);

    if(input_NetInterface_number < 1 || input_NetInterface_number > i)
    {
        printf("\nInterface number out of range.\n");

        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i< input_NetInterface_number-1 ;d=d->next, i++);
//adhandle is a adaptor handler
/* Open the output device */
if ( (outdesc= pcap_open(d->name, 65536,
PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL,errbuf) )
== NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

        pcap_freealldevs(alldevs);
        return -1;
    }

      printf("\nlistening on %s...\n", d->description);

//////////////////////////////////////////////////////////////////////////////////////////////

//	pcap_findalldevs(&alldevs, errbuf);//查找设备
//	outdesc = pcap_open_live(alldevs->name,65536,1,	10,errbuf	);//打开网卡
	totalPakNum = fileLen/DataLen; //总包数=文件总长/每个包的长度
	LastDataLen= fileLen-DataLen*totalPakNum;
	if (LastDataLen>0)//如果分包后，还有剩余不足一包的数据
		totalPakNum = totalPakNum+1;
	fileLen = DataLen*totalPakNum;//补足一个包
	squeue = pcap_sendqueue_alloc(PakNumTxPerTimes*(PakLen+16)*2);//队列容量可设为 PakNumTxPerTimes*(PakLen+16),16为2个时间戳的字节数

	Times=totalPakNum/PakNumTxPerTimes;
    LastTimeSendPackNum = totalPakNum-PakNumTxPerTimes*Times;//如果不足50;
	if(LastTimeSendPackNum>0)//最后一次发送这么多包
		Times = Times+1;//总次数


// 	pktdata[0]=0x00;
// 	pktdata[1]=0x1B;
// 	pktdata[2]=0x38;
// 	pktdata[3]=0x9D;
// 	pktdata[4]=0x0B;
// 	pktdata[5]=0x95;
	pktdata[0]=0x80;
	pktdata[1]=0xFA;
	pktdata[2]=0x5B;
	pktdata[3]=0x00;
	pktdata[4]=0xFC;
	pktdata[5]=0xD1;
/* set mac source to 2:2:2:2:2:2 */
	pktdata[6]=0x80;
	pktdata[7]=0xFA;
	pktdata[8]=0x5B;
	pktdata[9]=0x00;
   pktdata[10]=0xFC;
   pktdata[11]=0xD1;

	pktheader.len=PakLen;
	pktheader.caplen = PakLen;
	memset((void *)&(pktheader.ts),0,sizeof(struct timeval));
	cpu_time = (float)clock();
	//每次发50个包
	for (t=0;t<Times;t++)
	{
		if(t==Times-1 && LastTimeSendPackNum>0)
			PakNumTxPerTimes = LastTimeSendPackNum;
		for (p=0;p<PakNumTxPerTimes;p++)//放50个包进队列
		{
			if(p==PakNumTxPerTimes-1 && t==Times-1 && LastTimeSendPackNum>0 && LastDataLen>0)
			{
				pktheader.len=LastDataLen+12;
				pktheader.caplen = LastDataLen+12;
				PakLen = LastDataLen+12;
			}
			for(j=12;j<PakLen;j++)
			{
				pktdata[j]=(u_char)fgetc(inFile);
				//fputc(pktdata[j],outFile);
			}
			pcap_sendqueue_queue(squeue, &pktheader, (const u_char*)pktdata);
		}
		res=pcap_sendqueue_transmit(outdesc, squeue, 0);
		if(res!=squeue->len)
		{
			printf("send error！");
			errorCnt = errorCnt+1;
		}
		else
		{
			printf("send %d\n",res);
		}
		squeue->len=0;
		Sleep(2);
	}
	//发送最后一个空包，指示发送完毕
	pktheader.caplen=100;
	pktheader.len=100;
	for(j=12;j<100;j++)
		pktdata[j]=0;
	pcap_sendqueue_queue(squeue, &pktheader, (const u_char*)pktdata);
	res=pcap_sendqueue_transmit(outdesc, squeue, 0);
	pcap_sendqueue_destroy(squeue);
	cpu_time = (clock()-cpu_time)/CLK_TCK;
	printf("Time Consuming: %5.3f\n",cpu_time);                          //耗时
	printf("Speed: %5.3fMB\n",fileLen/cpu_time/1e6);            //速率
	printf("Error Number:  %d\n",errorCnt);                          //错误次数
	free(pktdata);
	fclose(inFile);
	//fclose(outFile);
	return 0;
}

