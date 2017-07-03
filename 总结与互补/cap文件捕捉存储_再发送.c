int packet_number;   //指定发送的数据包数量

void send_complicated_file(pcap_t *store_adhandle,int send_stored_packet_packet_number);
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
void complicated_storePackets(pcap_t *store_adhandle);

void complicated_storePackets(pcap_t *store_adhandle)
{
    pcap_dumper_t *dumpfile;
    dumpfile = pcap_dump_open(store_adhandle, "dumpfile.cap");     //！！！！！！！！！！！！！！！！！！！！！
    if( dumpfile == NULL) {
        printf("Error on opening output .cap file\n");
        exit(-1);
    }
    pcap_loop(store_adhandle, packet_number, packet_handler, (u_char *)dumpfile);

    pcap_dump_close(dumpfile);
}
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    printf("store packets in xxx.cap\n");
     /* 保存数据包到堆文件 */
    pcap_dump((unsigned char*)dumpfile, pkt_header, pkt_data);
    return;
}

void send_complicated_file(pcap_t *store_adhandle,int send_stored_packet_packet_number)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];

    /* 根据新WinPcap语法创建一个源字符串 */
    if ( pcap_createsrcstr( source,         // 源字符串
                            PCAP_SRC_FILE,  // 我们要打开的文件
                            NULL,           // 远程主机
                            NULL,           // 远程主机端口
                            "dumpfile.cap",        // 我们要打开的文件名
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

    pcap_loop(fp, 0, dispatcher_handler, NULL);// 第二个参数 为0，表示遇到错误，才停止，为-1，表示无限循环

}
void dispatcher_handler(u_char *temp1,const struct pcap_pkthdr *header, const u_char *pkt_data)
{
//header->len 是包的长度，在header中声明   header->caplen是真实捕获的长度
//
//
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
    if ( pcap_sendpacket(adhandle,pBuf,MaxPacketLen)==-1)
    {
       printf("发送失败\n");
        return -1;
    }
    else{
        printf(".cap文件发送成功\n");
    }
     free(pBuf);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
    // 打印pkt时间戳和pkt长度
    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

    // 打印数据包
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }
*/
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
}
