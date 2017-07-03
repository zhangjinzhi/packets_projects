void send_simple_file(pcap_t *store_adhandle,int send_stored_packet_packet_number);
void simple_storePackets( pcap_t *store_adhandle, char *store_ucSend,   int simple_store_datasize);

   int packetNumber;

   printf("Do you want to store the data of packets in order to use it next time\ninput 0 or 1 to choose NO or YES\n");
   int store_or_not;
   scanf("%d",&store_or_not);
   printf("\n");
   if(store_or_not == 1)
   {
       simple_storePackets(_adhandle,ucSend,datasize);
   }
   if(store_or_not == 0)
   {
    for(int k = 0; k < packetNumber; k++)
    if ( 0 != pcap_sendpacket(_adhandle, (const unsigned char *)ucSend, datasize ) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send successfully without storing packets\n");
    }
    system("pause");
   }




void simple_storePackets( pcap_t *store_adhandle,char *store_ucSend, int simple_store_datasize)
{
 FILE* wc =fopen("keep.dat","wb");
  if(wc==NULL) {
        printf("failed to open file\n");
        system("pause");
    }

 fwrite( store_ucSend, simple_store_datasize, 1, wc );
 fclose(wc);
 for(int k = 0; k < packet_number; k++)
    if ( 0 != pcap_sendpacket(store_adhandle, (const unsigned char *)store_ucSend, simple_store_datasize ) )
    {
        printf("send failed.\n");
    }
    else
    {
        printf("send successfully and  store in .dat file successfully\n");
    }

}


void send_simple_file(pcap_t *store_adhandle,int send_stored_packet_packet_number)
{
    int simple_store_datasize;
    char use_store_ucSend[1600];
    FILE *fp=fopen( "keep.dat", "rb" );//b表示以二进制方式打开文件
    if( fp == NULL ) //打开文件失败，返回错误信息
    {
        printf("open file for read error\n");
        system("pause");
    }
    fseek (fp, 0, SEEK_END);
    simple_store_datasize=ftell(fp);
    printf("size=ftell (fp)=%d\n",simple_store_datasize);
    fclose(fp);//关闭文件

    fp=fopen( "keep.dat", "rb" );//b表示以二进制方式打开文件
    if( fp == NULL ) //打开文件失败，返回错误信息
    {
        printf("open file for read error\n");
        system("pause");
    }
    fread( use_store_ucSend, simple_store_datasize, 1, fp );
    fclose(fp);//关闭文件
    for(int k = 0; k < send_stored_packet_packet_number; k++)
    if ( 0 != pcap_sendpacket(store_adhandle, (const unsigned char *)use_store_ucSend, simple_store_datasize ) )
    {
        printf("use .dat file to send failed.\n");
    }
    else
    {
        printf(" use .dat file to send success.\n");
    }
}
