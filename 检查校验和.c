//计算校验和
unsigned short checksum(unsigned short *buffer, int size) 
{ 
    register  unsigned long cksum=0; 
    while(size >1) 
    { 
        cksum+=*buffer++; 
        size -=sizeof(unsigned short); 
    } 
    if(size) 
        cksum += *(unsigned short*)buffer; 
    
    cksum = (cksum >> 16) + (cksum & 0xffff); 
    cksum += (cksum >>16); 
    return (unsigned short)(~cksum); 
}

USHORT CheckSum(USHORT *buffer, int size)
{
    unsigned long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }

    if (size)
    {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);

    return (USHORT)(~cksum);
}

/**********************************************************************
* 函数名称：ipcrcCheck
* 功能描述：判断收到的ip报文的ip校验和是否正确
* 输入参数：
  ipHdr    收到报文的ip头
*  输出参数：无
* 返 回 值：
    校验和正确
    校验和错误
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int ipcrcCheck(struct ip *ipHdr)            
{
    unsigned short crcPacket;
    unsigned short crcCheck;
    
                
    crcPacket = ntohs(ipHdr->ip_sum);
    ipHdr->ip_sum = 0;
    crcCheck = checksum((unsigned short *)ipHdr,sizeof(struct ip));
    if(crcPacket != crcCheck)
    {
         printf("ip crc check wrong ...packet(%02x), my(receive %x)---\n", crcPacket, crcCheck);
         return ERR_IP_CRCC_WRONG;
    }
    else
    {
        printf("ip crc:packet %x, my %x---\n", crcPacket, crcCheck);
    }
    ipHdr->ip_sum = crcCheck;
    return PACKET_OK;       
}        


/**********************************************************************
* 函数名称：udpcrcCheck
* 功能描述：判断收到的ip报文的udp校验和是否正确
* 输入参数：
  ipHdr    收到报文的ip头
*  输出参数：无
* 返 回 值：
    校验和正确
    校验和错误
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int udpcrcCheck(struct ip *ipHdr)            
{
    unsigned short crcPacket;
    unsigned short crcCheck;
    unsigned short packet_ip_sum;
    unsigned char packet_ip_ttl;
    unsigned char packet_ip_p;
    unsigned short *pcrckBufBegin;
    
    struct udphdr  udpHdr;
    
    udpHdr = (struct udphdr *)(ipHdr + IP_HDR_LEN);
            
    packet_ip_ttl =  ipHdr->ip_ttl;           /* 8bit */
    packet_ip_p   =  ipHdr->ip_p;                /*  8bit */
    packet_ip_sum =  ntohs(udpHdr->uh_ulen);          /* 16bit  check crc */
    crcPacket     =  ntohs(udpHdr->uh_sum);
            
    printf("udpHdr->uh_ulen:%x", ntohs(udpHdr->uh_ulen));
            
    /* 伪首部初始化 */
    ipHdr->ip_ttl = 0;                          /* 8bit */
    ipHdr->ip_p   = IPPROTO_UDP;                /*  8bit */
    ipHdr->ip_sum =  ntohs(udpHdr->uh_ulen);    /* 16bit  check crc */
    ipHdr->ip_src.s_addr = inet_addr("10.16.8.51"); /* 32bit */
    ipHdr->ip_dst.s_addr = inet_addr("10.16.8.54"); /* 32bit */
            
    udpHdr->uh_sum = 0;
    pcrckBufBegin   = (unsigned short *)(&ipHdr->ip_ttl);
            
    crcCheck = checksum(pcrckBufBegin, ntohs(udpHdr->uh_ulen));
            
    if(crcCheck != crcPacket)
    {
        printf("udp crc wrong:packet(%x), (receive %x)---\n", crcPacket, crcCheck);
        return ERR_UDP_CRC_WRONG;
    }
    else
    {
        printf("udp crc :packet(%x), (receive %x)---\n", crcPacket, crcCheck);
    }
    return PACKET_OK;
}
