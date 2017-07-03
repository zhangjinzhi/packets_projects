/**********************************************************
* 版权所有 (C)2007, 深圳市中兴通讯股份有限公司。
*
* 文件名称：packet_gen.c
* 文件标识：
* 内容摘要： 模拟ENPU演示程序处理函数
* 其它说明：
* 当前版本：
* 作    者：丁 鹏
* 完成日期：2007/12/11
*
* 修改记录1：   
*    修改日期： 
*    版 本 号：
*    修 改 人：                    
*    修改内容：
**********************************************************/

/***********************************************************
 *                      头文件                             *
***********************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/***********************************************************
 *                     全局变量                            *
***********************************************************/
unsigned short ip_id;



/***********************************************************
 *                     全局函数                            *
***********************************************************/
void UdpHdrGen(struct udphdr *udpHdr, unsigned short int idport, unsigned short int isport, unsigned short int msglen);
void IpHdrGen(struct ip *ipHdr, unsigned char *sdaddr, unsigned char *ssaddr, unsigned int msglen, unsigned char proto);
void ethHdrGen(struct ethhdr *ethhdr, unsigned char *cdmac, unsigned char *csmac);
unsigned short checksum(unsigned short *buffer, int size);
int getMac(unsigned char *ipaddr, unsigned char *mac);


/**********************************************************************
* 函数名称：UdpHdrGen
* 功能描述：构造udp头
* 输入参数：
  udpHdr     构造的udp头的存放地址
  idport     源udp端口
  isport     目的udp端口
  msglen     udp负荷长度，不包括udp头长
* 输出参数：无
* 返 回 值：无
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
void UdpHdrGen(struct udphdr *udpHdr, unsigned short int idport, unsigned short int isport, unsigned short int msglen)
{
    if(udpHdr == NULL)
    {
        printf("UdpHdrGen get udpHdr err\n");
        return ;
    }
    udpHdr->uh_dport = htons(idport);
    udpHdr->uh_sport = htons(isport);
    udpHdr->uh_ulen  = htons(msglen+sizeof(struct udphdr));  /* updhdr + msgdatalen */
    udpHdr->uh_sum   = 0;
}

/**********************************************************************
* 函数名称：IpHdrGen
* 功能描述：构造IP头
* 输入参数：
  ipHdr     构造的ip头的存放地址
  sdaddr     源IP地址
  ssaddr     目的udp端口
  msglen     发送消息体长度，不包括upd头，ip头，eth头
  proto
* 输出参数：无
* 返 回 值：无
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
void IpHdrGen(struct ip *ipHdr, unsigned char *sdaddr, unsigned char *ssaddr, unsigned int msglen, unsigned char proto)
{
       
    if( ipHdr == NULL)
    {
        printf("IpHdrGen get ipHdr err\n");
        return ;
    }

    ipHdr->ip_hl = 5;  /* ip_hl << 2 ----ip头长度，这里我们选为标准的20字节 */
    ipHdr->ip_v  = 4;   /* ip版本, ipv4 */
    ipHdr->ip_tos = 0;  /* normal service */ /*这个8bit字段由3bit的优先权子字段（现在已经被忽略），4 bit的TOS子字段以及1 bit的未用字段（现在为 
                                             0）构成。4 bit的TOS子字段包含：最小延时、最大吞吐量、最高可靠性以及最小费用 
                                             构成，这四个1 bit位最多只能有一个为1，本例中都为0，表示是一般服务。 */
    ipHdr->ip_len = htons(msglen + sizeof(struct udphdr)+sizeof(struct ip)); /* 包括ip头长 */
    ipHdr->ip_id  = htons(ip_id++); /* 包括ip头长 */
    ipHdr->ip_off = 0; /* 其中第一位是IP协议目前没有用上的，为0。接着的是两个标志DF和MF。
                          DF为1表示不要分段，MF为1表示还有进一步的分段（本例为0）。
                          然后的“0 0000”是分段片移（Fragment Offset）。 */
    ipHdr->ip_ttl = IPDEFTTL; /* time to live, 64 by default，linux */
    ipHdr->ip_p   = proto;
    ipHdr->ip_sum = 0; /*   check crc */
    
    ipHdr->ip_src.s_addr = inet_addr(ssaddr);
    ipHdr->ip_dst.s_addr = inet_addr(sdaddr);
    ipHdr->ip_sum = htons(checksum((unsigned short *)ipHdr,sizeof(struct ip)));
 
}
/**********************************************************************
* 函数名称：ethHdrGen
* 功能描述：构造eth头
* 输入参数：
  ipHdr     构造的eth头的存放地址
  sdmac     源MAC地址
  ssmac     目的方MAC地址
*  输出参数：无
* 返 回 值：无
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
void ethHdrGen(struct ethhdr *ethhdr, unsigned char *sdmac, unsigned char *ssmac)
{
    memcpy(ethhdr->h_dest,sdmac, ETH_ALEN);
    memcpy(ethhdr->h_source,ssmac, ETH_ALEN);
    ethhdr->h_proto = htons(ETH_P_IP);
}    
/**********************************************************************
* 函数名称：checksum
* 功能描述：校验和计算
* 输入参数：
  buffer    开始地址处，从这开始计算内存内容的校验和
  size      计算多少个字节的校验和
*  输出参数：
* 返 回 值：校验和数值
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
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

/**********************************************************************
* 函数名称：getMac
* 功能描述：取得MAC地址
* 输入参数：
  ipaddr    ip地址
*  输出参数：
   Mac      对应ip的MAC地址
* 返 回 值：
    对应ip地址的序列号
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int getMac(unsigned char *ipaddr, unsigned char *Mac)
{
    int ret = 0;
    printf("ipaddr:%s", ipaddr);
    if(rules_memcmp(ipaddr, "10.16.8.53", sizeof("10.16.8.53")) == 0)
    {
        *(unsigned char *)Mac=0x00;
        *(unsigned char *)(Mac+1)=0x11;
        *(unsigned char *)(Mac+2)=0x5B;
        *(unsigned char *)(Mac+3)=0x29;
        *(unsigned char *)(Mac+4)=0x7F;
        *(unsigned char *)(Mac+5)=0x3A; 
        ret = 1;
        
    }
    else  if(rules_memcmp(ipaddr, "10.16.8.55", sizeof("10.16.8.55")) == 0)
    {
        *(unsigned char *)Mac=0x00;
        *(unsigned char *)(Mac+1)=0x11;
        *(unsigned char *)(Mac+2)=0x85;
        *(unsigned char *)(Mac+3)=0xBA;
        *(unsigned char *)(Mac+4)=0xE9;
        *(unsigned char *)(Mac+5)=0x18; 
        ret = 2;
    }
    else  if(rules_memcmp(ipaddr, "10.16.8.51", sizeof("10.16.8.51")) == 0)
    {
        *(unsigned char *)Mac=0x00;
        *(unsigned char *)(Mac+1)=0x0E;
        *(unsigned char *)(Mac+2)=0x0C;
        *(unsigned char *)(Mac+3)=0x50;
        *(unsigned char *)(Mac+4)=0x72;
        *(unsigned char *)(Mac+5)=0x32; 
        ret = 3;
    }
    else  if(rules_memcmp(ipaddr, "10.16.8.63", sizeof("10.16.8.63")) == 0)
    {
        *(unsigned char *)Mac=0x00;
        *(unsigned char *)(Mac+1)=0x15;
        *(unsigned char *)(Mac+2)=0x58;
        *(unsigned char *)(Mac+3)=0x12;
        *(unsigned char *)(Mac+4)=0x9E;
        *(unsigned char *)(Mac+5)=0x5E; 
        ret = 4;
    }
    else  if(rules_memcmp(ipaddr, "10.16.8.54", sizeof("10.16.8.54")) == 0)
    {
        *(unsigned char *)Mac=0x00;
        *(unsigned char *)(Mac+1)=0x12;
        *(unsigned char *)(Mac+2)=0x79;
        *(unsigned char *)(Mac+3)=0xD0;
        *(unsigned char *)(Mac+4)=0x71;
        *(unsigned char *)(Mac+5)=0x9D; 
        ret = 5;
    }
    else
    {
        ret = 0;
    }
    return ret;    
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

/**********************************************************************
* 函数名称：packetSend
* 功能描述：发送报文
* 输入参数：
  len     发送报文长度
  pktBuf  发送报文的地址，包括eth，ip，udp头
  ptoaddr 发送的地址
*  输出参数：无
* 返 回 值：
    发送成功
    发送失败    
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int packetSend(unsigned int len, unsigned char *pktBuf, struct sockaddr_ll *ptoaddr)
{
    int sendLen = 0;
    int ret     = 0;    
    unsigned char *pSendBuf;
    
    if(NULL == pktBuf || len == 0)
    {
        return ERR_PACKET_SEND;
    } 
    pSendBuf =  pktBuf;
    sendLen  =  len;
    while(sendLen > 0)
    {
        ret = sendto(sockfd, pSendBuf, sendLen, 0, (struct sockaddr *)ptoaddr, sizeof(ptoaddr));
        if(ret < 0)
        {
            perror("sendto err");
            return ERR_PACKET_SEND;
        }
        else
        {
            sendLen -= ret;
            pSendBuf += ret;
        }
    }
    return PACKET_SEND_OK;
}                

/**********************************************************************
* 函数名称：packetBuild
* 功能描述：构造发送到外网去的数据包
* 输入参数：
  fib_addr     转发规则，用来判断要发到哪些外网口
  cmsgDatabuf  构造报文所存放的地址
  localIp      本地ip，字符串形式
  sport        发送源端口
  dport        发送目的端口
*  输出参数：
* 返 回 值：
    构造成功
    构造失败    
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int packetBuild(struct fib_address *fib_addr, unsigned char *cmsgDatabuf, unsigned char *localIp, unsigned short sport, unsigned short dport)
{
    unsigned char *pktBuf;
    unsigned char *puicrckBufBegin;
    struct udphdr *udpHdr;
    struct ethhdr *ethHdr;
    unsigned char dstMac[ETH_ALEN+1]={0};
    unsigned char srcMac[ETH_ALEN+1]={0};
     
    if((NULL == fib_addr_next) || (NULL == cmsgDatabuf))
    {
        printf("packetBuild: arg err\n");
        return ERR_GENERR;
    }
    /* build send packet */
    /* build udphdr */
    pktBuf = (unsigned char *)cmsgDatabuf;
    udpHdr = (struct udphdr *)(pktBuf + uiEthHdrLen + uiIpHdrLen);
    UdpHdrGen(udpHdr, dport, sport, msgDataLen);
    /* builde iphdr */       
    psDstAddr = inet_ntoa(fib_addr->ip_dst);
    psSrcAddr = LocalIp;
    ipHdr = (struct ip *)(pktBuf + sizeof(struct ethhdr));
    ipHdr->ip_ttl = 0;                        /* 8bit */
    ipHdr->ip_p = IPPROTO_UDP;                /*  8bit */
    ipHdr->ip_sum = udpHdr->uh_ulen;           /* 16bit  check crc */
    ipHdr->ip_src.s_addr = inet_addr(psSrcAddr); /* 32bit */
    ipHdr->ip_dst.s_addr = inet_addr(psDstAddr); /* 32bit */
    
    
    puicrckBufBegin = (unsigned short *)&(ipHdr->ip_ttl);
    udpHdr->uh_sum  = checksum(puicrckBufBegin, msgDataLen + FAKE_IP_HEAD + 8);
    if (0 == udpHdr->uh_sum) 
    {
        udpHdr->uh_sum = 0xffff;
    }
    IpHdrGen(ipHdr, psDstAddr, psSrcAddr, msgDataLen, IPPROTO_UDP);
              
    /* build ethhdr */
    ret = getMac(psDstAddr, dstMac);
    if(ret == 0)
    {
        printf("no %s mac , err\n", dstMac);
        return ERR_GENERR;
    }
    printf("dst ret:%d\n",ret);
    dstMac[ETH_ALEN+1]='\0';
    ret = getMac(psSrcAddr, srcMac);
    if(ret == 0)
    {
        printf("no %s mac , err\n", srcMac);
        return ERR_GENERR;
    }
    srcMac[ETH_ALEN+1]='\0';
    psrcMac=&srcMac[0];
    pdstMac=&dstMac[0];
    
    ethHdr = (struct ethhdr *)pktBuf;
    ethHdrGen(ethHdr, dstMac, srcMac);
}


/**********************************************************************
* 函数名称：Handle_Externel
* 功能描述：处理对应外网规则的数据包
* 输入参数：
  pfib_rule     转发规则，用来判断要发到哪些外网口
  cmsgDatabuf   发送报文所存放的地址
  ptoaddr      发送的地址
  msgLen        发送消息体长度 包括eth，ip，udp头
*  输出参数：
* 返 回 值：
    处理成功
    处理失败    
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int Handle_Externel(FIB_RULE  *pfib_rule, unsigned char *cmsgDatabuf, struct sockaddr_ll *ptoaddr, unsigned int msgLen)
{
    struct fib_address *fib_addr_next;
    if((NULL == pfib_rule) || (NULL == cmsgDatabuf))
    {
        printf("Handle_Externel: arg err\n");
        return ERR_GENERR;
    }
    
    /* 遍历发送的目的地 */
    fib_addr_next = pfib_rule->pdstaddr;
    while(fib_addr_next != NULL)             
    {  
        /* build send packet */
        if(packetBuild(fib_addr_next, cmsgDatabuf, localIp, 100000, 10001) < 0)
        {
            continue;
        }
        /* send to the paket*/
        memset(&toaddr,0,sizeof(toaddr));
        ptoaddr->sll_family   = AF_PACKET;
        ptoaddr->sll_ifindex  = ifr.ifr_ifindex;  
        ptoaddr->sll_protocol = htons(ETH_P_ALL);
        ptoaddr->sll_halen   = 6;
         
        ptoaddr->sll_addr[0] = 0x00;
        ptoaddr->sll_addr[1] = 0x15;
        ptoaddr->sll_addr[2] = 0x58;
        ptoaddr->sll_addr[3] = 0x12;
        ptoaddr->sll_addr[4] = 0x9E;
        ptoaddr->sll_addr[5] = 0x5E;
           
        if(packetSend(msgLen, cmsgDatabuf, ptoaddr) < 0)
        {
           continue;
        }
        fib_addr_next = fib_addr_next->next;
    }    /*end while  */
    return PACKET_OK;      
}     




/**********************************************************************
* 函数名称：Handle_Internel
* 功能描述：处理对应外网规则的数据包
* 输入参数：
  pfib_rule     转发规则，用来判断要发到哪些内网口
  udpHdr       内网口只需处理udp头及udp负荷
*  输出参数：
* 返 回 值：
    处理成功
    处理失败    
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2007/12/11             丁鹏              创建
************************************************************************/
int Handle_Internel(FIB_RULE  *pfib_rule, struct udphdr *udpHdr)
{
    struct fib_address *fib_addr_next;
    unsigned char       filename[20];
    int    fd;

    memset(filename, 0x00, 20)
    /* 遍历发送的目的地 */
    fib_addr_next = pfib_rule->pdstaddr;
    while(fib_addr_next != NULL)             
    {  
        if(getfilename(fib_addr_next->chipnum, &filename) == 0)
        { 
            printf("no that 8360 chip \n");
            continue;
        }
        else
        { 
            fd = open(filename, O_RDWR | O_APPEND);
            udpHdr = (struct udphdr *)pktBuf;
            /*write file */
            write(fd, udpHdr, ntohs(udpHdr->uh_ulen));
            close(fd);
        } /*end getfile name */
        fib_addr_next = fib_addr_next->next;
    }/* end while  */
    return PACKET_OK;  
}    
            