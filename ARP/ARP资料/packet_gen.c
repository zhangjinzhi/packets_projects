/**********************************************************
* ��Ȩ���� (C)2007, ����������ͨѶ�ɷ����޹�˾��
*
* �ļ����ƣ�packet_gen.c
* �ļ���ʶ��
* ����ժҪ�� ģ��ENPU��ʾ��������
* ����˵����
* ��ǰ�汾��
* ��    �ߣ��� ��
* ������ڣ�2007/12/11
*
* �޸ļ�¼1��   
*    �޸����ڣ� 
*    �� �� �ţ�
*    �� �� �ˣ�                    
*    �޸����ݣ�
**********************************************************/

/***********************************************************
 *                      ͷ�ļ�                             *
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
 *                     ȫ�ֱ���                            *
***********************************************************/
unsigned short ip_id;



/***********************************************************
 *                     ȫ�ֺ���                            *
***********************************************************/
void UdpHdrGen(struct udphdr *udpHdr, unsigned short int idport, unsigned short int isport, unsigned short int msglen);
void IpHdrGen(struct ip *ipHdr, unsigned char *sdaddr, unsigned char *ssaddr, unsigned int msglen, unsigned char proto);
void ethHdrGen(struct ethhdr *ethhdr, unsigned char *cdmac, unsigned char *csmac);
unsigned short checksum(unsigned short *buffer, int size);
int getMac(unsigned char *ipaddr, unsigned char *mac);


/**********************************************************************
* �������ƣ�UdpHdrGen
* ��������������udpͷ
* ���������
  udpHdr     �����udpͷ�Ĵ�ŵ�ַ
  idport     Դudp�˿�
  isport     Ŀ��udp�˿�
  msglen     udp���ɳ��ȣ�������udpͷ��
* �����������
* �� �� ֵ����
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�IpHdrGen
* ��������������IPͷ
* ���������
  ipHdr     �����ipͷ�Ĵ�ŵ�ַ
  sdaddr     ԴIP��ַ
  ssaddr     Ŀ��udp�˿�
  msglen     ������Ϣ�峤�ȣ�������updͷ��ipͷ��ethͷ
  proto
* �����������
* �� �� ֵ����
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
************************************************************************/
void IpHdrGen(struct ip *ipHdr, unsigned char *sdaddr, unsigned char *ssaddr, unsigned int msglen, unsigned char proto)
{
       
    if( ipHdr == NULL)
    {
        printf("IpHdrGen get ipHdr err\n");
        return ;
    }

    ipHdr->ip_hl = 5;  /* ip_hl << 2 ----ipͷ���ȣ���������ѡΪ��׼��20�ֽ� */
    ipHdr->ip_v  = 4;   /* ip�汾, ipv4 */
    ipHdr->ip_tos = 0;  /* normal service */ /*���8bit�ֶ���3bit������Ȩ���ֶΣ������Ѿ������ԣ���4 bit��TOS���ֶ��Լ�1 bit��δ���ֶΣ�����Ϊ 
                                             0�����ɡ�4 bit��TOS���ֶΰ�������С��ʱ���������������߿ɿ����Լ���С���� 
                                             ���ɣ����ĸ�1 bitλ���ֻ����һ��Ϊ1�������ж�Ϊ0����ʾ��һ����� */
    ipHdr->ip_len = htons(msglen + sizeof(struct udphdr)+sizeof(struct ip)); /* ����ipͷ�� */
    ipHdr->ip_id  = htons(ip_id++); /* ����ipͷ�� */
    ipHdr->ip_off = 0; /* ���е�һλ��IPЭ��Ŀǰû�����ϵģ�Ϊ0�����ŵ���������־DF��MF��
                          DFΪ1��ʾ��Ҫ�ֶΣ�MFΪ1��ʾ���н�һ���ķֶΣ�����Ϊ0����
                          Ȼ��ġ�0 0000���Ƿֶ�Ƭ�ƣ�Fragment Offset���� */
    ipHdr->ip_ttl = IPDEFTTL; /* time to live, 64 by default��linux */
    ipHdr->ip_p   = proto;
    ipHdr->ip_sum = 0; /*   check crc */
    
    ipHdr->ip_src.s_addr = inet_addr(ssaddr);
    ipHdr->ip_dst.s_addr = inet_addr(sdaddr);
    ipHdr->ip_sum = htons(checksum((unsigned short *)ipHdr,sizeof(struct ip)));
 
}
/**********************************************************************
* �������ƣ�ethHdrGen
* ��������������ethͷ
* ���������
  ipHdr     �����ethͷ�Ĵ�ŵ�ַ
  sdmac     ԴMAC��ַ
  ssmac     Ŀ�ķ�MAC��ַ
*  �����������
* �� �� ֵ����
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
************************************************************************/
void ethHdrGen(struct ethhdr *ethhdr, unsigned char *sdmac, unsigned char *ssmac)
{
    memcpy(ethhdr->h_dest,sdmac, ETH_ALEN);
    memcpy(ethhdr->h_source,ssmac, ETH_ALEN);
    ethhdr->h_proto = htons(ETH_P_IP);
}    
/**********************************************************************
* �������ƣ�checksum
* ����������У��ͼ���
* ���������
  buffer    ��ʼ��ַ�������⿪ʼ�����ڴ����ݵ�У���
  size      ������ٸ��ֽڵ�У���
*  ���������
* �� �� ֵ��У�����ֵ
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�getMac
* ����������ȡ��MAC��ַ
* ���������
  ipaddr    ip��ַ
*  ���������
   Mac      ��Ӧip��MAC��ַ
* �� �� ֵ��
    ��Ӧip��ַ�����к�
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�ipcrcCheck
* �����������ж��յ���ip���ĵ�ipУ����Ƿ���ȷ
* ���������
  ipHdr    �յ����ĵ�ipͷ
*  �����������
* �� �� ֵ��
    У�����ȷ
    У��ʹ���
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�udpcrcCheck
* �����������ж��յ���ip���ĵ�udpУ����Ƿ���ȷ
* ���������
  ipHdr    �յ����ĵ�ipͷ
*  �����������
* �� �� ֵ��
    У�����ȷ
    У��ʹ���
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
            
    /* α�ײ���ʼ�� */
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
* �������ƣ�packetSend
* �������������ͱ���
* ���������
  len     ���ͱ��ĳ���
  pktBuf  ���ͱ��ĵĵ�ַ������eth��ip��udpͷ
  ptoaddr ���͵ĵ�ַ
*  �����������
* �� �� ֵ��
    ���ͳɹ�
    ����ʧ��    
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�packetBuild
* �������������췢�͵�����ȥ�����ݰ�
* ���������
  fib_addr     ת�����������ж�Ҫ������Щ������
  cmsgDatabuf  ���챨������ŵĵ�ַ
  localIp      ����ip���ַ�����ʽ
  sport        ����Դ�˿�
  dport        ����Ŀ�Ķ˿�
*  ���������
* �� �� ֵ��
    ����ɹ�
    ����ʧ��    
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
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
* �������ƣ�Handle_Externel
* ���������������Ӧ������������ݰ�
* ���������
  pfib_rule     ת�����������ж�Ҫ������Щ������
  cmsgDatabuf   ���ͱ�������ŵĵ�ַ
  ptoaddr      ���͵ĵ�ַ
  msgLen        ������Ϣ�峤�� ����eth��ip��udpͷ
*  ���������
* �� �� ֵ��
    ����ɹ�
    ����ʧ��    
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
************************************************************************/
int Handle_Externel(FIB_RULE  *pfib_rule, unsigned char *cmsgDatabuf, struct sockaddr_ll *ptoaddr, unsigned int msgLen)
{
    struct fib_address *fib_addr_next;
    if((NULL == pfib_rule) || (NULL == cmsgDatabuf))
    {
        printf("Handle_Externel: arg err\n");
        return ERR_GENERR;
    }
    
    /* �������͵�Ŀ�ĵ� */
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
* �������ƣ�Handle_Internel
* ���������������Ӧ������������ݰ�
* ���������
  pfib_rule     ת�����������ж�Ҫ������Щ������
  udpHdr       ������ֻ�账��udpͷ��udp����
*  ���������
* �� �� ֵ��
    ����ɹ�
    ����ʧ��    
* ����˵������
* �޸�����      �汾��  �޸���      �޸�����
* ---------------------------------------------------------------------
* 2007/12/11             ����              ����
************************************************************************/
int Handle_Internel(FIB_RULE  *pfib_rule, struct udphdr *udpHdr)
{
    struct fib_address *fib_addr_next;
    unsigned char       filename[20];
    int    fd;

    memset(filename, 0x00, 20)
    /* �������͵�Ŀ�ĵ� */
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
            