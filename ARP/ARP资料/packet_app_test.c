#include "packet_gen.h"
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
#include <strings.h>
#include "my_list.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define SIZE 1500
#define MAX_DATA_LEN 65536
#define MSG_DATA_LENGTH 50
unsigned char cmsgDatabuf[MAX_DATA_LEN]={0};
unsigned char receivebuf[MAX_DATA_LEN]={0x0};
#define ETH_INTERFACE_NAME    "eth0"
#define PORT_ALLOC_SIZE       20
#define FAKE_IP_HEAD          12

extern struct fib_rules *fibTableHead;

int main(int argc, char *argv[])
{
    unsigned char LocalIp[20];
    int sockfd;
    struct ifreq ifr;
    char device[] = "eth0";
    struct ethhdr *ethhdr;
    struct   arphdr*   arphdr;   
    struct sockaddr_ll toaddr;
    struct sockaddr_ll fromaddr;
    int ret = 0;
    int pktTotlen;
    int msgDataLen = MSG_DATA_LENGTH;
    int sendlen;
    struct udphdr *udpHdr;
    unsigned char *pktBuf;
    unsigned short uiUdpHdrLen, uiEthHdrLen, uiIpHdrLen;
    char *psDstAddr, *psSrcAddr;
    struct fib_key new_key;
    struct in_addr srcAddr;
    struct fib_rules *pfib_rule;;
    unsigned short crcCheck;
    unsigned short crcPacket;
    struct sockaddr_in LoacalAddr;
    unsigned int useport[PORT_ALLOC_SIZE] = {10000,10001,10002,10003,10004,0};
    int i;
   
    struct ip *ipHdr; 
    struct tcphdr *tcp;
    unsigned char dstMac[ETH_ALEN+1]={0};
    unsigned char srcMac[ETH_ALEN+1]={0};
    unsigned char *psrcMac;
    unsigned char *pdstMac;
    unsigned short *puicrckBufBegin;
    unsigned short dport, sport;
    
    struct fib_rules *pNode = fibTableHead;
    struct fib_rules *pTail = fibTableHead;
    
    struct fib_rules *new_rules;
    struct fib_address *fib_addr = NULL;
    struct fib_address *fib_addr_next;
    struct fib_address *new_addr;
    
    
    int recLen, receiveLen;
    unsigned char ss[ETH_ALEN], dd[ETH_ALEN];
  
    /* udp校验伪首部 */
   unsigned char  packet_ip_ttl;         /* 8bit */
   unsigned char  packet_ip_p;           /*  8bit */
   unsigned short packet_ip_sum;         /* 16bit  check crc */
   unsigned short packet_uh_sum;
   /* fib internel */
   unsigned char filename[20]={0};
   int  fd;
  
    uiUdpHdrLen = sizeof(struct udphdr);
    uiEthHdrLen = sizeof(struct ethhdr);
    uiIpHdrLen  = sizeof(struct ip);


    for(i = 0; i < 100; i++)
    {
      receivebuf[i] = 'a'+i;
    }

    if((sockfd=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) 
    {
        perror("socket");
        exit(1);
    }
    strcpy(ifr.ifr_name, device);
    if(ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS err");
        exit(1);
    }
    
    if(ioctl(sockfd, SIOCGIFINDEX,   &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX err");
        exit(1);
    }
    /* Get IP Address */
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0){
        perror("ioctl get siocgifaddr err\n");
        exit(1);
    }
    memcpy(&LoacalAddr, &ifr.ifr_addr, sizeof(LoacalAddr));
    strcpy(LocalIp,inet_ntoa(LoacalAddr.sin_addr)); 
    LocalIp[strlen(inet_ntoa(LoacalAddr.sin_addr))] = '\0';
  
    memset(cmsgDatabuf, 0x00, sizeof(cmsgDatabuf));

    /* udp data */    
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen ] = 'b';
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen + 1] = 'e';
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen + 2] = 'g';
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen + 3] = 'i';
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen+ 4] = 'n';
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen + MSG_DATA_LENGTH -1] = 'r';
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen+ MSG_DATA_LENGTH -2 ] = 'e';
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen + MSG_DATA_LENGTH -3 ] = 'v';
    cmsgDatabuf[uiUdpHdrLen + uiIpHdrLen + uiEthHdrLen + MSG_DATA_LENGTH -4 ] = 'o';    
    
    
    
    fib_rules_init();

  
    new_key.direction = 0;
    new_key.ip_src.s_addr  = inet_addr("10.16.8.51");
    new_key.chipnum = 2;
    fib_rules_insert(&new_key);
    
    new_key.direction = 0;
    new_key.ip_src.s_addr  = inet_addr("10.16.8.51");
    new_key.chipnum = 3;
    fib_rules_insert(&new_key);
    


    
    rules_print();


#if 1    
    while(1)
     {
#if 0
//        recLen = recvfrom(sockfd,(char *)receivebuf,sizeof(receivebuf),0,(struct sockaddr *)&fromaddr,receiveLen);
         recLen = recvfrom(sockfd,(char *)receivebuf,sizeof(receivebuf),0,NULL,0);
         if( recLen > 0)
         {
            receivebuf[recLen] = 0; 
            ethhdr= (struct ethhdr *)receivebuf; 
            if (ntohs(ethhdr->h_proto) == ETH_P_IP)
            {
                ipHdr = (struct ip *)(receivebuf+uiEthHdrLen);
                switch(ipHdr->ip_p)
                {
                case IPPROTO_ICMP:
                    printf("ICMP: ");
                  //  continue;
                    break; 
                case IPPROTO_IGMP:
                  //  printf("IGMP: ICMP: ");
                     //continue;
                    break;
                case IPPROTO_UDP:
                   printf("UDP: ");
                 
                    break;
                case IPPROTO_TCP:
                //    printf("TCP: ICMP: drop");
                    continue;
                    break;
                }
            } /* end if (ntohs) */
            
            else if (ntohs(ethhdr->h_proto) == ETH_P_ARP)
            {
               // printf("ARP packet received\n");
               // printf("it's not a ip packet, drop!\n");
                continue;
            }
            else
            {
               // printf("it's not a ip packet, drop!\n");
                continue;
            } /*end if (ntohs)...*/
        }
        else
        {
           continue;
        }/*end if (ret < 0) */
        /* 1    identify the dst's ipAddress */     
#endif
#if 0        
        if(strcmp(LocalIp, inet_ntoa(*(struct in_addr*)&(ipHdr->ip_dst))) == 0)
        {
            //printf("the packet received is sent to my ip address machine\n"); 
        }
        else
        {
            //printf("the packet received is not sent to my ip address machine\n");
            continue; 
        }
        
        printf("recLen:%d, receiveLen:%d", recLen, receiveLen);
        printf("dst ip:%s\n", inet_ntoa(*(struct in_addr*)&(ipHdr->ip_dst)));
        printf("src ip:%s\n", inet_ntoa(*(struct in_addr*)&(ipHdr->ip_src)));
        printf("local ip1:%s\n", LocalIp);
         
        /* 2 identify the src's ipAddress */
        srcAddr.s_addr = ipHdr->ip_src.s_addr;
#endif
        srcAddr.s_addr = inet_addr("10.16.8.51");
        pfib_rule = rules_isExist(&srcAddr);

        if (pfib_rule == NULL)
        {
            continue;
        }
        else
        {
            printf("wait net step .....\n");
            /* 1------ip crc check ---------*/
      
            /* according to the rule to packet it */
            if(pfib_rule->direction == FIB_EXTERNEL_NETWORK)
            {
                /* 遍历发送的目的地 */
                fib_addr_next = pfib_rule->pdstaddr;
                while(fib_addr_next != NULL)             
                {  
                    /* build send packet */
                    pktBuf = (unsigned char *)cmsgDatabuf;
                    //psDstAddr = "10.16.8.63";
                    //psSrcAddr = "10.16.8.54";
                    psDstAddr = inet_ntoa(fib_addr_next->ip_dst);
                    psSrcAddr = LocalIp;
                  
                    sport = 10000;
                    dport = 10001;
                    /* build udphdr */
                    udpHdr = (struct udphdr *)(pktBuf + uiEthHdrLen + uiIpHdrLen);
                    UdpHdrGen(udpHdr, dport, sport, msgDataLen);
                    /* builde iphdr */       
                    ipHdr = (struct ip *)(pktBuf + sizeof(struct ethhdr));
                    ipHdr->ip_ttl = 0;                        /* 8bit */
                    ipHdr->ip_p = IPPROTO_UDP;                /*  8bit */
                    ipHdr->ip_sum = udpHdr->uh_ulen;           /* 16bit  check crc */
                    ipHdr->ip_src.s_addr = inet_addr(psSrcAddr); /* 32bit */
                    ipHdr->ip_dst.s_addr = psDstAddr; /* 32bit */
                    
                    
                    puicrckBufBegin      = (unsigned short *)&(ipHdr->ip_ttl);
                    
                    
                    udpHdr->uh_sum = checksum(puicrckBufBegin, msgDataLen + FAKE_IP_HEAD + 8);
                    
                    if (udpHdr->uh_sum == 0 ) 
                    {
                        udpHdr->uh_sum = 0xffff;
                    }
                    
                    IpHdrGen(ipHdr, psDstAddr, psSrcAddr, msgDataLen, IPPROTO_UDP);
                    
                  
                              
                    /* build ethhdr */
                    ret = getMac(psDstAddr, dstMac);
                    if(ret == 0)
                    {
                        printf("no %s mac , err\n", dstMac);
                        continue;
                    }
                    printf("dst ret:%d\n",ret);
                    dstMac[ETH_ALEN+1]='\0';
                    ret = getMac(psSrcAddr, srcMac);
                    if(ret == 0)
                    {
                        printf("no %s mac , err\n", srcMac);
                        continue;
                    }
                     printf("src ret:%d\n",ret);
                    srcMac[ETH_ALEN+1]='\0';
                    psrcMac=&srcMac[0];
                    pdstMac=&dstMac[0];
                    
                    
                  
                    printf("ret:%d, src ip:%s, mac:%s  ----> dst ip:%s, mac:%s \n",ret, psSrcAddr, (unsigned char* )psrcMac, psDstAddr, (unsigned char* )pdstMac);
                    ethhdr = (struct ethhdr *)pktBuf;
                    ethHdrGen(ethhdr, dstMac, srcMac);
                   
                    
                    pktTotlen = msgDataLen + uiIpHdrLen + uiUdpHdrLen + uiEthHdrLen;
                    /* send to the paket*/
                     memset(&toaddr,0,sizeof(toaddr));
                     toaddr.sll_family   = AF_PACKET;
                     toaddr.sll_ifindex  = ifr.ifr_ifindex;  
                     toaddr.sll_protocol = htons(ETH_P_ALL);
                     toaddr.sll_halen   = 6;
                     
                     toaddr.sll_addr[0] = 0x00;
                     toaddr.sll_addr[1] = 0x15;
                     toaddr.sll_addr[2] = 0x58;
                     toaddr.sll_addr[3] = 0x12;
                     toaddr.sll_addr[4] = 0x9E;
                     toaddr.sll_addr[5] = 0x5E;
                     
                     
                    // memcpy(&toaddr.sll_addr[0], &dstMac[0], IFHWADDRLEN);
              
                    sendlen = sendto(sockfd, pktBuf, pktTotlen, 0, (struct sockaddr *)&toaddr, sizeof(toaddr));
                    if(sendlen < 0)
                    {
                        perror("sendto");
                        continue;
                    }
                    else
                    {
                        printf("sendlen = %d\n", sendlen);
                    }  
                    fib_addr_next = fib_addr_next->next;
                    
    }    /*end while  */
                      
      }/*end if*/

            if(pfib_rule->direction == FIB_INTERNEL_NETWORK)
      {
        printf("----internel network ----\n");
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
      if(fd < 0)
        {
                            printf("open file %s err\n");
                        }
                            printf("open file:%s ok\n", filename); 
                        /*write file */
                        write(fd, receivebuf, 50);
                        close(fd);
               
                    } /*end getfile name */
                    fib_addr_next = fib_addr_next->next;
    }/* end while  */  
            } /* end pfib_rules */

        } /* end else*/

      
        
#if 0    

        /* build send packet */
        pktBuf = (unsigned char *)cmsgDatabuf;
        psDstAddr = "10.16.8.63";
        psSrcAddr = "10.16.8.54";
        sport = 10000;

       
        
        IpHdrGen(ipHdr, psDstAddr, psSrcAddr, msgDataLen, IPPROTO_UDP);
        /* build ethhdr */
        ethhdr = (struct ethhdr *)pktBuf;
        ethHdrGen(ethhdr, dstMac, srcMac);
       
        pktTotlen = msgDataLen + uiIpHdrLen + uiUdpHdrLen + uiEthHdrLen;
        /* send to the paket*/
        sendlen = sendto(sockfd, pktBuf, pktTotlen, 0, (struct sockaddr *)&toaddr, sizeof(toaddr));
        if(sendlen < 0)
        {
            perror("sendto");
            exit(1);
        }
        else
        {
            printf("sendlen = %d\n", sendlen);
        }
#endif        
        sleep(2);
     }/*end while */
#endif    
}

