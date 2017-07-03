/**********************************************************
* 版权所有 (C)2007, 深圳市中兴通讯股份有限公司。
*
* 文件名称：
* 文件标识：
* 内容摘要： 模拟ENPU演示程序
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
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "packet_gen.h"
#include "my_list.h"

/***********************************************************
 *                     全局变量                            *
***********************************************************/
unsigned char cmsgDatabuf[MAX_DATA_LEN]={0};  /* 发送buff */
unsigned char areceivebuf[MAX_DATA_LEN]={0};   /* 接收buff */
unsigned char device[] = "eth0";    
int sockfd;
unsigned int useport[PORT_ALLOC_SIZE] = {10000,10001,10002,10003,10004,0};

extern struct fib_rules *fibTableHead;

/***********************************************************
 *                    宏定义                               *
***********************************************************/
#define SIZE                  1500
#define MAX_DATA_LEN          65536
#define MSG_DATA_LENGTH       50
#define ETH_INTERFACE_NAME    "eth0"
#define PORT_ALLOC_SIZE       20
#define FAKE_IP_HEAD          12




/**********************************************************************
* 函数名称：fib_init
* 功能描述：转发表初始化,加入配置信息
* 输入参数：无
* 输出参数：无
* 返 回 值：无
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 
************************************************************************/
void fib_init()    
{    
    FIB_RULE     new_key;
    
    fib_rules_init();
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.54");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.63");
    
    fib_rules_insert(&new_key);
    
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.54");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.64");
    fib_rules_insert(&new_key);
    
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.54");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.65");
    fib_rules_insert(&new_key);
    
    
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.56");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.57");
    fib_rules_insert(&new_key);
    
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.58");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.52");
    fib_rules_insert(&new_key);
       
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.63");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.54");
    fib_rules_insert(&new_key);
        
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.55");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.63");
    fib_rules_insert(&new_key);
    
    
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.51");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.63");
    fib_rules_insert(&new_key);
    
    new_key.direction = 1;
    new_key.ip_src.s_addr = inet_addr("10.16.8.51");
    new_key.ip_dst.s_addr = inet_addr("10.16.8.55");
    fib_rules_insert(&new_key);

  
    new_key.direction = 0;
    new_key.ip_src.s_addr  = inet_addr("10.16.8.51");
    new_key.chipnum = 1;
    fib_rules_insert(&new_key);

    new_key.direction = 0;
    new_key.ip_src.s_addr  = inet_addr("10.16.8.51");
    new_key.chipnum = 2;
    fib_rules_insert(&new_key);


    new_key.direction = 0;
    new_key.ip_src.s_addr  = inet_addr("10.16.8.51");
    new_key.chipnum = 3;
    fib_rules_insert(&new_key);

    new_key.direction = 0;
    new_key.ip_src.s_addr  = inet_addr("10.16.8.52");
    new_key.chipnum = 1;
    fib_rules_insert(&new_key);
}    


/**********************************************************************
* 函数名称：sockInit
* 功能描述：演示程序socket初始化
* 输入参数：无
* 输出参数：无
* 返 回 值：无
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 
************************************************************************/
void sockInit()
{

      
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
}

/**********************************************************************
* 函数名称：main
* 功能描述：演示程序主函数
* 输入参数：无
* 输出参数：无
* 返 回 值：无
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 
************************************************************************/
int main(int argc, char *argv[])
{
    struct ifreq ifr;
    struct ethhdr *ethhdr;
    struct ip *ipHdr; 
    struct udphdr *udpHdr;
    struct arphdr*   arphdr;   
    struct sockaddr_ll toaddr;
    struct sockaddr_ll fromaddr;
    struct in_addr srcAddr;
    struct sockaddr_in LoacalAddr;
 
    struct fib_rules *pfib_rule;;
    struct fib_address *fib_addr_next;
    
    int i;
    int msgDataLen = MSG_DATA_LENGTH;

    int recLen, receiveLen;
    int pktTotlen;

    unsigned char LocalIp[20];
    
    fib_init();

    
  
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
    

    
    rules_print();
    
    while(1)
     {
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
        if(strcmp(LocalIp, inet_ntoa(*(struct in_addr*)&(ipHdr->ip_dst))) != 0)
        {
            continue;
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
        printf("the next  step :is the packet's src address is valid ........\n");
        srcAddr.s_addr = ipHdr->ip_src.s_addr;
        pfib_rule = rules_isExist(&srcAddr);

        if (pfib_rule == NULL)
        {
            continue;
        }
        else
        {
            printf("wait next  step ........\n");
            /* 1------ip crc check ---------*/
            printf(".....1 ipcrc check.....\n");
            if(ipcrcCheck(ipHdr) < 0)
            {
                continue;  
            } 
            
            printf(".....2 udpcrc check.....\n");
            /* 2------udp crc check ------*/
            if(udpcrcCheck(ipHdr) < 0)
            {
                continue;     
            }
            
            printf(".....3 udp dest port check.....\n");
            /* udp port check */
            udpHdr = (struct udphdr *)(ipHdr + uiIpHdrLen);
            if(udpPortCheck(udpHdr) < 0)
            {
                continue;  
            }
   
            printf(".....4 according to FIB rules handle the packet.....\n");
            /* according to the rule to packet it */
            if(pfib_rule->direction == FIB_EXTERNEL_NETWORK)
            {
                /* 遍历发送的目的地 */
                fib_addr_next = pfib_rule->pdstaddr;
                /* send it */    
                pktTotlen = msgDataLen + IP_HDR_LEN + UDP_HDR_LEN + ETH_HDR_LEN;
                Handle_Externel(pfib_rule, cmsgDatabuf, &toaddr, pktTotlen)
            }/*end if*/

            if(pfib_rule->direction == FIB_INTERNEL_NETWORK)
            {
                Handle_Internel(pfib_rule, udpHdr)
            } /* end pfib_rules */

        } /* end else*/
    
}

