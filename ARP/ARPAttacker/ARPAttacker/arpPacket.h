#pragma once
#include <pcap.h>
#include "stdafx.h"

#define BROADMAC        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} //广播MAC
#define EH_TYPE            0x0806                            //ARP类型
#define ARP_HRD            0X0001                            //硬件类型：以太网接口类型为        
#define ARP_PRO            0x0800                            //协议类型：IP协议类型为X0800
#define ARP_HLN            0x06                            //硬件地址长度：MAC地址长度为B
#define ARP_PLN            0x04                            //协议地址长度：IP地址长度为B
#define ARP_REQUEST        0x0001                            //操作：ARP请求为
#define ARP_REPLY          0x0002                            //操作：ARP应答为
#define ARP_THA            {0,0,0,0,0,0}                    //目的MAC地址：ARP请求中该字段没有意义，设为；ARP响应中为接收方的MAC地址
#define ARP_PAD            {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} //18字节的填充数据
#define SPECIAL            0x70707070                        //定义获得自己MAC地址的特殊源IP，.112.112.112
#define ETH_HRD_DEFAULT    {BROADMAC, {0,0,0,0,0,0}, htons(EH_TYPE),htons(ARP_HRD)} //广播ARP包帧头
#define ARP_HRD_DEFAULT    {htons(ARP_PRO),ARP_HLN, ARP_PLN, htons(ARP_REQUEST), {0,0,0,0,0,0}, 0, ARP_THA, 0, ARP_PAD}

#define IPTOSBUFFERS 12
#define WM_PACKET    WM_USER + 105    //用户自定义消息
#define WM_FLOODSTOP    WM_USER + 106    //用户自定义消息


#pragma pack(push, 1)      //设置结构体按字节对齐
struct ethernet_head
{// 物理帧帧头结构
    unsigned char dest_mac[6];                                    //目标主机MAC地址(6字节)
    unsigned char source_mac[6];                                //源端MAC地址(6字节)
    unsigned short eh_type;                                        //以太网类型(2字节)
	unsigned short hardware_type;  
	
};
struct arp_head
{//ARP数据帧
                                  //硬件类型：以太网接口类型为
    unsigned short protocol_type;                                //协议类型：IP协议类型为X0800
    unsigned char add_len;                                        //硬件地址长度：MAC地址长度为B
    unsigned char pro_len;                                        //协议地址长度：IP地址长度为B
    unsigned short option;                                        //操作：ARP请求为，ARP应答为

    unsigned char sour_addr[6];                                    //源MAC地址：发送方的MAC地址
    unsigned long sour_ip;                                        //源IP地址：发送方的IP地址
    unsigned char dest_addr[6];                                    //目的MAC地址：ARP请求中该字段没有意义；ARP响应中为接收方的MAC地址
    unsigned long dest_ip;                                        //目的IP地址：ARP请求中为请求解析的IP地址；ARP响应中为接收方的IP地址
    unsigned char padding[18];
};

struct arp_packet                                        //最终arp包结构
{//物理帧结构
    struct ethernet_head eth;                                    //以太网头部
    struct arp_head arp;                                        //arp数据包头部
};
#pragma pack(pop)      //还原对齐方式





const char * IpToStr(unsigned long in);
char* MacToStr(unsigned char* chMAC);
unsigned char* BuildArpRequestPacket(unsigned char* source_mac, unsigned char* arp_sha, unsigned long chLocalIP, unsigned long arp_tpa, int PackSize);
unsigned char* BuildArpReplyPacket(unsigned char* source_mac, unsigned char* arp_sha, unsigned long chLocalIP, unsigned long arp_tpa, int PackSize);