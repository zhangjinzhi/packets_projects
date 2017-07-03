#pragma once
#include <pcap.h>
#include "stdafx.h"

#define BROADMAC        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} //�㲥MAC
#define EH_TYPE            0x0806                            //ARP����
#define ARP_HRD            0X0001                            //Ӳ�����ͣ���̫���ӿ�����Ϊ        
#define ARP_PRO            0x0800                            //Э�����ͣ�IPЭ������ΪX0800
#define ARP_HLN            0x06                            //Ӳ����ַ���ȣ�MAC��ַ����ΪB
#define ARP_PLN            0x04                            //Э���ַ���ȣ�IP��ַ����ΪB
#define ARP_REQUEST        0x0001                            //������ARP����Ϊ
#define ARP_REPLY          0x0002                            //������ARPӦ��Ϊ
#define ARP_THA            {0,0,0,0,0,0}                    //Ŀ��MAC��ַ��ARP�����и��ֶ�û�����壬��Ϊ��ARP��Ӧ��Ϊ���շ���MAC��ַ
#define ARP_PAD            {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} //18�ֽڵ��������
#define SPECIAL            0x70707070                        //�������Լ�MAC��ַ������ԴIP��.112.112.112
#define ETH_HRD_DEFAULT    {BROADMAC, {0,0,0,0,0,0}, htons(EH_TYPE),htons(ARP_HRD)} //�㲥ARP��֡ͷ
#define ARP_HRD_DEFAULT    {htons(ARP_PRO),ARP_HLN, ARP_PLN, htons(ARP_REQUEST), {0,0,0,0,0,0}, 0, ARP_THA, 0, ARP_PAD}

#define IPTOSBUFFERS 12
#define WM_PACKET    WM_USER + 105    //�û��Զ�����Ϣ
#define WM_FLOODSTOP    WM_USER + 106    //�û��Զ�����Ϣ


#pragma pack(push, 1)      //���ýṹ�尴�ֽڶ���
struct ethernet_head
{// ����֡֡ͷ�ṹ
    unsigned char dest_mac[6];                                    //Ŀ������MAC��ַ(6�ֽ�)
    unsigned char source_mac[6];                                //Դ��MAC��ַ(6�ֽ�)
    unsigned short eh_type;                                        //��̫������(2�ֽ�)
	unsigned short hardware_type;  
	
};
struct arp_head
{//ARP����֡
                                  //Ӳ�����ͣ���̫���ӿ�����Ϊ
    unsigned short protocol_type;                                //Э�����ͣ�IPЭ������ΪX0800
    unsigned char add_len;                                        //Ӳ����ַ���ȣ�MAC��ַ����ΪB
    unsigned char pro_len;                                        //Э���ַ���ȣ�IP��ַ����ΪB
    unsigned short option;                                        //������ARP����Ϊ��ARPӦ��Ϊ

    unsigned char sour_addr[6];                                    //ԴMAC��ַ�����ͷ���MAC��ַ
    unsigned long sour_ip;                                        //ԴIP��ַ�����ͷ���IP��ַ
    unsigned char dest_addr[6];                                    //Ŀ��MAC��ַ��ARP�����и��ֶ�û�����壻ARP��Ӧ��Ϊ���շ���MAC��ַ
    unsigned long dest_ip;                                        //Ŀ��IP��ַ��ARP������Ϊ���������IP��ַ��ARP��Ӧ��Ϊ���շ���IP��ַ
    unsigned char padding[18];
};

struct arp_packet                                        //����arp���ṹ
{//����֡�ṹ
    struct ethernet_head eth;                                    //��̫��ͷ��
    struct arp_head arp;                                        //arp���ݰ�ͷ��
};
#pragma pack(pop)      //��ԭ���뷽ʽ





const char * IpToStr(unsigned long in);
char* MacToStr(unsigned char* chMAC);
unsigned char* BuildArpRequestPacket(unsigned char* source_mac, unsigned char* arp_sha, unsigned long chLocalIP, unsigned long arp_tpa, int PackSize);
unsigned char* BuildArpReplyPacket(unsigned char* source_mac, unsigned char* arp_sha, unsigned long chLocalIP, unsigned long arp_tpa, int PackSize);