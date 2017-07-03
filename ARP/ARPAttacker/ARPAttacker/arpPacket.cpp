#include "stdafx.h"
#include "arpPacket.h"



const char * IpToStr(unsigned long in)
{
static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;									
	unsigned char* chIP;
	chIP = (unsigned char*)&in;							
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1); 
	sprintf(output[which], "%d.%d.%d.%d", chIP[0], chIP[1], chIP[2], chIP[3]); 
	return output[which];
}

char* MacToStr(unsigned char* chMAC)
{							
	static unsigned char uMac[18];
	for(int i=0; i < 17; i++)
	{
		if ((i+1) % 3)
		{
			if (!(i % 3))
			{
				if ((chMAC[i/3] >> 4) < 0x0A)
				{
					uMac[i] = (chMAC[i/3] >> 4) + 48;
				}
				else
				{
					uMac[i] = (chMAC[i/3] >> 4) + 55;
				}
				if ((chMAC[i/3] & 0x0F) < 0x0A)
				{
					uMac[i+1] = (chMAC[i/3] & 0x0F) + 48;
				}
				else
				{
					uMac[i+1] = (chMAC[i/3] & 0x0F) + 55;
				}
			}
		}
		else
		{
			uMac[i] = '-';
		}
	}
	uMac[17] = '\0';
	return (char*)uMac;
}

//创建报文用的函数
unsigned char* BuildArpRequestPacket(unsigned char* source_mac, unsigned char* arp_sha, unsigned long chLocalIP, unsigned long arp_tpa, int PackSize)
{
	static arp_packet arpPackStru;
    static const arp_packet arpDefaultPack= {ETH_HRD_DEFAULT,ARP_HRD_DEFAULT};
    memcpy(&arpPackStru,&arpDefaultPack,sizeof(arpDefaultPack));
    //填充源MAC地址
    memcpy(arpPackStru.eth.source_mac,arp_sha,6);//源MAC
    memcpy(arpPackStru.arp.sour_addr,arp_sha,6);//源MAC
    arpPackStru.arp.sour_ip=chLocalIP;//源IP地址    
    arpPackStru.arp.dest_ip=arp_tpa;//目的IP地址
    return (unsigned char *)&arpPackStru;
}

unsigned char* BuildArpReplyPacket(unsigned char* source_mac, unsigned char* arp_sha, unsigned long chLocalIP, unsigned long arp_tpa, int PackSize)
{
	static arp_packet arpPackStru;
    static const arp_packet arpDefaultPack= {ETH_HRD_DEFAULT,ARP_HRD_DEFAULT};
    memcpy(&arpPackStru,&arpDefaultPack,sizeof(arpDefaultPack));
	arpPackStru.arp.option=htons(ARP_REPLY);
    //填充源MAC地址
    memcpy(arpPackStru.eth.source_mac,arp_sha,6);//源MAC
    memcpy(arpPackStru.arp.sour_addr,arp_sha,6);//源MAC
    arpPackStru.arp.sour_ip=chLocalIP;//源IP地址    
    arpPackStru.arp.dest_ip=arp_tpa;//目的IP地址
    return (unsigned char *)&arpPackStru;
}
