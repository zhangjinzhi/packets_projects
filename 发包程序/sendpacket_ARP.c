#define WIN32
#define HAVE_REMOTE

#include <stdio.h>
#include "pcap.h"
#include "Win32-Extensions.h"
// DLC Header
typedef struct tagDLCHeader
{
   unsigned char      DesMAC[6];             /* destination HW addrress */
   unsigned char      SrcMAC[6];             /* source HW addresss */
   unsigned short     Ethertype;                /* ethernet type */
} DLCHEADER,*PDLCHEADER;
// ARP Frame
typedef struct tagARPFrame
{
          unsigned short         HW_Type;           /* hardware address */
          unsigned short         Prot_Type;             /* protocol address */
          unsigned char      HW_Addr_Len;       /* length of hardware address */
          unsigned char      Prot_Addr_Len;         /* length of protocol address */
          unsigned short         Opcode;                /* ARP/RARP */

          unsigned char      Send_HW_Addr[6];     /* sender hardware address */
          unsigned long      Send_Prot_Addr;      /* sender protocol address */
          unsigned char      Targ_HW_Addr[6];     /* target hardware address */
          unsigned long      Targ_Prot_Addr;      /* target protocol address */
          unsigned char      padding[18];
} ARPFRAME, *PARPFRAME;
// ARP Packet = DLC header + ARP Frame
typedef struct tagARPPacket
{
     DLCHEADER     dlcHeader;
     ARPFRAME      arpFrame;
} ARPPACKET,*PARPPACKET;


void genPacket(unsigned char *buf,int len);
void formatARPPacket(char* srcDLC,char* desDLC,char* srcMAC,char* srcIP,char* desMAC,char* desIP,int arpType);
void formatStrToMAC(const LPSTR lpHWAddrStr, unsigned char *HWAddr);


int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret=-1;

/* Retrieve the device list from the local machine */
if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,
&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
 /* Print the list */

    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }


    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");

        pcap_freealldevs(alldevs);
        return -1;
    }


    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
//adhandle is a adaptor handler
/* Open the output device */
if ( (adhandle= pcap_open(d->name, 65536,
PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL,errbuf) )
== NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

        pcap_freealldevs(alldevs);
        return -1;
    }


    printf("\nlistening on %s...\n", d->description);




    int MaxPacketLen=100;
    unsigned char *pBuf= (unsigned char *)malloc(MaxPacketLen);
    memset(pBuf,0x0,MaxPacketLen);
//������ɵ����ݰ�������ΪMaxPacketLen


    genPacket(pBuf,MaxPacketLen);


    if ( (ret=pcap_sendpacket(adhandle,pBuf,MaxPacketLen))
==-1)
    {
       printf("����ʧ��\n");
       pcap_close(adhandle);
        pcap_freealldevs(alldevs);
        return -1;
    }



     free(pBuf);
     pcap_close(adhandle);
     pcap_freealldevs(alldevs);

    return 0;
}
void genPacket(unsigned char *buf,int len)
{

char* src_DLC = "6002B4FB7AD9";
char* des_DLC = "FFFFFFFFFFFF";
char* src_MAC = "6002B4FB7AD9";
char* src_IP  = "222.20.95.17";
char* des_MAC = "6002B4FB7AD9";
char* des_IP  = "222.20.95.17";
int arp_Type  = 0x0001;

//formatARPPacket(char* srcDLC,char* desDLC,char* srcMAC,char* srcIP,char* desMAC,char* desIP,int arpType);

        int i;
       //���ù㲥��ַ
           buf[0]=0xFF;
           buf[1]=0xFF;
           buf[2]=0xFF;
           buf[3]=0xFF;
           buf[4]=0xFF;
           buf[5]=0xFF;
       //����ԴMAC��ַΪ60:02:B4:FB:7A:D9
           buf[6]=0x80;
           buf[7]=0xFA;
           buf[8]=0x5B;
           buf[9]=0x00;
           buf[10]=0xFC;
           buf[11]=0xD1;
       //����Э���ʶ
       buf[12]=0x08;
       buf[13]=0x06;
         //Ӳ������
         buf[14]=0x00;
         buf[15]=0x01;
         //Э������
         buf[16]=0x08;
         buf[17]=0x00;
         //Ӳ����ַ����
        buf[18]=0x06;
        //Э���ַ����
        buf[19]=0x04;
        //�����
        buf[20]=0x00;
        buf[21]=0x01;
        //�����ߵ�mac��ַ
         buf[22]=0x80;
         buf[23]=0xFA;
         buf[24]=0x5B;
         buf[25]=0x00;
         buf[26]=0xFC;
         buf[27]=0xD1;
         //�����ߵ�ip��ַ
         buf[28]=222;
         buf[29]=20;
         buf[30]=95;
         buf[31]=17;
         //Ŀ��mac��ַ
         buf[32]=0x80;
         buf[33]=0xFA;
         buf[34]=0x5B;
         buf[35]=0x00;
         buf[36]=0xFC;
         buf[37]=0xD1;
         //Ŀ��ip��ַ
         buf[38]=222;
         buf[39]=20;
         buf[40]=95;
         buf[41]=17;

     //������ݰ�������
       for(i=42;i<len;i++)
       {
           buf[i]=i-42;
       }

}
void formatARPPacket(char* srcDLC,char* desDLC,char* srcMAC,char* srcIP,
                char* desMAC,char* desIP,int arpType)
{
    struct tagARPPacket ARPPacket;
  memset(&ARPPacket, 0, sizeof(ARPPACKET));                         // ���ݰ���ʼ��Ϊ0     //�����⣡��������������������������������

  formatStrToMAC(srcDLC,ARPPacket.dlcHeader.SrcMAC);       // DLC֡ͷ
  formatStrToMAC(desDLC,ARPPacket.dlcHeader.DesMAC);

  formatStrToMAC(srcMAC,ARPPacket.arpFrame.Send_HW_Addr);  // Դ��ַ
  ARPPacket.arpFrame.Send_Prot_Addr = inet_addr(srcIP);
  formatStrToMAC(desMAC,ARPPacket.arpFrame.Targ_HW_Addr);  // Ŀ�ĵ�ַ
  ARPPacket.arpFrame.Targ_Prot_Addr = inet_addr(desIP);

  ARPPacket.arpFrame.Opcode = htons((unsigned short)arpType);        // arp������  �������Ӧ�� 0x0001/0x0002

  // �Զ���䳣��
  ARPPacket.dlcHeader.Ethertype = htons((unsigned short)0x0806);     // DLC Header����̫������
  ARPPacket.arpFrame.HW_Type = htons((unsigned short)1);             // Ӳ������
  ARPPacket.arpFrame.Prot_Type = htons((unsigned short)0x0800);      // �ϲ�Э������
  ARPPacket.arpFrame.HW_Addr_Len = (unsigned char)6;                 // MAC��ַ����
  ARPPacket.arpFrame.Prot_Addr_Len = (unsigned char)4;               // IP��ַ����


}
void formatStrToMAC(const LPSTR lpHWAddrStr, unsigned char *HWAddr)
{
       unsigned int i, index = 0, value, temp;
      unsigned char c;

      _strlwr(lpHWAddrStr);                                                   // ת����Сд

      for (i = 0; i < strlen(lpHWAddrStr); i++)
     {
           c = *(lpHWAddrStr + i);
            if (( c>='0' && c<='9' ) || ( c>='a' && c<='f' ))
           {
               if (c>='0' && c<='9')  temp = c - '0';                         // ����
               if (c>='a' && c<='f')  temp = c - 'a' + 0xa;               // ��ĸ
               if ( (index % 2) == 1 )
              {
                   value = value*0x10 + temp;
                   HWAddr[index/2] = value;
              }
              else value = temp;
              index++;
         }
               if (index == 12) break;
        }
}
