#include<pcap.h>
/**
数据包主执行函数
 */
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"ws2_32.lib")

void getAddr();
int main(int argc,char *argv[])
{

    getAddr();
    return 0;
}

//获取网卡网络地址和子网掩码
void getAddr()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct in_addr net_ip_address;//网卡IP信息,在pcap.h里面有定义
    u_int32_t net_ip;
    char *net_ip_string;

    struct in_addr net_mask_address;
    u_int32_t net_mask;
    char *net_mask_string;

    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs,errbuf)==-1)//无法找到网卡列表
    {
        fprintf(stderr,"error in pcap_findalldevs: %s\n",errbuf);
        exit(1);
    }
    /* 扫描列表 */
    for(d=alldevs;d;d=d->next)
    {
        printf("%s\n",d->name);
        printf("Description: %s\n",d->description);
        pcap_lookupnet(d->name,&net_ip,&net_mask,errbuf);

        net_ip_address.s_addr = net_ip;
        net_ip_string = inet_ntoa(net_ip_address);//format
        printf("网络地址: %s \n",net_ip_string);

        net_mask_address.s_addr = net_mask;
        net_mask_string = inet_ntoa(net_mask_address);//format
        printf("子网掩码: %s \n",net_mask_string);
        printf("\n");
    }

    /* 释放链表 */
    pcap_freealldevs(alldevs);
    printf("\n");
}
/*
int pcap_lookupnet ( char * device, bpf_u_int32 * netp, pf_u_int32 * maskp, char * errbuf );

该函数用于获取指定网络接口的IP地址、子网掩码。
 */