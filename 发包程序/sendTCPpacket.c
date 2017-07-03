#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <unistd.h>
#include <pcap.h>
#include <remote-ext.h>
#define _CRT_SECURE_NO_WARNINGS
#include <winsock.h>
#include <stdlib.h>
#define HAVE_REMOTE

#include <pcap.h>
#include "pcap.h"
#include <pcap/pcap.h>
#include <sys/types.h>
#include <pcap-bpf.h>
#define IP_PROTO    0x0800
#pragma comment(lib, "ws2_32.lib")
char    LocalIP[20] = { 0 };
char    InterfaceName[256] = { 0 };
char    GatewayIP[20] = { 0 };
BYTE    GatewayMac[6];

typedef struct et_header
{
    unsigned char   eh_dst[6];
    unsigned char   eh_src[6];
    unsigned short  eh_type;
}ET_HEADER;

typedef struct ip_hdr
{
    unsigned char       h_verlen;
    unsigned char       tos;
    unsigned short      total_len;
    unsigned short      ident;
    unsigned short      frag_and_flags;
    unsigned char       ttl;
    unsigned char       proto;
    unsigned short      checksum;   //全小写
    unsigned int        sourceIP;
    unsigned int        destIP;
}IP_HEADER;

typedef struct tcp_hdr
{
    unsigned short    th_sport;            //16位源端口
    unsigned short    th_dport;           //16位目的端口
    unsigned int    th_seq;              //32位序列号 
    unsigned int    th_ack;             //32位确认号
    unsigned char    th_lenres;        //4位首部长度/4位保留字 
    unsigned char    th_flag;         //6位标志位
    unsigned short    th_win;        //16位窗口大小
    unsigned short    th_sum;       //16位校验和 
    unsigned short    th_urp;      //16位紧急数据偏移量 
}TCP_HEADER;
typedef struct tsd_hdr
{
    unsigned long    saddr;
    unsigned long    daddr;
 char            mbz;
 char            ptcl;
    unsigned short    tcpl;
}PSD_HEADER;

unsigned short CheckSum(unsigned short * buffer, int size)   //首字母大写
{
    unsigned long   cksum = 0;

 while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
 if (size)
    {
        cksum += *(unsigned char *) buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

 return (unsigned short) (~cksum);
}


void GetLocalIP( )
{
    WORD        wVersionRequested;
    WSADATA        wsaData;
    char        name[255];
    PHOSTENT    hostinfo;

    wVersionRequested = MAKEWORD( 2, 0 );

    if( WSAStartup( wVersionRequested, &wsaData ) == 0 )
    {
        if( gethostname( name, sizeof(name) ) == 0 )
        {
            if( (hostinfo = gethostbyname(name) ) != NULL )
            {
                strcpy( LocalIP, inet_ntoa( *(struct in_addr*)*hostinfo->h_addr_list ) );
            }
        }
    }

    WSACleanup(   );
}


int GetDevices( )
{
    pcap_if_t    *alldevs;
    pcap_if_t    *d;

 int i = 0;
 char errbuf[PCAP_ERRBUF_SIZE];

 /* 获取本地机器设备列表 */
 if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

 /* 打印列表 */
 for( d = alldevs; d != NULL; d = d->next )
    {
        printf("%d. %s", ++i, d->name);

 if (d->description)
        {
            printf( " (%s)", d->description );
        }

 if( d->addresses != NULL )
        {
 if( d->addresses->addr->sa_family == AF_INET )
            {

                printf( ": %s\n", inet_ntoa( ((struct sockaddr_in *)d->addresses->addr)->sin_addr ) );
            }
 else
            {
                printf( "\n" );
            }
        }
 else
        {
            printf(" (No description available)\n");
        }
    }

 if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
 return -1;
    }

    printf( "\nPlease choose the index of your NetAdapter：" );
 int    AdapterIndex = 1;
    scanf( "%d", &AdapterIndex );
 if( AdapterIndex > i )
    {
        printf( "网卡选错啦\n" );
 return -1;
    }

    d = alldevs;
 for( int index = 1; index < AdapterIndex; index ++ )
    {
        d = d->next;
    }

 if( d->name == NULL || d->addresses == NULL )
    {
        printf( "网卡选错啦\n" );
 return -1;
    }

    strcpy( InterfaceName, d->name );
    strcpy( LocalIP, inet_ntoa( ((struct sockaddr_in *)d->addresses->addr)->sin_addr ) );

 /* 不再需要设备列表了，释放它 */
    pcap_freealldevs(alldevs);

 return 1;
}

int GetGateWayMac( )
{
    PIP_ADAPTER_INFO AdapterInfo;

    ULONG    OutBufLen = sizeof(IP_ADAPTER_INFO);
    AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof (IP_ADAPTER_INFO));
 if( AdapterInfo == NULL )
    {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
 return -1;
    }

 if(GetAdaptersInfo( AdapterInfo, &OutBufLen ) == ERROR_BUFFER_OVERFLOW)
    {
        free( AdapterInfo );
        AdapterInfo = (IP_ADAPTER_INFO *)malloc( OutBufLen );
 if( AdapterInfo == NULL )
        {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
 return -1;
        }
    }

 if( GetAdaptersInfo( AdapterInfo, &OutBufLen ) == NO_ERROR )
    {
        PIP_ADAPTER_INFO    a = AdapterInfo;
        BOOL                Found = FALSE;

 while( a )
        {
 if( strcmp(a->IpAddressList.IpAddress.String, LocalIP) == 0 )
            {
                strcpy( GatewayIP, a->GatewayList.IpAddress.String );
                Found = TRUE;
 break;
            }
            a = a->Next;
        }
 if( !Found )
        {
            printf( "Get gateway's ip error.\n" );
            free( AdapterInfo );
 return -1;
        }
 else
        {
            free( AdapterInfo );
        }
    }
 else
    {
        printf( "Get gateway's ip error.\n" );
        free( AdapterInfo );
 return -1;
    }

    BYTE    Mac[6];
    ULONG    MacLen = 6;
    SendARP( inet_addr(GatewayIP), 0, (PULONG)&Mac, &MacLen );
    memcpy( GatewayMac, Mac, MacLen );

 /*
    for( int index = 0; index < MacLen; index ++ )
    {
        printf( "%d: %02x\n", index, Mac[index] );
    }
    printf( "\n%d\n", MacLen );
    */
}

void Usage( char *me )
{
    printf( "Make tcp package 0.1\n" );
    printf( "%s:   targetip  targetport [flag]\n", me );
    printf( "flag: \n" );
    printf( "      u|U     set urg flag.\n" );
    printf( "      a|A     set ack flag.\n" );
    printf( "      p|P     set push flag.\n" );
    printf( "      r|R     set rst flag.\n" );
    printf( "      s|S     set syn flag.\n" );
    printf( "      f|F     set fin flag.\n" );
    printf( "      default is syn flag, and you can use sa to set syn+ack, and more…\n" );
}

int main( int argc, char *argv[] )
{
    ET_HEADER    EtHeader;
    IP_HEADER    IpHeader;
    TCP_HEADER    TcpHeader;
    PSD_HEADER    PsdHeader;
    u_char        Buffer[sizeof(ET_HEADER) + sizeof(IP_HEADER) + sizeof(TCP_HEADER)] = { 0 };

 if( (argc != 3) && (argc != 4) )
    {
        Usage( argv[0] );
        exit( -1 );
    }

 int    Flag = 2;
 if( argc == 4 )
    {
        Flag = 0;
 if( strchr(argv[3], 'U') || strchr(argv[3], 'u') )
        {
            Flag = Flag | 32;
        }
 if( strchr(argv[3], 'A') || strchr(argv[3], 'a') )
        {
            Flag = Flag | 16;
        }
 if( strchr(argv[3], 'P') || strchr(argv[3], 'p') )
        {
            Flag = Flag | 8;
        }
 if( strchr(argv[3], 'R') || strchr(argv[3], 'r') )
        {
            Flag = Flag | 4;
        }
 if( strchr(argv[3], 'S') || strchr(argv[3], 's') )
        {
            Flag = Flag | 2;
        }
 if( strchr(argv[3], 'F') || strchr(argv[3], 'f') )
        {
            Flag = Flag | 1;
        }
    }

 GetLocalIP( );
 if( -1 == GetDevices( ) )
    {
           exit( -1 );
    }

 printf( "Adapter is %s, ip is %s\n", InterfaceName, LocalIP );

 if( -1 == GetGateWayMac( ) )
    {
        exit( -1 );
    }

 printf( "Gateway IP is %s\n", GatewayIP );
 printf( "Gateway Mac is %x\n", *GatewayMac );

    memcpy( EtHeader.eh_dst, GatewayMac, 6 );
    memset( EtHeader.eh_src, 0xa, 6 );
    EtHeader.eh_type = htons( IP_PROTO );

    IpHeader.h_verlen = (4<<4 | sizeof(IpHeader)/sizeof(unsigned int));
    IpHeader.tos = 0;
    IpHeader.total_len = htons(sizeof(IpHeader)+sizeof(TcpHeader));
    IpHeader.ident = 1;
    IpHeader.frag_and_flags = 0x40;
    IpHeader.ttl = 128;
    IpHeader.proto = IPPROTO_TCP;
    IpHeader.checksum = 0;
    IpHeader.sourceIP = inet_addr( LocalIP );
    IpHeader.destIP = inet_addr( argv[1] );

    TcpHeader.th_sport = htons( rand()%60000 + 1024 );
    TcpHeader.th_dport = htons( atoi(argv[2]) );
    TcpHeader.th_seq = htonl( rand()%900000000 + 100000 );
    TcpHeader.th_ack = 0;
    TcpHeader.th_lenres = (sizeof(TcpHeader)/4<<4|0);
    TcpHeader.th_flag = Flag;
    TcpHeader.th_win = htons(512);
    TcpHeader.th_sum = 0;
    TcpHeader.th_urp = 0;

    PsdHeader.saddr = inet_addr( LocalIP );
    PsdHeader.daddr = IpHeader.destIP;
    PsdHeader.mbz = 0;
    PsdHeader.ptcl = IPPROTO_TCP;
    PsdHeader.tcpl = htons(sizeof(TcpHeader));

    memcpy( Buffer, &PsdHeader, sizeof(PsdHeader) );
    memcpy( Buffer + sizeof(PsdHeader), &TcpHeader, sizeof(TcpHeader) );
    TcpHeader.th_sum = CheckSum( (unsigned short *)Buffer, sizeof(PsdHeader) + sizeof(TcpHeader) );

    memset( Buffer, 0, sizeof(Buffer) );
    memcpy( Buffer, &IpHeader, sizeof(IpHeader) );
    IpHeader.checksum = CheckSum( (unsigned short *)Buffer, sizeof(IpHeader) );

    memset( Buffer, 0, sizeof(Buffer) );
    memcpy( Buffer, (void *)&EtHeader, sizeof(ET_HEADER) );
    memcpy( Buffer + sizeof(ET_HEADER), (void *)&IpHeader, sizeof(IP_HEADER) );
    memcpy( Buffer + sizeof(ET_HEADER) + sizeof(IP_HEADER), (void *)&TcpHeader, sizeof(TCP_HEADER) );

 char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    pcap_t *fp;
 if ( (fp= pcap_open( InterfaceName, 100, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf ) ) == NULL )
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", InterfaceName );
 return -1;
    }

 if ( pcap_sendpacket( fp, Buffer, sizeof(Buffer) ) != 0 )
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
 return -1;
    }
    printf( "send ok!\nData is:\n" );

 for( int i = 0; i < sizeof(Buffer); i ++ )
    {
         printf( "%02x ", Buffer );
    }

 return 0;
}
