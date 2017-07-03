������������һ��С������ʵ�ֵĹ��ܾ��ǲ����û�ָ���豸���������ݰ����������ļ���

#define HAVE_REMOTE
#include <pcap.h>
 
/* �ص�����ԭ�� */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
 
int main(int argc, char **argv)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t *dumpfile;
 
 
 
    /* ������������� */
    if(argc != 2)
    {
        printf("usage: %s filename", argv[0]);
        return -1;
    }
 
    /* ��ȡ�����豸�б� */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
 
    /* ��ӡ�б� */
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
        /* �ͷ��б� */
        pcap_freealldevs(alldevs);
        return -1;
    }
 
    /* ��ת��ѡ�е������� */
    for(d=alldevs, i=0; i< inum-1 ; d=d->next, i++);
 
 
    /* �������� */
    if ( (adhandle= pcap_open(d->name,          // �豸��
                              65536,            // Ҫ��׽�����ݰ��Ĳ���
                              // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                              PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
                              1000,             // ��ȡ��ʱʱ��
                              NULL,             // Զ�̻�����֤
                              errbuf            // ���󻺳��
                             ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }
 
    /* �򿪶��ļ� */
    dumpfile = pcap_dump_open(adhandle, argv[1]);
 
    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }
 
    printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);
 
    /* �ͷ��豸�б� */
    pcap_freealldevs(alldevs);
 
    /* ��ʼ���� */
    pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);
 
    return 0;
}
 
/* �ص������������������ݰ� */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /* �������ݰ������ļ� */
    pcap_dump(dumpfile, header, pkt_data);
}
��
�����������������ô�س��������������֮ǰд���Ĳ��͵Ļ���dumpfile����һ��pcap_dumper�ṹ��ָ�룬
�����޴ӿ���pcap_dumper�ṹ��Ķ��壬��Ҳ��WinPcap�ں˵�һ���֡��ĵ��Ͻ�������һ��libpcap�ļ���������
����pcap_dump_open()����ֻ��Ҫ������������һ���ǽӿ�ָ�룬��һ�����ļ��������ص����ļ�ָ�롣
ͨ������pcap_dump_open()����������ǾͿ��Խ��ļ��ͽӿڹ���������
pcap_loop()�ص�������ֻ��һ�д��룬pcap_dump()�����������ǽ���������д���ļ���
����������Ҫע��һ��pcap_loop()�����ĸ��������¿���֪��pcap_loop()���һ�������ǻص�������һ���û�������
������һ���򵥵�д�ļ����������������ٿ�����δ�dump�ļ��н����ݶ�ȡ��������Ȼ�Ǹ���һ��ʵ����

#define HAVE_REMOTE
#include <stdio.h>
#include <pcap.h>
 
#define LINE_LEN 16
 
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
 
int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
 
    if(argc != 2)
    {
 
        printf("usage: %s filename", argv[0]);
        return -1;
 
    }
 
    /* ������WinPcap�﷨����һ��Դ�ַ��� */
    if ( pcap_createsrcstr( source,         // Դ�ַ���
                            PCAP_SRC_FILE,  // ����Ҫ�򿪵��ļ�
                            NULL,           // Զ������
                            NULL,           // Զ�������˿�
                            argv[1],        // ����Ҫ�򿪵��ļ���
                            errbuf          // ���󻺳���
                          ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
 
    /* �򿪲����ļ� */
    if ( (fp= pcap_open(source,         // �豸��
                        65536,          // Ҫ��׽�����ݰ��Ĳ���
                        // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                        PCAP_OPENFLAG_PROMISCUOUS,     // ����ģʽ
                        1000,              // ��ȡ��ʱʱ��
                        NULL,              // Զ�̻�����֤
                        errbuf         // ���󻺳��
                       ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s.\n", source);
        return -1;
    }
 
    // ��ȡ���������ݰ���ֱ��EOFΪ��
    pcap_loop(fp, 0, dispatcher_handler, NULL);
 
    return 0;
}
 
 
 
void dispatcher_handler(u_char *temp1,
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int i=0;
 
    /* ��ӡpktʱ�����pkt���� */
    printf("%ld:%ld (%u)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
 
    /* ��ӡ���ݰ� */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }
 
    printf("\n\n");
 
}