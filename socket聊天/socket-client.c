/* --------------------------------------------------- */
// file name: socket-client.c
// file useage: demostrate the basic TCP-based blocked
//              socket programming in windows system
// file origin: demo of simplex-talk
//				computer networks, system approach, 4th
// modified by Wei Liu, 06/12/2011
/* --------------------------------------------------- */

/* wliu comments: required for linux socket programming */
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <netdb.h>

/* wliu comments: required for windows socket programming */
#include <winsock.h>
#pragma comment(lib, "wsock32.lib")

#include <WinBase.h>		//���ڵ��ÿ��е�Sleep()����
#include <windows.h>		//windows�Դ���ʱ�亯���⣬�ڱ�����δ�õ�
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SERVER_PORT 5432
#define MAX_BUFSIZE 256     //�������Ļ�����Ϊ256�ֽ�


int main(/*int argc, char * argv[]*/)		//����������������������޸�
{
	/* wliu comments: required for windows socket programming */
	WSADATA WSAData;		//WSADATA���ݽṹָ��
	int WSAreturn;

	/* wliu comments: useless pointer */
	//FILE *fp;

	struct hostent *hp;
	struct sockaddr_in sin;
	char *host;
	char buf[MAX_BUFSIZE];
	int s;
	int len;

	////////////////////////////////////////////
	SYSTEMTIME sys;		//����ʱ�亯���ṹ�壬�ڱ�����δ�õ�
	WORD Second;
	int count  = 5;		//������
	int resend = 0;		//�趨�ط���־
	int rerecv = 0;		//�趨���ձ�־
	int argc;
	char argv[2][32];

	// ���Դ���
	int nNetTimeOut = 5;		//�趨�������õķ��������ʱ�ޣ���λΪms
	argc            = 2;
	strcpy(argv[1], "127.0.0.1");

	////////////////////////////////////////////

	if (argc==2) {
		host = argv[1];
	}
	else {
		fprintf(stderr, "usage: simplex-talk host\n");
		exit(1);
	}

	/* wliu comments: modified for windows socket programming */
	WSAreturn = WSAStartup(0x101,&WSAData);		//ָ�����ص�Winsock�汾
	if(WSAreturn)		//WSAStartupִ�гɹ��Ժ󷵻�0����0���ӡ����
	{
		fprintf(stderr, "simplex-talk: WSA error.\n");
		exit(1);
	}

	/* translate host name into peer's IP address */
	hp = gethostbyname(host);		//���ض�Ӧ�ڸ����������İ�������
									//���ֺ͵�ַ��Ϣ��hostent�ṹָ��
	if (!hp) 		//gethostbynameִ�д����򷵻�һ����ָ��
	{
		fprintf(stderr, "simplex-talk: unknown host: %s\n", host);
		exit(1);
	}

	/* wliu comments: modified for string memory operation in windows */
	//bzero((char *)&sin, sizeof(sin));
	//bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);

	/* build address data structure */
	memset((char *)&sin, 0, sizeof(sin));		//�Խṹ���������
	memcpy((char *)&sin.sin_addr, hp->h_addr, hp->h_length);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(SERVER_PORT);		//�������ֽ�˳��ת��Ϊ�����ֽ�˳��
											//����С�ֽ���ת��Ϊ���ֽ���

	/* active open */
	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) 		//��������TCP/IP�����׽���
	{
		perror("simplex-talk: socket failed.");		//����������ӡ����
		exit(1);
	}

	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)		//�����׽�������
	{
		perror("simplex-talk: connect failed.");		//����������ӡ������Ϣ
		/* wliu comments: modified for windows socket programming */
		//close(s);
		closesocket(s);		//��ӡ������Ϣ�Ժ�ر��׽���
		exit(1);
	}

	/* wliu comments: displaying current status */
	printf("[simplex-talk client] connection to %s is ready\n", host);		//һ���������ӡ������Ϣ
	printf("[simplex-talk client] please input your message (empty input to halt):\n");		//һ���������ӡ������Ϣ

	// ���ý���ʱ��
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &nNetTimeOut, sizeof(int));
	// ���÷���ʱ��
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *) &nNetTimeOut, sizeof(int));


	/* wliu comments: modification to support connection termination */
	//while (fgets(buf, sizeof(buf), stdin)) {

	/* main loop: get and send lines of text */
	while (1)		//����ѭ��ֱ���˳�
	{
		if((resend || rerecv) != 1)		//�ж��Ƿ���Ҫ������Ϣ
		{
			fgets(buf, sizeof(buf), stdin);
		}

		/* wliu comments: modified to stop sending */
		if ( strlen(buf) == 1 )
		{
			/* wliu comments: user input empty message with '\n' */
			buf[0] = '\0';
			send(s, buf, 1, 0);
			printf("[simplex-talk client] empty message is send to server\n");
			break;
		}
		else
		{
			buf[MAX_BUFSIZE-1] = '\0';
			len = send(s, buf, strlen(buf) + 1, 0);		//���ط�����Ϣ
			if(len == -1)		//��ʱ�����·���
			{
				printf("���ͳ�ʱ\n");
				while(count >= 0)
				{
					printf("����׼���ط�...%d\r", count--);
					Sleep(1000);		//�ӳ�1����
				}
				printf("\n");
				count       = 5;		//�ָ�������
				resend      = 1;		//�ط���־��1
				nNetTimeOut += 10;		//���ͽ���ʱ���ӳ�10ms
				continue;
			}
			else		//��������ʾ���ͽ��
			{
				printf("[simplex-talk client] send %d chars to server\n", \
					strlen(buf) - 1);
				resend = 0;		//�ط���־��0
			}

			len = recv(s, buf, sizeof(buf), 0);		//�������Ƿ�ʱ
			if( len == -1 )		//��ʱ�����·���
			{
				printf("���ճ�ʱ\n");
				while(count >= 0)
				{
					printf("����׼���ط�...%d\r", count--);
					Sleep(1000);		//�ӳ�1����
				}
				printf("\n");
				count       = 5;		//�ָ�������
				rerecv      = 1;		//���ձ�־��1
				nNetTimeOut += 10;		//���ͽ���ʱ���ӳ�10ms
			}
			else		//��������ʾ�յ���ACKȷ���ź�
			{
				printf("[simplex-talk server] received %d chars from server \n", \
						strlen(buf));
				fputs(buf, stdout);
				printf("\n");
				rerecv = 0;		//���ձ�־��0
			}
		}

	}
	printf("[simplex-talk client] connection is terminated\n");

	/* wliu comments: modified for windows socket programming */
	WSACleanup();
	system("pause");
	return 1;
}



