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

#include <WinBase.h>		//用于调用库中的Sleep()函数
#include <windows.h>		//windows自带的时间函数库，在本例中未用到
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SERVER_PORT 5432
#define MAX_BUFSIZE 256     //设置最大的缓冲区为256字节


int main(/*int argc, char * argv[]*/)		//对主函数的输入参数做了修改
{
	/* wliu comments: required for windows socket programming */
	WSADATA WSAData;		//WSADATA数据结构指针
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
	SYSTEMTIME sys;		//定义时间函数结构体，在本例中未用到
	WORD Second;
	int count  = 5;		//计数器
	int resend = 0;		//设定重发标志
	int rerecv = 0;		//设定重收标志
	int argc;
	char argv[2][32];

	// 测试代码
	int nNetTimeOut = 5;		//设定测试所用的发送与接收时限，单位为ms
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
	WSAreturn = WSAStartup(0x101,&WSAData);		//指定加载的Winsock版本
	if(WSAreturn)		//WSAStartup执行成功以后返回0，非0则打印错误
	{
		fprintf(stderr, "simplex-talk: WSA error.\n");
		exit(1);
	}

	/* translate host name into peer's IP address */
	hp = gethostbyname(host);		//返回对应于给定主机名的包含主机
									//名字和地址信息的hostent结构指针
	if (!hp) 		//gethostbyname执行错误则返回一个空指针
	{
		fprintf(stderr, "simplex-talk: unknown host: %s\n", host);
		exit(1);
	}

	/* wliu comments: modified for string memory operation in windows */
	//bzero((char *)&sin, sizeof(sin));
	//bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);

	/* build address data structure */
	memset((char *)&sin, 0, sizeof(sin));		//对结构体进行清零
	memcpy((char *)&sin.sin_addr, hp->h_addr, hp->h_length);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(SERVER_PORT);		//将主机字节顺序转化为网络字节顺序，
											//即将小字节序转换为大字节序

	/* active open */
	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) 		//创建基于TCP/IP的流套接字
	{
		perror("simplex-talk: socket failed.");		//如果出错则打印错误
		exit(1);
	}

	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)		//建立套接字连接
	{
		perror("simplex-talk: connect failed.");		//如果出错则打印错误信息
		/* wliu comments: modified for windows socket programming */
		//close(s);
		closesocket(s);		//打印出错信息以后关闭套接字
		exit(1);
	}

	/* wliu comments: displaying current status */
	printf("[simplex-talk client] connection to %s is ready\n", host);		//一切正常则打印正常信息
	printf("[simplex-talk client] please input your message (empty input to halt):\n");		//一切正常则打印正常信息

	// 设置接收时限
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *) &nNetTimeOut, sizeof(int));
	// 设置发送时限
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *) &nNetTimeOut, sizeof(int));


	/* wliu comments: modification to support connection termination */
	//while (fgets(buf, sizeof(buf), stdin)) {

	/* main loop: get and send lines of text */
	while (1)		//无限循环直至退出
	{
		if((resend || rerecv) != 1)		//判断是否需要输入信息
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
			len = send(s, buf, strlen(buf) + 1, 0);		//返回发送信息
			if(len == -1)		//超时则重新发送
			{
				printf("发送超时\n");
				while(count >= 0)
				{
					printf("正在准备重发...%d\r", count--);
					Sleep(1000);		//延迟1秒钟
				}
				printf("\n");
				count       = 5;		//恢复计数器
				resend      = 1;		//重发标志置1
				nNetTimeOut += 10;		//发送接收时限延长10ms
				continue;
			}
			else		//正常则显示发送结果
			{
				printf("[simplex-talk client] send %d chars to server\n", \
					strlen(buf) - 1);
				resend = 0;		//重发标志置0
			}

			len = recv(s, buf, sizeof(buf), 0);		//检测接收是否超时
			if( len == -1 )		//超时则重新发送
			{
				printf("接收超时\n");
				while(count >= 0)
				{
					printf("正在准备重发...%d\r", count--);
					Sleep(1000);		//延迟1秒钟
				}
				printf("\n");
				count       = 5;		//恢复计数器
				rerecv      = 1;		//重收标志置1
				nNetTimeOut += 10;		//发送接收时限延长10ms
			}
			else		//正常则显示收到的ACK确认信号
			{
				printf("[simplex-talk server] received %d chars from server \n", \
						strlen(buf));
				fputs(buf, stdout);
				printf("\n");
				rerecv = 0;		//重收标志置0
			}
		}

	}
	printf("[simplex-talk client] connection is terminated\n");

	/* wliu comments: modified for windows socket programming */
	WSACleanup();
	system("pause");
	return 1;
}



