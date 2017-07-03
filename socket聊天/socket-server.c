/* --------------------------------------------------- */
// file name: socket-server.c
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
#include <stdio.h>
#include <string.h>

#define SERVER_PORT 5432
#define MAX_PENDING 5
#define MAX_BUFSIZE 256		//设置最大缓冲区为256字节

#define MAX_CONNECTION 32	//设置最大连接数为32个


int main()
{
    /* wliu comments: required for windows socket programming */
    WSADATA WSAData;
    int WSAreturn;

    struct sockaddr_in sin;
    char buf[MAX_BUFSIZE];
    int len;
    int s, new_s;

	/* wliu comments: connections */
	int conn;

    /* wliu comments: required for windows socket programming */
	WSAreturn = WSAStartup(0x101,&WSAData);		//指定加载的Winsock版本
	if(WSAreturn)		//WSAStartup执行成功以后返回0，非0则打印错误
	{
		fprintf(stderr, "simplex-talk: WSA error.\n");
		exit(1);
	}

    /* wliu comments: modified for string memory operation in windows */
    //bzero((char *)&sin, sizeof(sin));

    /* build address data structure */
    memset((char *)&sin, 0, sizeof(sin));		//对结构体进行清零
    sin.sin_family = AF_INET;		//指定地址族
    sin.sin_addr.s_addr = INADDR_ANY;		//制定IP地址
    sin.sin_port = htons(SERVER_PORT);		//将主机字节顺序转化为网络字节顺序，
											//即将小字节序转换为大字节序
    /* setup passive open */
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)		//创建基于TCP/IP的流套接字
    {
		perror("simplex-talk: socket failed.");		//如果出错则打印错误
		exit(1);
    }
    if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0)		//绑定套接字
    {
		perror("simplex-talk: bind failed.");		//绑定失败则返回错误信息
		exit(1);
    }

    listen(s, MAX_PENDING);		//对套接字进行侦听

	/* wliu comments: displaying current status */
    printf("[simplex-talk server] server is ready in listening ...\n");


    /* wait for connection, then receive and print text */
	conn = 0;
    while( conn < MAX_CONNECTION )		//判断是否超出连接数上限
    {
        /* wliu comments: correction for variable len */
        len = sizeof(struct sockaddr_in);

        if ((new_s = accept(s, (struct sockaddr *)&sin, &len)) < 0)		//建立套接字连接
        {
            perror("simplex-talk: accept failed.");		//失败则打印错误信息
            exit(1);
        }

		/* wliu comments: displaying current status */
        printf("[simplex-talk server] received a connection from %s : \n", inet_ntoa(sin.sin_addr));
        //成功则打印客户机IP地址
        //inet_ntoa作用是将一个IP转换成一个互联网标准点分格式的字符串

		/* wliu comments: modification to support connection termination */
        //while (len = recv(new_s, buf, sizeof(buf), 0))  {
		while (1)
		{
            len = recv(new_s, buf, sizeof(buf), 0);

			/* wliu comments: modified to stop sending */
			if ( strlen(buf) == 0 )
			{
				/* wliu comments: received empty message */
				printf("[simplex-talk server] empty message is received\n");
				break;
			}
			else
			{
				printf("[simplex-talk server] received %d chars \n", strlen(buf) - 1);
				fputs(buf, stdout);		//打印收到的信息
				strcpy( buf, "ACK" );
				len = strlen(buf) + 1;
				// Sleep(10);		//延时函数，用于模拟客户机接收超时
				send(new_s, buf, len, 0);		//回复ACK确认信号
				printf("[simplex-talk client] send %d chars to client\n", strlen(buf));
				buf[0] = "\0";
			}
        }

		printf("[simplex-talk server] connection from %s is terminated\n", \
			inet_ntoa(sin.sin_addr));

		/* wliu comments: modified for windows socket programming */
		//close(new_s);
		closesocket(new_s);

		conn ++;		//连接数加1
    }

	printf("[simplex-talk server] max_connections achieved, server halt\n");

    /* wliu comments: required for windows socket programming */
    WSACleanup();
	return 1;
}