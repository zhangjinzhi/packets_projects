////////////////////////////////////
//服务器代码
///////////////////////////////////
//本文件是服务器的代码
#include <netinet/in.h>  // for sockaddr_in
#include <sys/types.h>  // for socket
#include <sys/socket.h>  // for socket
#include <stdio.h>    // for printf
#include <stdlib.h>    // for exit
#include <string.h>    // for bzero
#include <time.h>        //for time_t and time
#define HELLO_WORLD_SERVER_PORT 7754
#define LENGTH_OF_LISTEN_QUEUE 20
#define BUFFER_SIZE 1024
int main(int argc, char **argv)
{
//设置一个socket地址结构server_addr,代表服务器internet地址, 端口
struct sockaddr_in server_addr;
bzero(&server_addr,sizeof(server_addr)); //把一段内存区的内容全部设置为0
server_addr.sin_family = AF_INET;
server_addr.sin_addr.s_addr = htons(INADDR_ANY);
server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);
// time_t now;
FILE *stream;
//创建用于internet的流协议(TCP)socket,用server_socket代表服务器socket
int server_socket = socket(AF_INET,SOCK_STREAM,0);
if( server_socket < 0)
{
printf("Create Socket Failed!");
exit(1);
}
//把socket和socket地址结构联系起来
if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
{
printf("Server Bind Port : %d Failed!", HELLO_WORLD_SERVER_PORT);
exit(1);
}
//server_socket用于监听
if ( listen(server_socket, LENGTH_OF_LISTEN_QUEUE) )
{
printf("Server Listen Failed!");
exit(1);
}
while (1) //服务器端要一直运行
{
struct sockaddr_in client_addr;
socklen_t length = sizeof(client_addr);
int new_server_socket = accept(server_socket,(struct sockaddr*)&client_addr,&length);
if ( new_server_socket < 0)
{
printf("Server Accept Failed!\n");
break;
}
char buffer[BUFFER_SIZE];
bzero(buffer, BUFFER_SIZE);
strcpy(buffer,"Hello,World! 从服务器来！");
strcat(buffer,"\n"); //C语言字符串连接
send(new_server_socket,buffer,BUFFER_SIZE,0);
bzero(buffer,BUFFER_SIZE);
//接收客户端发送来的信息到buffer中
length = recv(new_server_socket,buffer,BUFFER_SIZE,0);
if (length < 0)
{
printf("Server Recieve Data Failed!\n");
exit(1);
}
printf("\n%s",buffer);
if((stream = fopen("data1","r"))==NULL)
{
printf("The file 'data1' was not opened! \n");
exit(1);
}
else
printf("The file 'filename' was opened! \n");
bzero(buffer,BUFFER_SIZE);
int lengsize = 0;
while((lengsize = fread(buffer,1,1024,stream)) > 0)
{
printf("lengsize = %d\n",lengsize);
if(send(new_server_socket,buffer,lengsize,0)<0)
{
printf("Send File is Failed\n");
break;
}
bzero(buffer, BUFFER_SIZE);
}
if(fclose(stream))
printf("The file 'data' was not closed! \n");
exit(1);    
//关闭与客户端的连接
close(new_server_socket);    
}
//关闭监听用的socket
close(server_socket);
return 0;
}





////////////////////////////////////
//客户端代码
///////////////////////////////////
//本文件是客户机的代码
#include <netinet/in.h>  // for sockaddr_in
#include <sys/types.h>  // for socket
#include <sys/socket.h>  // for socket
#include <stdio.h>    // for printf
#include <stdlib.h>    // for exit
#include <string.h>    // for bzero
#include <time.h>        //for time_t and time
#include <arpa/inet.h>
#define HELLO_WORLD_SERVER_PORT  7754
#define BUFFER_SIZE 1024
int main(int argc, char **argv)
{
if (argc != 2)
{
printf("Usage: ./%s ServerIPAddress\n",argv[0]);
exit(1);
}
//time_t now;
FILE *stream;
//设置一个socket地址结构client_addr,代表客户机internet地址, 端口
struct sockaddr_in client_addr;
bzero(&client_addr,sizeof(client_addr)); //把一段内存区的内容全部设置为0
client_addr.sin_family = AF_INET;  //internet协议族
client_addr.sin_addr.s_addr = htons(INADDR_ANY);//INADDR_ANY表示自动获取本机地址
client_addr.sin_port = htons(0);  //0表示让系统自动分配一个空闲端口
//创建用于internet的流协议(TCP)socket,用client_socket代表客户机socket
int client_socket = socket(AF_INET,SOCK_STREAM,0);
if( client_socket < 0)
{
printf("Create Socket Failed!\n");
exit(1);
}
//把客户机的socket和客户机的socket地址结构联系起来
if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr)))
{
printf("Client Bind Port Failed!\n");
exit(1);
}
//设置一个socket地址结构server_addr,代表服务器的internet地址, 端口
struct sockaddr_in server_addr;
bzero(&server_addr,sizeof(server_addr));
server_addr.sin_family = AF_INET;
if(inet_aton(argv[1],&server_addr.sin_addr) == 0) //服务器的IP地址来自程序的参数
{
printf("Server IP Address Error!\n");
exit(1);
}
server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);
socklen_t server_addr_length = sizeof(server_addr);
//向服务器发起连接,连接成功后client_socket代表了客户机和服务器的一个socket连接
if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
{
printf("Can Not Connect To %s!\n",argv[1]);
exit(1);
}
char buffer[BUFFER_SIZE];
bzero(buffer,BUFFER_SIZE);
//从服务器接收数据到buffer中
int length = recv(client_socket,buffer,BUFFER_SIZE,0);
if(length < 0)
{
printf("Recieve Data From Server %s Failed!\n", argv[1]);
exit(1);
}
printf("\n%s\n",buffer);
bzero(buffer,BUFFER_SIZE);
bzero(buffer,BUFFER_SIZE);
strcpy(buffer,"Hello, World! From Client\n");
//向服务器发送buffer中的数据
send(client_socket,buffer,BUFFER_SIZE,0);
if((stream = fopen("data","w+t"))==NULL)
{
printf("The file 'data' was not opened! \n");
}
else
bzero(buffer,BUFFER_SIZE);
length = 0;
while( length = recv(client_socket,buffer,BUFFER_SIZE,0))
{
if(length < 0)
{
printf("Recieve Data From Server %s Failed!\n", argv[1]);
break;
}
int write_length = fwrite(buffer,sizeof(char),length,stream);
if (write_length<length)
{
printf("File is Write Failed\n");
break;
}
bzero(buffer,BUFFER_SIZE); 
}
printf("Recieve File From Server[%s] Finished\n", argv[1]);
//关闭 文件
fclose(stream);
//关闭socket
close(client_socket);
return 0;
}