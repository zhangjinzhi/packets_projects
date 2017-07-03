////////////////////////////////////
//����������
///////////////////////////////////
//���ļ��Ƿ������Ĵ���
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
//����һ��socket��ַ�ṹserver_addr,���������internet��ַ, �˿�
struct sockaddr_in server_addr;
bzero(&server_addr,sizeof(server_addr)); //��һ���ڴ���������ȫ������Ϊ0
server_addr.sin_family = AF_INET;
server_addr.sin_addr.s_addr = htons(INADDR_ANY);
server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);
// time_t now;
FILE *stream;
//��������internet����Э��(TCP)socket,��server_socket���������socket
int server_socket = socket(AF_INET,SOCK_STREAM,0);
if( server_socket < 0)
{
printf("Create Socket Failed!");
exit(1);
}
//��socket��socket��ַ�ṹ��ϵ����
if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
{
printf("Server Bind Port : %d Failed!", HELLO_WORLD_SERVER_PORT);
exit(1);
}
//server_socket���ڼ���
if ( listen(server_socket, LENGTH_OF_LISTEN_QUEUE) )
{
printf("Server Listen Failed!");
exit(1);
}
while (1) //��������Ҫһֱ����
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
strcpy(buffer,"Hello,World! �ӷ���������");
strcat(buffer,"\n"); //C�����ַ�������
send(new_server_socket,buffer,BUFFER_SIZE,0);
bzero(buffer,BUFFER_SIZE);
//���տͻ��˷���������Ϣ��buffer��
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
//�ر���ͻ��˵�����
close(new_server_socket);    
}
//�رռ����õ�socket
close(server_socket);
return 0;
}





////////////////////////////////////
//�ͻ��˴���
///////////////////////////////////
//���ļ��ǿͻ����Ĵ���
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
//����һ��socket��ַ�ṹclient_addr,����ͻ���internet��ַ, �˿�
struct sockaddr_in client_addr;
bzero(&client_addr,sizeof(client_addr)); //��һ���ڴ���������ȫ������Ϊ0
client_addr.sin_family = AF_INET;  //internetЭ����
client_addr.sin_addr.s_addr = htons(INADDR_ANY);//INADDR_ANY��ʾ�Զ���ȡ������ַ
client_addr.sin_port = htons(0);  //0��ʾ��ϵͳ�Զ�����һ�����ж˿�
//��������internet����Э��(TCP)socket,��client_socket����ͻ���socket
int client_socket = socket(AF_INET,SOCK_STREAM,0);
if( client_socket < 0)
{
printf("Create Socket Failed!\n");
exit(1);
}
//�ѿͻ�����socket�Ϳͻ�����socket��ַ�ṹ��ϵ����
if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr)))
{
printf("Client Bind Port Failed!\n");
exit(1);
}
//����һ��socket��ַ�ṹserver_addr,�����������internet��ַ, �˿�
struct sockaddr_in server_addr;
bzero(&server_addr,sizeof(server_addr));
server_addr.sin_family = AF_INET;
if(inet_aton(argv[1],&server_addr.sin_addr) == 0) //��������IP��ַ���Գ���Ĳ���
{
printf("Server IP Address Error!\n");
exit(1);
}
server_addr.sin_port = htons(HELLO_WORLD_SERVER_PORT);
socklen_t server_addr_length = sizeof(server_addr);
//���������������,���ӳɹ���client_socket�����˿ͻ����ͷ�������һ��socket����
if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
{
printf("Can Not Connect To %s!\n",argv[1]);
exit(1);
}
char buffer[BUFFER_SIZE];
bzero(buffer,BUFFER_SIZE);
//�ӷ������������ݵ�buffer��
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
//�����������buffer�е�����
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
//�ر� �ļ�
fclose(stream);
//�ر�socket
close(client_socket);
return 0;
}