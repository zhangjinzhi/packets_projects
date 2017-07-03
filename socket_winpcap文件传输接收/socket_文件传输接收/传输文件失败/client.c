//client.cpp
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <iostream.h>
//#include <fstream>
//using namespace std;
#define SERVERPORT 12345
#pragma comment(lib, "Wsock32")
#pragma comment(lib, "ws2_32")
receiveFile(SOCKET consock)
{
printf("Prepare to receive file\n");
FILE *dest;
char destfile[50];
char recvBuff[100];
// Receive name of the file
int namelen = recv(consock, recvBuff, 100, 0);
memcpy(destfile, recvBuff, namelen);
printf("Name of the file is %s \n", destfile);
if((dest=fopen(destfile,"wb"))==NULL)
{
printf("Can't open the dest file");
exit(0);
}
// Receive size of the file
int flag_file_len = recv(consock, recvBuff, 100, 0);
long file_len = 0;
for (int i = 0; flag_file_len != 0; i++)
{
long temp = recvBuff[i];
for (int j = 0; j != i; j++)
{
temp = temp * 10;
}
file_len = file_len + temp;
flag_file_len--;
}
printf("Size of the file is %ld\n", file_len);
printf("Ready to receive file\n");
char ch;
char chack = 1;
int n;
while ( recv(consock, &ch, 1, 0))
{
fputc(ch, dest);
send(consock, &chack, 1, 0);
file_len--;
if (file_len == 0)
{
break;
}
printf(".");
}
printf("\nTransmission finished\n");
}
int main()
{
    WSADATA words;
if(WSAStartup(MAKEWORD(2,2),&words)!=0)
{
printf("Winsock   init   failed\n");
}
SOCKET conSock;
conSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
if (conSock == INVALID_SOCKET)
{
printf("Socket create failed\n");
return 0;
}
struct sockaddr_in servAddr;
servAddr.sin_family = AF_INET;
servAddr.sin_port = htons(SERVERPORT);
servAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
if (connect(conSock, (SOCKADDR *)& servAddr, sizeof(servAddr)) == -1)
{
printf("Connect failed\n");
return 0;
}
else
{
printf("Connect to server succeed\n");
receiveFile(conSock);
}
closesocket(conSock);
WSACleanup();
return 1;
}
