//server.cpp
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <io.h>
#define LISTENPORT 12345
#pragma comment(lib,"Wsock32")
#pragma comment(lib,"ws2_32")
sendFile(SOCKET conSock)
{
printf("Prapare to send file\n");
//char *sendBuf = new char[100];
char sendBuf[100];
FILE *in;
char infile[50]="F:\\1\\1.doc";
if((in=fopen(infile,"rb"))==NULL)
{
printf("Can't open the source file");
exit(0);
}
printf("File name is %s\n", infile);
// send file name to the client
send(conSock, infile, sizeof(infile), 0);
int handle = open(infile, 0x0001);
long file_len = filelength(handle);
long file_len_bak = file_len;
printf("Size of the file is %d\n", file_len);
// store the length of the file in sendBuffer
int i;
for (i = 0; file_len > 9; i++)
{
  sendBuf[i] = (file_len % 10);
  file_len = file_len / 10;
}
sendBuf[i] = file_len % 10;
send(conSock,sendBuf,i+1,0);

printf("Transmission started\n");
Sleep(1);
char ch;
char chack;
while (file_len_bak != 0)
{
ch = fgetc(in);
send(conSock, &ch, 1, 0);
recv(conSock, &chack, 1, 0);
file_len_bak--;
printf(".");
}

ch = EOF;
send(conSock, &ch, 1, 0);
printf("\nTransmission finished");
}

int main()
{
WSADATA words;
if(WSAStartup(MAKEWORD(2,2),&words)!=0)
{
printf("Winsock   init   failed!\n");
}

SOCKET listenSock, conSock;

struct sockaddr_in remoteAddr;
int remoteAddrLen;
int ServerAddrLen;

listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
if (listenSock == INVALID_SOCKET)
{
printf("ListenSocket create failed!\n");
return 0;
}

struct sockaddr_in sin;
sin.sin_family = AF_INET;
sin.sin_port = htons(LISTENPORT);
sin.sin_addr.S_un.S_addr = INADDR_ANY;
ServerAddrLen = sizeof(sin);

if (bind(listenSock, (SOCKADDR*)&sin, ServerAddrLen) == SOCKET_ERROR)
{
printf("Bind error!\n");
return 0;
}

if (listen(listenSock, 2) == SOCKET_ERROR)
{
printf("Can't listen!\n");
return 0;
}

remoteAddrLen = sizeof(remoteAddr);

while (TRUE)
{
conSock = accept(listenSock, (SOCKADDR*)& remoteAddr, &remoteAddrLen);
if (conSock == INVALID_SOCKET)
{
printf("Accept failed!\n");
continue;
}
else
{
printf("Accept a new connect : %s \r\n", inet_ntoa(remoteAddr.sin_addr));
sendFile(conSock);
}
}

closesocket(conSock);
closesocket(listenSock);
WSACleanup();
return 1;
}
