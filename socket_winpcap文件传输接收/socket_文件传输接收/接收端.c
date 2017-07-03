//接收文件
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <winsock.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wsock32.lib")
void main() {

    // 初始化 Winsock.
    WSADATA wsaData;
    int iResult = WSAStartup( MAKEWORD(2,2), &wsaData );
    if ( iResult != NO_ERROR )
        printf("Error at WSAStartup()\n");

    // 建立socket socket.
    SOCKET client;
    client = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

    if ( client == INVALID_SOCKET ) {
        printf( "Error at socket(): %ld\n", WSAGetLastError() );
        WSACleanup();
        return;
    }

    // 连接到服务器.
   struct sockaddr_in clientService;

    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr( "127.0.0.1" );
    clientService.sin_port = htons( 8000 );

    if ( connect( client, (SOCKADDR*) &clientService, sizeof(clientService) ) == SOCKET_ERROR) {
        printf( "Failed to connect.\n" );
        WSACleanup();
        return;
    }
    char recvbuf[1024];//发送缓冲区
 int read;
 DWORD        dwWrite;
    BOOL         bRet;
    // 发送并接收数据.
    char filename[]="F:\\1\\1.doc";
    printf("%s",filename);
 HANDLE hFile=CreateFile(filename,GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
 while(1)
    {
  read=recv( client, recvbuf, 1024, 0 );
  if(read==-1)break;
  bRet=WriteFile(hFile,recvbuf,read,&dwWrite,NULL);
  if(bRet==FALSE)
  {
   MessageBox(NULL,"Write Buf ERROR!","Error",MB_OK);
   break;
  }

    }
 MessageBox(NULL,"Receive file OK!","OK",MB_OK);
    return;
}
