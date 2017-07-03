///发送方
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <winsock.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wsock32.lib")
void main() {
// 初始化
    WSADATA wsaData;
    int iResult = WSAStartup( MAKEWORD(2,2), &wsaData );
    if ( iResult != NO_ERROR )
        printf("Error at WSAStartup()\n");    // 建立socket
    SOCKET server;
    server = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );    if ( server == INVALID_SOCKET ) {
        printf( "Error at socket(): %ld\n", WSAGetLastError() );
        WSACleanup();
        return;
    }    // 绑定socket
    struct sockaddr_in service;
    service.sin_family = AF_INET;
 service.sin_addr.S_un.S_addr = INADDR_ANY;
    //service.sin_addr.s_addr = inet_addr( "127.0.0.1" );
    service.sin_port = htons(8000);
    if ( bind( server, (SOCKADDR*) &service, sizeof(service) ) == SOCKET_ERROR ) {
        printf( "bind() failed.\n" );
        closesocket(server);
        return;
    }

    // 监听 socket
    if ( listen( server, 1 ) == SOCKET_ERROR )
        printf( "Error listening on socket.\n");    // 接受连接
    SOCKET AcceptSocket;
     printf( "Waiting for a client to connect...\n" );
    while (1) {
        AcceptSocket = SOCKET_ERROR;
        while ( AcceptSocket == SOCKET_ERROR ) {
            AcceptSocket = accept( server, NULL, NULL );
        }
        printf( "Client Connected.\n");
        server = AcceptSocket;
        break;
    }

    // 发送接受数据
//    int bytesSent;
    char sendbuf[1024];//发送缓冲区
 //DWORD dwFileSize;//文件大小
   DWORD        dwRead;
    BOOL         bRet;
    char filename[]="F:\\1\\2.doc";
    printf("%s",filename);
 HANDLE hFile=CreateFile(filename,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
 //dwFileSize=GetFileSize(hFile,NULL);
 while(1)
    {
      bRet=ReadFile(hFile,sendbuf,1024,&dwRead,NULL);
      if(bRet==FALSE)
      {
        MessageBox(NULL,"Read Buf ERROR!","Error",MB_OK);
        break;
      }
      else if(dwRead==0)
      {
        MessageBox(NULL,"Send file OK!","OK",MB_OK);
        break;
      }
      else
      {
       send(server,sendbuf,dwRead,0);
      }
    };
    CloseHandle(hFile);
    return;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////// //接收文件
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
