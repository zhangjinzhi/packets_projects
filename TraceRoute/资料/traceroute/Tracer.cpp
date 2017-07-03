// Tracer.cpp: implementation of the CTracer class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "TraceRoute.h"
#include "Tracer.h"
#include"TraceRouteDlg.h"
#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CTracer::CTracer()
{
	m_nSeq=1;
	icmpData=NULL;
	icmpRcvBuf=NULL;
    m_hSocket=INVALID_SOCKET;

	//初始化socket
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2),&wsaData)!=0)
    {
	    AfxMessageBox("WSAStartup()出错!");
    }

}

CTracer::~CTracer()
{
	//关闭Socket
	if (m_hSocket!=NULL)
		closesocket(m_hSocket);    
	WSACleanup();
}
USHORT CTracer::CheckSum(char* pBuffer,int size)
{  
USHORT* buffer=(USHORT*)pBuffer;
	unsigned long cksum=0;
 	   while(size > 1) 
 	   {
 	       cksum += *buffer++;
 	       size -= sizeof(USHORT);
 	   }
  	  if(size )
     	   cksum += *(UCHAR*)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
   		 return (USHORT)(~cksum);
}
//由字符串转化为地址
BOOL CTracer::FillAddress(char *addrDest)
{
	memset(&m_addrDest,0,sizeof(m_addrDest));
	m_addrDest.sin_family =AF_INET;
	if(inet_addr(addrDest)==INADDR_NONE)
	{
		//输入的地址为计算机名字
		HOSTENT* hp=NULL;
		hp=gethostbyname(addrDest);
		if(hp)
		{
		    memcpy(&(m_addrDest.sin_addr),hp->h_addr,hp->h_length);
			m_addrDest.sin_family =hp->h_addrtype ;
		}
		else
		{
			AfxMessageBox("获取地址失败!");
			return FALSE;
		}
	}
	else
	{
		m_addrDest.sin_addr.s_addr=inet_addr(addrDest);
	}
	return TRUE;
}
//填充ICMP报文首部
void CTracer::FillICMPData(char* icmpData,int size)
{
	memset(icmpData,0,size);
	ICMPHEADER* icmpHeader=NULL;
	icmpHeader=(ICMPHEADER*)icmpData;
	icmpHeader->i_type =ICMP_ECHO;
	icmpHeader->i_code =0;
	icmpHeader->i_id =(USHORT)GetCurrentProcessId();
	icmpHeader->i_seq =m_nSeq++; 
	//GetTickCount返回从0点到现在的毫秒数，作时间戳
	icmpHeader->timestamp=GetTickCount();
	char* datapart=icmpData+sizeof(ICMPHEADER);
    memset(datapart,'*',size-sizeof(ICMPHEADER));
	//填充校验和
    icmpHeader->i_cksum =CheckSum(icmpData,size);
}
//设置数据报的寿命
BOOL CTracer::SetTTL(SOCKET hSocket, int ttl)
{
	int result;
	result=setsockopt(hSocket,IPPROTO_IP,IP_TTL,(LPSTR)&ttl,sizeof(ttl));
	if(result==SOCKET_ERROR)
	{
		AfxMessageBox("设置数据报寿命失败!");
		TerminateProcess(GetCurrentProcess(),-1);
	}
	return TRUE;
}
//发送数据报
BOOL CTracer::SendData(char* icmpData,int size)
{
	//填充ICMP报头
    FillICMPData(icmpData,size);

	//发送数据报
	int result;
	result=sendto(m_hSocket,icmpData,size,0,(SOCKADDR*)&m_addrDest,sizeof(m_addrDest));
		 
	if(result==SOCKET_ERROR)
	{
		if(WSAGetLastError()==WSAETIMEDOUT)
		{
			((CTraceRouteDlg*)m_pWnd)->InfoAdd ("发送超时");
			return TRUE;
		}
		AfxMessageBox("发送报文失败!");
		TerminateProcess(GetCurrentProcess(),-1);
	}
	return FALSE;
}
//接收数据报
BOOL CTracer::RecvData(char* icmpRcvBuf,int* presult)
{
	static int count=0;
	//总共6次出现接收超时，判断存在连接问题。
	if(count>5)            
	{
		AfxMessageBox("连接存在问题!");
		TerminateProcess(GetCurrentProcess(),-1);
	}

	int fromlen=sizeof(SOCKADDR);
	*presult=SOCKET_ERROR;
	*presult=recvfrom(m_hSocket,icmpRcvBuf,MAX_PACKET,0,(SOCKADDR*)&m_addrFrom,&fromlen);
		 
	if(*presult==SOCKET_ERROR)
	{
		if(WSAGetLastError()==WSAETIMEDOUT)
		{
			((CTraceRouteDlg*)m_pWnd)->InfoAdd ("接收超时!");
			count++;
			return TRUE;
		}
		AfxMessageBox("接收数据报失败!");
		TerminateProcess(GetCurrentProcess(),-1);
	}
	return FALSE;
}
//处理接收到的数据报
BOOL CTracer::DecodeICMP(char* pBuffer,int bytes,int ttl)
{
    IPHEADER       *ipHeader=NULL;
    ICMPHEADER     *icmpHeader=NULL;
    unsigned short  ipHeaderLen;
    HOSTENT *ph=NULL;
    in_addr inaddr=m_addrFrom.sin_addr;

    ipHeader=(IPHEADER*)pBuffer;
	ipHeaderLen=20;

    if (bytes<ipHeaderLen+ICMP_MIN) 
		AfxMessageBox("接收数据报长度不正确!");
	
	icmpHeader=(ICMPHEADER*)(pBuffer+20);
    
    switch (icmpHeader->i_type)
    {
		//目的站点的返回
        case ICMP_ECHOREPLY:     
            ph=gethostbyaddr((const char *)&inaddr,AF_INET, sizeof(in_addr));
            if (ph != NULL)
			{
				CString report;
				report.Format("%2d  %s (%s)",ttl,ph->h_name,inet_ntoa(inaddr));
				((CTraceRouteDlg*)m_pWnd)->InfoAdd(report);
			}
			return TRUE;
            break;
		//中途路由器的返回
        case ICMP_TIMEOUT:     
            {
				CString report;
				report.Format("%2d  %s", ttl, inet_ntoa(inaddr));
				((CTraceRouteDlg*)m_pWnd)->InfoAdd(report);
				return FALSE;
				break;
			}
		//错误：主机不可达
        case ICMP_DESTUNREACH:  
            {
				CString report;
				report.Format("%2d  %s   主机不可达",ttl,inet_ntoa(inaddr));
				((CTraceRouteDlg*)m_pWnd)->InfoAdd(report);
				return TRUE;
				break;
			}
		//收到一个不是回应的报文
        default:
			{
				CString report;
				report.Format("非回应报文");
				((CTraceRouteDlg*)m_pWnd)->InfoAdd(report);
				return TRUE;
			}
           
    }
    return FALSE;
}
void CTracer::SetWnd(CDialog *pWnd)
{
	//设置窗口指针
	m_pWnd=pWnd;
}
void CTracer::Trace(char *destAddress)
{
	 int size=DEF_PACKET_SIZE+sizeof(ICMPHEADER);
	 //转换地址
     if (!FillAddress(destAddress)) return ;

	 //分配必要的内存空间
	 icmpData=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,MAX_PACKET);
	 icmpRcvBuf=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,MAX_PACKET);
	 if(!icmpData||!icmpRcvBuf)
	 {
		 AfxMessageBox("分配内存空间失败!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }
	 memset(icmpData,0,MAX_PACKET);
	 memset(icmpRcvBuf,0,MAX_PACKET);
	 

//初始化套接字
m_hSocket=WSASocket(AF_INET,SOCK_RAW,IPPROTO_ICMP,NULL,0,WSA_FLAG_OVERLAPPED);
	 if(m_hSocket==INVALID_SOCKET)
	 {   
		 AfxMessageBox("套接字初始化失败!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }
	
	 //设置超时选项
	 int nTimeOut=1000;
	 int result;
	 result=setsockopt(m_hSocket,SOL_SOCKET,SO_RCVTIMEO,(char*)&nTimeOut,sizeof(nTimeOut));
	 if(result==SOCKET_ERROR)
	 { 
		 AfxMessageBox("设置接收超时选项失败!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }
	 result=setsockopt(m_hSocket,SOL_SOCKET,SO_SNDTIMEO,(char*)&nTimeOut,sizeof(nTimeOut));
	 if(result==SOCKET_ERROR)
	 {
		 AfxMessageBox("设置发送超时选项失败!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }
	 //设置路由不查询路由表选项
	 BOOL bDontRoute=TRUE;
	 result=setsockopt(m_hSocket,SOL_SOCKET,SO_DONTROUTE,(char*)&bDontRoute,sizeof(BOOL));
	 if(result==SOCKET_ERROR)
	 {
		 AfxMessageBox("设置不查询路由表选项失败!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }

	 for(int ttl=1;ttl<MAX_NOTES;ttl++)
	 {
		 //设定数据报的寿命
		 SetTTL(m_hSocket,ttl);
		 //发送数据报
		 if(SendData(icmpData,size)) continue; 
		 //接收数据报
		 if(RecvData(icmpRcvBuf,&result)) continue; 
		 //处理接收到的数据报
		 if (DecodeICMP(icmpRcvBuf,result,ttl)) break;
	 }
	 
	HeapFree(GetProcessHeap(), 0, icmpData);
    HeapFree(GetProcessHeap(), 0, icmpRcvBuf);
}

