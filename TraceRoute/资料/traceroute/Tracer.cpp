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

	//��ʼ��socket
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2),&wsaData)!=0)
    {
	    AfxMessageBox("WSAStartup()����!");
    }

}

CTracer::~CTracer()
{
	//�ر�Socket
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
//���ַ���ת��Ϊ��ַ
BOOL CTracer::FillAddress(char *addrDest)
{
	memset(&m_addrDest,0,sizeof(m_addrDest));
	m_addrDest.sin_family =AF_INET;
	if(inet_addr(addrDest)==INADDR_NONE)
	{
		//����ĵ�ַΪ���������
		HOSTENT* hp=NULL;
		hp=gethostbyname(addrDest);
		if(hp)
		{
		    memcpy(&(m_addrDest.sin_addr),hp->h_addr,hp->h_length);
			m_addrDest.sin_family =hp->h_addrtype ;
		}
		else
		{
			AfxMessageBox("��ȡ��ַʧ��!");
			return FALSE;
		}
	}
	else
	{
		m_addrDest.sin_addr.s_addr=inet_addr(addrDest);
	}
	return TRUE;
}
//���ICMP�����ײ�
void CTracer::FillICMPData(char* icmpData,int size)
{
	memset(icmpData,0,size);
	ICMPHEADER* icmpHeader=NULL;
	icmpHeader=(ICMPHEADER*)icmpData;
	icmpHeader->i_type =ICMP_ECHO;
	icmpHeader->i_code =0;
	icmpHeader->i_id =(USHORT)GetCurrentProcessId();
	icmpHeader->i_seq =m_nSeq++; 
	//GetTickCount���ش�0�㵽���ڵĺ���������ʱ���
	icmpHeader->timestamp=GetTickCount();
	char* datapart=icmpData+sizeof(ICMPHEADER);
    memset(datapart,'*',size-sizeof(ICMPHEADER));
	//���У���
    icmpHeader->i_cksum =CheckSum(icmpData,size);
}
//�������ݱ�������
BOOL CTracer::SetTTL(SOCKET hSocket, int ttl)
{
	int result;
	result=setsockopt(hSocket,IPPROTO_IP,IP_TTL,(LPSTR)&ttl,sizeof(ttl));
	if(result==SOCKET_ERROR)
	{
		AfxMessageBox("�������ݱ�����ʧ��!");
		TerminateProcess(GetCurrentProcess(),-1);
	}
	return TRUE;
}
//�������ݱ�
BOOL CTracer::SendData(char* icmpData,int size)
{
	//���ICMP��ͷ
    FillICMPData(icmpData,size);

	//�������ݱ�
	int result;
	result=sendto(m_hSocket,icmpData,size,0,(SOCKADDR*)&m_addrDest,sizeof(m_addrDest));
		 
	if(result==SOCKET_ERROR)
	{
		if(WSAGetLastError()==WSAETIMEDOUT)
		{
			((CTraceRouteDlg*)m_pWnd)->InfoAdd ("���ͳ�ʱ");
			return TRUE;
		}
		AfxMessageBox("���ͱ���ʧ��!");
		TerminateProcess(GetCurrentProcess(),-1);
	}
	return FALSE;
}
//�������ݱ�
BOOL CTracer::RecvData(char* icmpRcvBuf,int* presult)
{
	static int count=0;
	//�ܹ�6�γ��ֽ��ճ�ʱ���жϴ����������⡣
	if(count>5)            
	{
		AfxMessageBox("���Ӵ�������!");
		TerminateProcess(GetCurrentProcess(),-1);
	}

	int fromlen=sizeof(SOCKADDR);
	*presult=SOCKET_ERROR;
	*presult=recvfrom(m_hSocket,icmpRcvBuf,MAX_PACKET,0,(SOCKADDR*)&m_addrFrom,&fromlen);
		 
	if(*presult==SOCKET_ERROR)
	{
		if(WSAGetLastError()==WSAETIMEDOUT)
		{
			((CTraceRouteDlg*)m_pWnd)->InfoAdd ("���ճ�ʱ!");
			count++;
			return TRUE;
		}
		AfxMessageBox("�������ݱ�ʧ��!");
		TerminateProcess(GetCurrentProcess(),-1);
	}
	return FALSE;
}
//������յ������ݱ�
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
		AfxMessageBox("�������ݱ����Ȳ���ȷ!");
	
	icmpHeader=(ICMPHEADER*)(pBuffer+20);
    
    switch (icmpHeader->i_type)
    {
		//Ŀ��վ��ķ���
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
		//��;·�����ķ���
        case ICMP_TIMEOUT:     
            {
				CString report;
				report.Format("%2d  %s", ttl, inet_ntoa(inaddr));
				((CTraceRouteDlg*)m_pWnd)->InfoAdd(report);
				return FALSE;
				break;
			}
		//�����������ɴ�
        case ICMP_DESTUNREACH:  
            {
				CString report;
				report.Format("%2d  %s   �������ɴ�",ttl,inet_ntoa(inaddr));
				((CTraceRouteDlg*)m_pWnd)->InfoAdd(report);
				return TRUE;
				break;
			}
		//�յ�һ�����ǻ�Ӧ�ı���
        default:
			{
				CString report;
				report.Format("�ǻ�Ӧ����");
				((CTraceRouteDlg*)m_pWnd)->InfoAdd(report);
				return TRUE;
			}
           
    }
    return FALSE;
}
void CTracer::SetWnd(CDialog *pWnd)
{
	//���ô���ָ��
	m_pWnd=pWnd;
}
void CTracer::Trace(char *destAddress)
{
	 int size=DEF_PACKET_SIZE+sizeof(ICMPHEADER);
	 //ת����ַ
     if (!FillAddress(destAddress)) return ;

	 //�����Ҫ���ڴ�ռ�
	 icmpData=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,MAX_PACKET);
	 icmpRcvBuf=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,MAX_PACKET);
	 if(!icmpData||!icmpRcvBuf)
	 {
		 AfxMessageBox("�����ڴ�ռ�ʧ��!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }
	 memset(icmpData,0,MAX_PACKET);
	 memset(icmpRcvBuf,0,MAX_PACKET);
	 

//��ʼ���׽���
m_hSocket=WSASocket(AF_INET,SOCK_RAW,IPPROTO_ICMP,NULL,0,WSA_FLAG_OVERLAPPED);
	 if(m_hSocket==INVALID_SOCKET)
	 {   
		 AfxMessageBox("�׽��ֳ�ʼ��ʧ��!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }
	
	 //���ó�ʱѡ��
	 int nTimeOut=1000;
	 int result;
	 result=setsockopt(m_hSocket,SOL_SOCKET,SO_RCVTIMEO,(char*)&nTimeOut,sizeof(nTimeOut));
	 if(result==SOCKET_ERROR)
	 { 
		 AfxMessageBox("���ý��ճ�ʱѡ��ʧ��!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }
	 result=setsockopt(m_hSocket,SOL_SOCKET,SO_SNDTIMEO,(char*)&nTimeOut,sizeof(nTimeOut));
	 if(result==SOCKET_ERROR)
	 {
		 AfxMessageBox("���÷��ͳ�ʱѡ��ʧ��!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }
	 //����·�ɲ���ѯ·�ɱ�ѡ��
	 BOOL bDontRoute=TRUE;
	 result=setsockopt(m_hSocket,SOL_SOCKET,SO_DONTROUTE,(char*)&bDontRoute,sizeof(BOOL));
	 if(result==SOCKET_ERROR)
	 {
		 AfxMessageBox("���ò���ѯ·�ɱ�ѡ��ʧ��!");
		 TerminateProcess(GetCurrentProcess(),-1);
	 }

	 for(int ttl=1;ttl<MAX_NOTES;ttl++)
	 {
		 //�趨���ݱ�������
		 SetTTL(m_hSocket,ttl);
		 //�������ݱ�
		 if(SendData(icmpData,size)) continue; 
		 //�������ݱ�
		 if(RecvData(icmpRcvBuf,&result)) continue; 
		 //������յ������ݱ�
		 if (DecodeICMP(icmpRcvBuf,result,ttl)) break;
	 }
	 
	HeapFree(GetProcessHeap(), 0, icmpData);
    HeapFree(GetProcessHeap(), 0, icmpRcvBuf);
}

