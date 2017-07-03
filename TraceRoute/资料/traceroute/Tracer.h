// Tracer.h: interface for the CTracer class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TRACER_H__FA3E73EF_D951_4145_B740_AD9D88EA4E86__INCLUDED_)
#define AFX_TRACER_H__FA3E73EF_D951_4145_B740_AD9D88EA4E86__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include "winsock2.h"
#include "ws2tcpip.h"


//��Ҫ�ĺ궨��
#define DEF_PACKET_SIZE		32
#define MAX_PACKET				1024
#define MAX_NOTES				30
#define ICMP_MIN				8

#define ICMP_ECHOREPLY      	0
#define ICMP_DESTUNREACH    	3
#define ICMP_SRCQUENCH      	4
#define ICMP_REDIRECT       	5
#define ICMP_ECHO           	8
#define ICMP_TIMEOUT       	11
#define ICMP_PARMERR       	12
struct ICMPHEADER
{
    BYTE   i_type;               // ����
    BYTE   i_code;               // ����
    USHORT i_cksum;              // �ײ�У���
    USHORT i_id;                 // ��ʶ
    USHORT i_seq;                // ���к�
    ULONG timestamp;             // ʱ���(ѡ��)
	unsigned int	time;		//ʱ��
};
struct IPHEADER
{	unsigned int       h_len:4;          // �ײ�����
	unsigned int       version:4;         // �汾
    unsigned char      tos;             // ��������
    unsigned short     total_len;         // �����ܳ���
    unsigned short     ident;            // ��ʶ
    unsigned short     frag_and_flags;   // ƫ����
    unsigned char      ttl;             // ����
    unsigned char      proto;          // Э��
    unsigned short     checksum;       // �ײ�У���
    unsigned int       sourceIP;       // ԴվIP
    unsigned int       destIP;         // Ŀ��վIP
};


class CTracer  
{
public:
	CTracer();
	virtual ~CTracer();
	void Trace(char*);
	void SetWnd(CDialog *);
	CString m_strInfo;
	sockaddr_in m_sockAddr;
	IPHEADER *		m_pIp;
private:
	CDialog* m_pWnd;              //ָ�������ڵ�ָ��
	char* icmpData;                 //ָ���ͱ����ڴ�ռ��ָ��
	char* icmpRcvBuf;              //ָ���Ľ��ջ���ռ��ָ��
	int m_nSeq;                    //�������к�
	SOCKET m_hSocket;            //�׽��־��
	SOCKADDR_IN m_addrDest;     //Ŀ��������ַ
	SOCKADDR_IN m_addrFrom;     //���·�ɵ�ַ
	USHORT CheckSum(char*,int);
	BOOL FillAddress(char *);
	void FillICMPData(char*,int);
    BOOL SetTTL(SOCKET,int);
	BOOL SendData(char*,int);
	BOOL RecvData(char*,int*);
	BOOL DecodeICMP(char*,int,int);
};

#endif // !defined(AFX_TRACER_H__FA3E73EF_D951_4145_B740_AD9D88EA4E86__INCLUDED_)
