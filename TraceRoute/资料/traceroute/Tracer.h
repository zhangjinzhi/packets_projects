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


//必要的宏定义
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
    BYTE   i_type;               // 类型
    BYTE   i_code;               // 代码
    USHORT i_cksum;              // 首部校验和
    USHORT i_id;                 // 标识
    USHORT i_seq;                // 序列号
    ULONG timestamp;             // 时间戳(选用)
	unsigned int	time;		//时间
};
struct IPHEADER
{	unsigned int       h_len:4;          // 首部长度
	unsigned int       version:4;         // 版本
    unsigned char      tos;             // 服务类型
    unsigned short     total_len;         // 报文总长度
    unsigned short     ident;            // 标识
    unsigned short     frag_and_flags;   // 偏移量
    unsigned char      ttl;             // 寿命
    unsigned char      proto;          // 协议
    unsigned short     checksum;       // 首部校验和
    unsigned int       sourceIP;       // 源站IP
    unsigned int       destIP;         // 目的站IP
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
	CDialog* m_pWnd;              //指向主窗口的指针
	char* icmpData;                 //指向发送报文内存空间的指针
	char* icmpRcvBuf;              //指向报文接收缓冲空间的指针
	int m_nSeq;                    //报文序列号
	SOCKET m_hSocket;            //套接字句柄
	SOCKADDR_IN m_addrDest;     //目的主机地址
	SOCKADDR_IN m_addrFrom;     //存放路由地址
	USHORT CheckSum(char*,int);
	BOOL FillAddress(char *);
	void FillICMPData(char*,int);
    BOOL SetTTL(SOCKET,int);
	BOOL SendData(char*,int);
	BOOL RecvData(char*,int*);
	BOOL DecodeICMP(char*,int,int);
};

#endif // !defined(AFX_TRACER_H__FA3E73EF_D951_4145_B740_AD9D88EA4E86__INCLUDED_)
