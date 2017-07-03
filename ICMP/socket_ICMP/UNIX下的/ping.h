//
// Ping.h
//

#pragma pack(1)

#define ICMP_ECHOREPLY	0
#define ICMP_ECHOREQ	8
#define REQ_DATASIZE 32	
//typedef  unsigned char u_char;
//typedef  unsigned short u_short;
// IP Header -- RFC 791
typedef struct tagIPHDR		//IP��ͷ
{
	u_char  VIHL;			// Version and IHL
	u_char	TOS;			// Type Of Service
	u_short	TotLen;			// Total Length
	u_short	ID;				// Identification
	u_short	FlagOff;		// Flags and Fragment Offset
	u_char	TTL;			// Time To Live
	u_char	Protocol;		// Protocol
	u_short	Checksum;		// Checksum
	unsigned int iaSrc;	// Internet Address - Source
	unsigned int iaDst;	// Internet Address - Destination
}IPHDR, *PIPHDR;

// ICMP Header - RFC 792
typedef struct tagICMPHDR	//ICMP��ͷ
{
	u_char	Type;			// Type
	u_char	Code;			// Code
	u_short	Checksum;		// Checksum
	u_short	ID;				// Identification
	u_short	Seq;			// Sequence
}ICMPHDR, *PICMPHDR;
// ICMP Echo Reply


typedef struct tagICMPPACK		//ICMP��ͷ+����
{
	ICMPHDR icmpHdr;
	char	Data[REQ_DATASIZE];	
}ICMPPACK,*PICMPPACK;

	// Echo Request Data size

// ICMP Echo Request
typedef struct tagECHOREQUEST		//�������ݸ�ʽ
{   IPHDR   iphdr;
	ICMPPACK icmpPack;
}ECHOREQUEST, *PECHOREQUEST;		

typedef struct tagRECHOREQUEST		//�ڶ���Ƭ�������ݸ�ʽ
	{   IPHDR   iphdr;
	    char	Data[REQ_DATASIZE/2];
}RECHOREQUEST, *PRECHOREQUEST;

typedef struct tagECHOREPLY			//����
{
	IPHDR	ipHdr;
	ICMPHDR icmpHdr;
	char    cFiller[256];		//IPͷ+ICMP������+�������
}ECHOREPLY, *PECHOREPLY;

#pragma pack()

