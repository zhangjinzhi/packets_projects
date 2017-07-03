#include "sysinclude.h"
#include <string.h>
extern void rip_sendIpPkt(unsigned char* pData, UINT16 len, unsigned short dstPort, UINT8 iNo);/*RIP包的发送函数*/

extern struct stud_rip_route_node *g_rip_route_table;/*路由表*/

typedef struct _packet_header /*RIP数据包的头部*/
{
	unsigned char command;/*命令只能是REQUEST或者RESONSE*/
	unsigned char version;/*版本号，1或者2*/
	unsigned short pad0;/*置零*/
} packet_header;
typedef struct _packet_data/*RIP数据包*/
{
	unsigned short addrfamily;/*地址族，必须为2*/
	unsigned short routetag;/*路由标记*/
	unsigned int ipaddr;/*IP地址*/
	unsigned int netmask;/*掩码*/
	unsigned int nexthop;/*下一跳*/
	unsigned int metric;/*跳数*/
} packet_data;

//////////////////////////////////////////////////////////////////////////////上下这两种是等同的
struct rte
{
  u_int16_t family;		// Address family of this route. 
  u_int16_t tag;		// Route Tag which included in RIP2 packet. 
  struct in_addr prefix;	// Prefix of rip route. 
  struct in_addr mask;		// Netmask of rip route. 
  struct in_addr nexthop;	// Next hop of rip route. 
  u_int32_t metric;		// Metric value of rip route. 
};
//这个结构体保存rip报文的每个路由信息单元，按照rip协议规定的格式定义。


struct rip_packet
{
  unsigned char command;	// Command type of RIP packet. 
  unsigned char version;   //RIP version which coming from peer. 
  unsigned char pad1;		// Padding of RIP packet header. 
  unsigned char pad2;		// Same as above. 
  struct rte rte[1];		/ Address structure. 
};
//这个结构体是包含一个路由信息单元的rip报文，也可以把它当做rip报文的首部，因为没有路由信息单元的报文是非法的。

union rip_buf
{
  struct rip_packet rip_packet;
  char buf[RIP_PACKET_MAXSIZ];
};
//这个联合体表示一个rip报文，rip_packet表示报文头，buf作为后续的空间，在代码流程中，这个数据通常伴随有一个值来表示其长度。


#define DECLAREERROR(pkt,type) {printf("Discard because %d\n",type);ip_DiscardPkt(pkt,type);return 0;}/*定义RIP包出错时的返回类型*/

unsigned char buffer[256];/*缓冲区*/
void dumpPkt(unsigned char*buf,int len)/*实现数据提取功能*/
{
	printf("Dumping sending packets:\n");
	int l=0;
	for (int i=0;i<len;i++)
	{
		printf("%02x ",(unsigned int)buf[i]);
		l++;
		if (l++==15)/*l应该小于16*/
		{
			printf("\n");
			l=0;
		}
	}
	printf("\n");
}
void MakePacket(char version, UINT8 iNo)/*该函数实现组装RIP数据包*/
{
	stud_rip_route_node *pnow=g_rip_route_table;
	/*发送数据包时满足：1.端口必须不相同2.跳数必须小于16*/
	while (pnow&&(pnow->if_no==iNo||pnow->metric==16))
		pnow=pnow->next;
	/*遍历并复制路由链表*/
	do
	{
		/*组装RIP数据包的头部*/
		packet_header*ph=(packet_header*)buffer;
		ph->command=2; /*响应（RESPONSE）分组*/
		ph->version=version; /*版本号*/
		ph->pad0=0; /*必须为0*/
	/*组装数据包*/
		int pCount=0;
		while (pCount<25&&pnow)/*一个数据包最多能容纳25条记录*/
		{
			packet_data*pd=(packet_data*)(buffer+sizeof(packet_header));
			pd+=pCount;
			pd->addrfamily=htons(2); 
			pd->routetag=0; 
			pd->ipaddr=htonl(pnow->dest);
			if (version==2)
				pd->netmask=htonl(pnow->mask);
			else
				pd->netmask=0;
			if (version==2)
				pd->nexthop=htonl(pnow->nexthop);
			else
				pd->nexthop=0;
			pd->metric=htonl(pnow->metric);
			pCount++;

			do {
				pnow=pnow->next;
			} while (pnow&&(pnow->if_no==iNo||pnow->metric==16));
		}
		/*发送数据包*/
		dumpPkt(buffer,sizeof(packet_header)+sizeof(packet_data)*pCount);
		rip_sendIpPkt(buffer,sizeof(packet_header)+sizeof(packet_data)*pCount,520,iNo);
	} while (pnow);
}
#include <stdlib.h>
char*clone(char*org,int len)/*取出数据并删除缓冲区的原始数据*/
{
	char*t=(char*)malloc(len);
	memmove(t,org,len);
	return t;
}
int stud_rip_packet_recv(char*pBuffer, int bufferSize, UINT8 iNo, UINT32 srcAdd)
{
	pBuffer=clone(pBuffer,bufferSize);
	/*检查数据包头部是否合法，否则调用出错函数返回出错类型*/
	packet_header*ph=(packet_header*)pBuffer;
	if (ph->command!=1&&ph->command!=2) DECLAREERROR(pBuffer,STUD_RIP_TEST_COMMAND_ERROR);
	if (ph->version!=1&&ph->version!=2) DECLAREERROR(pBuffer,STUD_RIP_TEST_VERSION_ERROR);
	if (ph->pad0!=0) DECLAREERROR(pBuffer,STUD_RIP_TEST_COMMAND_ERROR);
	
	if (ph->command==1)/*为REQUEST包*/
	{
		printf("Get valid request\n");
		MakePacket(ph->version,iNo);
	}
	else/*为RESPONSE包*/
	{
		dumpPkt((unsigned char*)pBuffer,bufferSize);/*从缓冲区取出数据组包*/
		int snums=(bufferSize-sizeof(packet_header))/sizeof(packet_data);/*计算缓冲区RIP包的总数*/
		for (int i=0;i<snums;i++)
		{
			packet_data*pd=(packet_data*)(pBuffer+sizeof(packet_header));/*从缓冲区dump数据形成本地路由表的链表*/
			pd+=i;
			dumpPkt((unsigned char*)pd,sizeof(packet_data));
			pd->ipaddr=ntohl(pd->ipaddr);
			pd->netmask=ntohl(pd->netmask);
			pd->nexthop=ntohl(pd->nexthop);
			pd->metric=ntohl(pd->metric);
			/*给RIP链表里的每一项赋值*/
			stud_rip_route_node*hd=g_rip_route_table;
			dumpPkt((unsigned char*)pd,sizeof(packet_data));
			int hdcount=0;
			while (hd) {
				if (hd->dest==pd->ipaddr&&hd->mask==pd->netmask) break;							hd=hd->next;
				hdcount++;
			}
			do/*对传来的RIP数据进行分析，更新本地路由表*/
			{
				if (hd) {
				/*如果下一跳不是原来表中的下一跳，只有当跳数更低时，更新表项*/
					printf("Match at %d and nexthop %x\n",hdcount,hd->nexthop);
					if (hd->nexthop!=pd->nexthop)
					{
						if (hd->metric>pd->metric)
						{
							hd->metric=pd->metric+1;/*跳数加一*/
							hd->nexthop=pd->nexthop;/*目的地更新*/
							hd->if_no=iNo;
						}
						break;
					}
					/*如果下一跳满足，直接更新RIP链表*/
					hd->metric=pd->metric+1;
					hd->nexthop=pd->nexthop;
					hd->if_no=iNo;
					/*如果跳数为16显然不合法，大于16的置为16*/
					if (hd->metric>16)
						hd->metric=16;
				}
				else {
					/*如果不存在则创建新节点（链表）*/
					printf("Unmatched.\n");
					if (pd->metric>=16) break;/*跳过跳数为16的项目*/
					stud_rip_route_node* nhd=(stud_rip_route_node*)malloc(sizeof(stud_rip_route_node));/*创建新节点*/
					nhd->dest=pd->ipaddr;
					nhd->mask=pd->netmask;
					nhd->nexthop=pd->nexthop;
					nhd->metric=pd->metric+1;/*初始值为1*/
					nhd->if_no=iNo;
					nhd->next=g_rip_route_table;/*插入路由链表的头部*/
					g_rip_route_table=nhd;
				}
			} while (false);
		}
	}
}
/*超时处理函数*/
void stud_rip_route_timeout(UINT32 destAdd, UINT32 mask, unsigned char msgType)
{
	if (msgType==RIP_MSG_SEND_ROUTE)
	{
		/*向两个端口都广播自己的路由表*/
		MakePacket(2,1);
		MakePacket(2,2);
	}
	else if (msgType==RIP_MSG_DELE_ROUTE)
	{
		stud_rip_route_node*hd=g_rip_route_table;
		while (hd) {
			if (hd->dest==destAdd&&hd->mask==mask)
				break;
			hd=hd->next;/*传入超时的路由表项，将跳数置为16，此该表项会被自动删除*/
		}
		hd->metric=16;
	}
}
