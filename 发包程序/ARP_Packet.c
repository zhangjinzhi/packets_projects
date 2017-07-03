// DLC Header
typedef struct tagDLCHeader                    
{
   unsigned char      DesMAC[6];             /* destination HW addrress */
   unsigned char      SrcMAC[6];             /* source HW addresss */
   unsigned short     Ethertype;                /* ethernet type */
} DLCHEADER, *PDLCHEADER;
// ARP Frame
typedef struct tagARPFrame                     
{
          unsigned short         HW_Type;           /* hardware address */
          unsigned short         Prot_Type;             /* protocol address */
          unsigned char      HW_Addr_Len;       /* length of hardware address */
          unsigned char      Prot_Addr_Len;         /* length of protocol address */
          unsigned short         Opcode;                /* ARP/RARP */
 
          unsigned char      Send_HW_Addr[6];     /* sender hardware address */
          unsigned long      Send_Prot_Addr;      /* sender protocol address */
          unsigned char      Targ_HW_Addr[6];     /* target hardware address */
          unsigned long      Targ_Prot_Addr;      /* target protocol address */
          unsigned char      padding[18];
} ARPFRAME, *PARPFRAME;
// ARP Packet = DLC header + ARP Frame
typedef struct tagARPPacket                
{
     DLCHEADER     dlcHeader;
     ARPFRAME      arpFrame;
} ARPPACKET, *PARPPACKET;


/****************************************************************************
* Name & Params::
*     formatMACToStr
*     (
*       LPSTR lpHWAddrStr :    要显示到list上的字符串
*       unsigned char *HWAddr :  传入的MAC字符串
*     )
* Purpose:
*     将用户输入的MAC地址字符转成相应格式
****************************************************************************/
void CSysInfo::formatMACToStr(LPSTR lpHWAddrStr,const unsigned char *HWAddr)
{
  int i;
  short temp;
  char szStr[3];

  strcpy(lpHWAddrStr, "");
  for (i=0; i<6; ++i)
  {
    temp = (short)(*(HWAddr + i));
    _itoa(temp, szStr, 16);
    if (strlen(szStr) == 1) strcat(lpHWAddrStr, "0");
    strcat(lpHWAddrStr, szStr);
    if (i<5)  strcat(lpHWAddrStr, "-");         // 加上 - 
  }
}

//
//
//填充数据包
//
//
/****************************************************************************
 *   Name & Params::
 *             formatStrToMAC
 *             (
 *                 const LPSTR lpHWAddrStr : 用户输入的MAC地址字符串
 *                 unsigned char *HWAddr :   返回的MAC地址字符串(赋给数据包结构体)
 *             )
 *   Purpose:
 *             将用户输入的MAC地址字符转成数据包结构体需要的格式
 ****************************************************************************/
void formatStrToMAC(const LPSTR lpHWAddrStr, unsigned char *HWAddr)
{
       unsigned int i, index = 0, value, temp;
      unsigned char c;
 
      _strlwr(lpHWAddrStr);                                                   // 转换成小写
 
      for (i = 0; i < strlen(lpHWAddrStr); i++)
     {
           c = *(lpHWAddrStr + i);
            if (( c>='0' && c<='9' ) || ( c>='a' && c<='f' ))
           {
               if (c>='0' && c<='9')  temp = c - '0';                         // 数字
               if (c>='a' && c<='f')  temp = c - 'a' + 0xa;               // 字母
               if ( (index % 2) == 1 )
              {
                   value = value*0x10 + temp;
                   HWAddr[index/2] = value;
              }
              else value = temp;
              index++;
         }
               if (index == 12) break;
        }
}
 
// 开始填充各个字段
    ARPPACKET ARPPacket;                                                  // 定义ARPPACKET结构体变量
 
    memset(&ARPPacket, 0, sizeof(ARPPACKET));                      // 数据包初始化
 
     formatStrToMAC(“DLC源MAC字符串”,ARPPacket.dlcHeader.SrcMAC);       // DLC帧头
     formatStrToMAC(“DLC目的MAC字符串”,ARPPacket.dlcHeader.DesMAC);
 
     formatStrToMAC(“ARP源MAC字符串”,ARPPacket.arpFrame.Send_HW_Addr);  // 源MAC
     ARPPacket.arpFrame.Send_Prot_Addr = inet_addr(srcIP);              // 源IP
     formatStrToMAC(“ARP目的MAC字符串”,ARPPacket.arpFrame.Targ_HW_Addr); // 目的MAC
     ARPPacket.arpFrame.Targ_Prot_Addr = inet_addr(desIP);               // 目的IP
    
     ARPPacket.arpFrame.Opcode = htons((unsigned short)arpType);        // arp包类型
    
     // 自动填充的常量
     ARPPacket.dlcHeader.Ethertype = htons((unsigned short)0x0806); // DLC Header的以太网类型
     ARPPacket.arpFrame.HW_Type = htons((unsigned short)1);           // 硬件类型
     ARPPacket.arpFrame.Prot_Type = htons((unsigned short)0x0800);    // 上层协议类型
     ARPPacket.arpFrame.HW_Addr_Len = (unsigned char)6;                 // MAC地址长度
     ARPPacket.arpFrame.Prot_Addr_Len = (unsigned char)4;               // IP地址长度

void formatARPPacket(char* srcDLC,char* desDLC,char* srcMAC,char* srcIP,
                char* desMAC,char* desIP,int arpType)
{
  memset(&ARPPacket, 0, sizeof(ARPPACKET));                         // 数据包初始化为0

  formatStrToMAC(srcDLC,ARPPacket.dlcHeader.SrcMAC);       // DLC帧头
  formatStrToMAC(desDLC,ARPPacket.dlcHeader.DesMAC);

  formatStrToMAC(srcMAC,ARPPacket.arpFrame.Send_HW_Addr);  // 源地址
  ARPPacket.arpFrame.Send_Prot_Addr = inet_addr(srcIP);              
  formatStrToMAC(desMAC,ARPPacket.arpFrame.Targ_HW_Addr);  // 目的地址
  ARPPacket.arpFrame.Targ_Prot_Addr = inet_addr(desIP);
  
  ARPPacket.arpFrame.Opcode = htons((unsigned short)arpType);        // arp包类型
     
  // 自动填充常量
  ARPPacket.dlcHeader.Ethertype = htons((unsigned short)0x0806);     // DLC Header的以太网类型
  ARPPacket.arpFrame.HW_Type = htons((unsigned short)1);             // 硬件类型
  ARPPacket.arpFrame.Prot_Type = htons((unsigned short)0x0800);      // 上层协议类型
  ARPPacket.arpFrame.HW_Addr_Len = (unsigned char)6;                 // MAC地址长度
  ARPPacket.arpFrame.Prot_Addr_Len = (unsigned char)4;               // IP地址长度


}
//
//
//发送数据包
//
//
//
//
     /**********************************************************************
*    Name & Params::
*             SendARPPacket()
*    Purpose:
*             发送ARP数据包
*    Remarks:
*             用的是winpcap的api函数
***********************************************************************/
void SendARPPacket()
{
     char *AdapterDeviceName =GetCurAdapterName();     // 首先获得获得网卡名字
 
     lpAdapter = PacketOpenAdapter(AdapterDeviceName);     // 根据网卡名字打开网卡
 
     lpPacket = PacketAllocatePacket();               // 给PACKET结构指针分配内存
 
     PacketInitPacket(lpPacket, &ARPPacket, sizeof(ARPPacket)); //初始化PACKET结构指针
                                             // 其中的ARPPacket就是我们先前填充的ARP包
 
     PacketSetNumWrites(lpAdapter, 1);               // 每次只发送一个包
 
     PacketSendPacket(lpAdapter, lpPacket, true)       // Send !!!!! ^_^
 
     PacketFreePacket(lpPacket);                     // 释放资源
     PacketCloseAdapter(lpAdapter);
}

// 网卡信息
typedef struct tagAdapterInfo         
{
              char szDeviceName[128];           // 名字
              char szIPAddrStr[16];             // IP
              char szHWAddrStr[18];             // MAC
              DWORD dwIndex;                    // 编号         
}INFO_ADAPTER, *PINFO_ADAPTER;
 
/*********************************************************************
*    Name & Params::
*             AddAdapInfoToList
*             (
*                  CListCtrl& list :  CARPPlayerDlg传入的list句柄
*             )
*    Purpose:
*             获得系统的网卡信息，并将其添加到list控件中
*    Remarks:
*             获得网卡IP及MAC用到了IpHelper api GetAdaptersInfo
******************************************************************/
void AddAdapInfoToList(CListCtrl& list)
{
     char tempChar;
     ULONG uListSize=1;
     PIP_ADAPTER_INFO pAdapter;           // 定义PIP_ADAPTER_INFO结构存储网卡信息
     int nAdapterIndex = 0;
 
     DWORD dwRet = GetAdaptersInfo((PIP_ADAPTER_INFO)&tempChar, &uListSize);//关键函数
 
     if (dwRet == ERROR_BUFFER_OVERFLOW)
     {
  PIP_ADAPTER_INFO pAdapterListBuffer = (PIP_ADAPTER_INFO)new(char[uListSize]);
  dwRet = GetAdaptersInfo(pAdapterListBuffer, &uListSize);
  if (dwRet == ERROR_SUCCESS)
  {
     pAdapter = pAdapterListBuffer;
     while (pAdapter)                                              // 枚举网卡然后将相关条目添加到List中
     {
        // 网卡名字
          CString strTemp = pAdapter->AdapterName;                    
          strTemp = "//Device//NPF_" + strTemp;                        // 加上前缀
          list.InsertItem(nAdapterIndex,strTemp);                 
          strcpy(AdapterList[nAdapterIndex].szDeviceName,strTemp);
          // IP
          strcpy(AdapterList[nAdapterIndex].szIPAddrStr,
                                                 pAdapter->IpAddressList.IpAddress.String );
          list.SetItemText(nAdapterIndex,1,AdapterList[nAdapterIndex].szIPAddrStr);
          // MAC
          formatMACToStr( AdapterList[nAdapterIndex].szHWAddrStr, pAdapter->Address );
          list.SetItemText(nAdapterIndex,2,AdapterLis[nAdapterIndex].szHWAddrStr);
          // 网卡编号
          AdapterList[nAdapterIndex].dwIndex = pAdapter->Index;         
 
          pAdapter = pAdapter->Next;
          nAdapterIndex ++;
          }
     delete pAdapterListBuffer;
     }
}
}

// ARP条目信息
typedef struct tagARPInfo            
{
     char szIPAddrStr[16];              // IP
     char szHWAddrStr[18];             // MAC
     DWORD dwType;                     // 类型
}INFO_ARP, *PINFO_ARP;
 
 
/**********************************************************************
*    Name & Params::
*             AddARPInfoToList
*             (
*                  CListCtrl& list :             CARPPlayerDlg传入的list句柄
*                  const short nAdapterIndex :   用户选中的网卡编号
*             )
*    Purpose:
*             读入系统的ARP缓存列表,.并添加到对话框中
*    Remarks:
*             用到了IpHelper api GetIpNetTable
*             而且用到了WinSock的api，所以要包含<WinSock2.h>
*****************************************************************/
void AddARPInfoToList(CListCtrl& list,const short nAdapterIndex)
{
     char tempChar;
     DWORD dwListSize = 1;
     DWORD dwRet;
     in_addr inaddr;
     list.DeleteAllItems();
 
     dwRet = GetIpNetTable((PMIB_IPNETTABLE)&tempChar, &dwListSize, TRUE);  // 关键函数
     if (dwRet == ERROR_INSUFFICIENT_BUFFER)
     {
         PMIB_IPNETTABLE pIpNetTable = (PMIB_IPNETTABLE)new(char[dwListSize]);
         dwRet = GetIpNetTable(pIpNetTable, &dwListSize, TRUE);
         if (dwRet == ERROR_SUCCESS)
         {
              for (int i=0; i<(int)pIpNetTable->dwNumEntries; i++)
              {
                  // IP
                   inaddr.S_un.S_addr = pIpNetTable->table[i].dwAddr;
                   strcpy( ARPList[i].szIPAddrStr, inet_ntoa(inaddr) );  
                   // MAC
                   formatMACToStr( ARPList[i].szHWAddrStr, pIpNetTable->table[i].bPhysAddr );
                   // Type
                   ARPList[i].dwType = pIpNetTable->table[i].dwType;        
 
                   if (AdapterList[nAdapterIndex].dwIndex != pIpNetTable->table[i].dwIndex)                                                       continue;
 
                   list.InsertItem(i,ARPList[i].szIPAddrStr);
                   list.SetItemText(i,1,ARPList[i].szHWAddrStr);
                   switch(ARPList[i].dwType) {           // 根据type的值来转换成字符显示
                   case 3:
                       list.SetItemText(i,2,"Dynamic");
                       break;
                   case 4:
                       list.SetItemText(i,2,"Static");
                       break;
                   case 1:
                       list.SetItemText(i,2,"Invalid");
                   default:
                       list.SetItemText(i,2,"Other");
                   }
              }
         }
         delete pIpNetTable;
     }
}