// ARPAttackerDlg.cpp : implementation file
//

#include "stdafx.h"
#include "ARPAttacker.h"
#include "ARPAttackerDlg.h"
#include "arpPacket.h"
#include "ARPAttackerFloodDlg.h"
#include "ARPAttackerCheatDlg.h"




#ifdef _DEBUG
#define new DEBUG_NEW
#endif

string strSelDeviceName = "";
unsigned char* bLocalMac;
unsigned long long bLocalIp;
pcap_if_t* pDevGlobalHandle = 0;
int nThreadSignal = 0;
int GetMacSignal = 0;
//unsigned char* BuildArpRequestPacket(unsigned char* source_mac, unsigned char* arp_sha, unsigned long chLocalIP, unsigned long arp_tpa, int PackSize);//封装ARP请求包
unsigned char* GetSelfMac(char* pDevName, unsigned long chLocalIP);
void SendArpRequest(pcap_if_t* pDev, unsigned char* bLocalMac);
UINT StartArpScan(LPVOID mainClass);//发送ARP请求数据包的线程函数
UINT WaitForArpRepeatPacket(LPVOID mainClass);//接收ARP响应的线程函数
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CARPAttackerDlg dialog




CARPAttackerDlg::CARPAttackerDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CARPAttackerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CARPAttackerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LOCALDEV, m_listLocalDev);
	DDX_Control(pDX, IDC_DEVLIST2, m_listNeighbor);

}

BEGIN_MESSAGE_MAP(CARPAttackerDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTONSCAN, &CARPAttackerDlg::OnBnClickedButtonscan)
	ON_MESSAGE(WM_PACKET, OnPacket)		//进行消息映射
	ON_BN_CLICKED(IDC_BUTTON_ATTACKFLOOD, &CARPAttackerDlg::OnBnClickedButtonAttackflood)
	ON_BN_CLICKED(IDC_BUTTON_ATTACKONE, &CARPAttackerDlg::OnBnClickedButtonAttackone)
END_MESSAGE_MAP()


// CARPAttackerDlg message handlers

BOOL CARPAttackerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.
	getLocalDev();
	m_listNeighbor.InsertColumn(0,"IP",0,200);
	m_listNeighbor.InsertColumn(1,"MAC",0,200);
	::SendMessage(m_listNeighbor.m_hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	GetDlgItem(IDC_BUTTON_ATTACKFLOOD)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_ATTACKONE)->EnableWindow(FALSE);

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CARPAttackerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CARPAttackerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CARPAttackerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CARPAttackerDlg::getLocalDev()
{
	int i = 0;
    string strDev = "";
    
    pcap_if_t* alldevs = 0; 
    pcap_if_t* pDev = 0;
    pcap_addr_t* pAdr = 0;
    char errbuf[PCAP_ERRBUF_SIZE+1]; 
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {// 获得设备列表
        AfxMessageBox(_T("找不到网卡设备"));// 若没有设备则弹出警告
        exit(1);
    } 
    for(pDev = alldevs; pDev; pDev = pDev->next)
    {// 遍历所有成员
        if (pDev->description)
        {
            strDev = char(i + 48);
            strDev += ". ";
            strDev += pDev->description;
            pAdr = pDev->addresses;//IP地址
            if (pAdr!=NULL)
            {        
                if (pAdr->addr->sa_family == AF_INET)
                {//pAdr->addr是否IP地址类型
                    strDev += " -> ";
                    strDev += IpToStr(((struct sockaddr_in *)pAdr->addr)->sin_addr.s_addr);
                    if(IpToStr(((struct sockaddr_in *)pAdr->addr)->sin_addr.s_addr)[0] != '0')
                    {
                        //m_Dev_No = i;
                        UpdateData(FALSE);//传递变量值去界面
                    }
                    strDev += " & [";
                    strDev += IpToStr(((struct sockaddr_in *)pAdr->netmask)->sin_addr.s_addr);//子网掩码
                    strDev += "]";
                    //GetDlgItem(IDC_GET_MAC)->EnableWindow(TRUE);//若网卡有IP地址，则使抓包按钮可用
                }
            }
			m_listLocalDev.InsertString(i++, strDev.c_str());
        }
    }
	m_listLocalDev.SetCurSel(0);
	UpdateData(FALSE);
    pcap_freealldevs(alldevs);//不再需要网络适配器列表, 释放


}

void CARPAttackerDlg::OnBnClickedButtonscan()
{
	// TODO: Add your control notification handler code here
	GetDlgItem(IDC_BUTTONSCAN)->EnableWindow(FALSE);								
	m_listNeighbor.DeleteAllItems();
	UpdateData(TRUE);															
	int nDevNo = m_listLocalDev.GetCurSel();											//此时取得操作对象序号
	int i = 0;
	int nDev = 0;
	unsigned long long chLocalIp = 0;														//存放本地ip地址
	pcap_if_t* alldevs = 0; 
	pcap_if_t* pDev = 0;
	pcap_addr_t* pAdr = 0;
	char errbuf[PCAP_ERRBUF_SIZE+1]; 
	pcap_findalldevs(&alldevs, errbuf);											// 获得设备列表 
	for(pDev = alldevs; pDev; pDev = pDev->next)
	{
		nDev++;							// 取得网卡总数
	}
	if ((nDevNo < 0) || (nDevNo > nDev))
	{
		MessageBox("您输入的序号越界!", "Get", MB_OK);
		pcap_freealldevs(alldevs);												// 释放设备列表
		GetDlgItem(IDC_BUTTONSCAN)->EnableWindow(TRUE);							//使按钮可再按并返回
		return;
	}
	for(pDev = alldevs, i = 0; i < nDevNo - 1; pDev = pDev->next, i++);			// 通过指针转到上步所选择的设备
	pAdr = pDev->addresses;
	if(!pAdr)
	{																	//若没有绑定IP地址，则退出
		MessageBox("该适配器没有绑定IP地址!", "Get.Note", MB_OK);
		pcap_freealldevs(alldevs);
		GetDlgItem(IDC_BUTTONSCAN)->EnableWindow(TRUE);							//使按钮可再按并返回
		return;
	}
	chLocalIp = ((struct sockaddr_in *)pAdr->addr)->sin_addr.s_addr;			//得到本地ip
	bLocalIp = chLocalIp;
	if(IpToStr(chLocalIp)[0] == '0')
	{
		MessageBox("请确定该适配器网线连接正常!", "Get.Note", MB_OK);
		pcap_freealldevs(alldevs);
		GetDlgItem(IDC_BUTTONSCAN)->EnableWindow(TRUE);							//使按钮可再按并返回
		return;
	}
	if (!GetMacSignal)
	{
		bLocalMac = GetSelfMac(pDev->name, chLocalIp);
	}
	if (!GetMacSignal)
	{
		MessageBox("请确定该适配器工作正常!", "Get.Note", MB_OK);
		pcap_freealldevs(alldevs);
		GetDlgItem(IDC_BUTTONSCAN)->EnableWindow(TRUE);							//使按钮可再按并返回
		return;
	}
	pDevGlobalHandle = pDev;
	strSelDeviceName = pDev->name;
	nThreadSignal = 1;
	//GetDlgItem(IDC_STOP_CAP)->EnableWindow(TRUE);

	AfxBeginThread(WaitForArpRepeatPacket, this);
	Sleep(100);																	//让守候线程有时间完成初始化：）20061025
	AfxBeginThread(StartArpScan, this);
	

}


//消息响应函数，处理捕获到的报文
LRESULT CARPAttackerDlg::OnPacket(WPARAM wParam, LPARAM lParam)
{
	string* ipDev = (string*)wParam;
	string* macDev = (string*)lParam;
	if (lParam == 1){
		GetDlgItem(IDC_STATIC_SCAN)->SetWindowTextA("开始扫描，请稍候");
	}
	if (lParam == 2){
		GetDlgItem(IDC_BUTTONSCAN)->EnableWindow(TRUE);
		GetDlgItem(IDC_BUTTON_ATTACKFLOOD)->EnableWindow(TRUE);
		GetDlgItem(IDC_BUTTON_ATTACKONE)->EnableWindow(TRUE);
		CString a;
		a.Format("扫描完成，本机mac地址%s",MacToStr(bLocalMac));
		GetDlgItem(IDC_STATIC_SCAN)->SetWindowTextA(a);
	}
	else{
		m_listNeighbor.InsertItem(m_listNeighbor.GetItemCount(),ipDev->c_str());
		m_listNeighbor.SetItemText(m_listNeighbor.GetItemCount()-1,1,macDev->c_str());
	}
		
	UpdateData(FALSE);
	return 0;
}




unsigned char* GetSelfMac(char* pDevName, unsigned long chLocalIP)
{		//获得自己的MAC
	pcap_t* pAdaptHandle;														//打开网卡适配器时用
	char errbuf[PCAP_ERRBUF_SIZE + 1]; 
	if((pAdaptHandle = pcap_open_live(pDevName, 60, 1, 100, errbuf)) == NULL)
	{	
		MessageBox(NULL, "无法打开适配器，可能与之不兼容!", "Note", MB_OK);
		return NULL;
	}
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	unsigned short arp_op;
	static unsigned char arp_sha[6];
	unsigned long arp_spa = 0;
	unsigned long arp_tpa = 0;
	unsigned char source_mac[6] = {0,0,0,0,0,0};
	unsigned char* arp_packet_for_self;
	arp_packet_for_self = BuildArpRequestPacket(source_mac, source_mac, SPECIAL, chLocalIP, 60);
	while(!GetMacSignal)
	{
		pcap_sendpacket(pAdaptHandle, arp_packet_for_self, 60);
		Sleep(10);										
		res = pcap_next_ex(pAdaptHandle, &header, &pkt_data);
		if(res == 0)
		{
			continue;
		}
		memcpy(&arp_op, pkt_data + 20, 2);
		memcpy(arp_sha, pkt_data + 22, 6);
		memcpy(&arp_spa, pkt_data + 28, 4);	
		memcpy(&arp_tpa, pkt_data + 38, 4);	
		if(arp_op == htons(ARP_REPLY) && arp_spa == chLocalIP && arp_tpa == SPECIAL)
		{	
			GetMacSignal = 1;
			pcap_close(pAdaptHandle);
			return arp_sha;
		}
		Sleep(100);																		//若不成功再等100ms再发，让网卡歇歇:) 20061025
	}
	pcap_close(pAdaptHandle);
	return arp_sha;
}

void SendArpRequest(pcap_if_t* pDev, unsigned char* bLocalMac)
{	//发送ARP请求
	pcap_addr_t* pAdr = 0;
	unsigned long long chLocalIp = 0;								//存放本地ip地址
	unsigned long long arp_tpa = 0;
	unsigned long long snd_tpa = 0;
	unsigned long long nlNetMask = 0;
	int netsize = 0;
	const char* pDevName = strSelDeviceName.c_str();
	pcap_t* pAdaptHandle;								//打开网卡适配器时用
	char errbuf[PCAP_ERRBUF_SIZE + 1]; 
	if((pAdaptHandle = pcap_open_live(pDev->name, 60, 0, 100, errbuf)) == NULL)
	{	
		MessageBox(NULL, "无法打开适配器，可能与之不兼容!", "Send", MB_OK);
		return;
	}
	unsigned char* arp_packet_for_req;
	arp_packet_for_req = BuildArpRequestPacket(bLocalMac, bLocalMac, chLocalIp, chLocalIp, 60);	
	unsigned long long ulOldMask=0;
	for (pAdr = pDev->addresses; pAdr; pAdr = pAdr->next)
	{
		if (!nThreadSignal)
		{
			break;
		}
		chLocalIp = ((struct sockaddr_in *)pAdr->addr)->sin_addr.s_addr;			//得到本地ip
		if (!chLocalIp) 
		{
			continue;
		}
		nlNetMask = ((struct sockaddr_in *)(pAdr->netmask))->sin_addr.S_un.S_addr;	//得到子网掩码
		if(ulOldMask==nlNetMask)
		{
			continue;
		}
		ulOldMask=nlNetMask;
		netsize = ~ntohl(nlNetMask);
		arp_tpa = ntohl(chLocalIp & nlNetMask);
	//	memcpy(arp_packet_for_req + 28, &chLocalIp, 4);								//将字串中源IP设为本次得到的本地IP
		for (int i=0; i < netsize; i++)
		{
			if (!nThreadSignal) 
			{
				break;
			}
			arp_tpa++;
			snd_tpa = htonl(arp_tpa);
			memcpy(arp_packet_for_req + 38, &snd_tpa, 4);							//目的IP在子网范围内按序增长	
			pcap_sendpacket(pAdaptHandle, arp_packet_for_req, 60);
			Sleep(5);
		}
	}
}

UINT StartArpScan(LPVOID mainClass)
{
	AfxGetApp()->m_pMainWnd->SendMessage(WM_PACKET, 0, 1);
	SendArpRequest(pDevGlobalHandle, bLocalMac);									//对选中设备的所有绑定的IP网段进行ARP请求
	AfxGetApp()->m_pMainWnd->SendMessage(WM_PACKET, 0, 2);
	return 0;
}

UINT WaitForArpRepeatPacket(LPVOID mainClass)
{								
	pcap_t* pAdaptHandle;														//打开网卡适配器时用
	const char* pDevName = strSelDeviceName.c_str();
	char errbuf[PCAP_ERRBUF_SIZE + 1]; 
	if((pAdaptHandle = pcap_open_live(pDevName, 60, 0, 100, errbuf)) == NULL)
	{	
		MessageBox(NULL, "无法打开适配器，可能与之不兼容!", "wait", MB_OK);
		return -1;
	}
	string ipDev,macDev;
	char* filter = "ether proto\\arp";
	bpf_program fcode;
	int res;
	unsigned short arp_op = 0;
	unsigned char arp_sha [6];
	unsigned long long arp_spa = 0;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	if (pcap_compile(pAdaptHandle, &fcode, filter, 1, (unsigned long)(0xFFFF0000)) < 0)
	{
		MessageBox(NULL,"过滤条件语法错误!", "wait", MB_OK);
		return -1;
	}
	//set the filter
	if (pcap_setfilter(pAdaptHandle, &fcode) < 0)
	{
		MessageBox(NULL,"适配器与过滤条件不兼容!", "wait", MB_OK);
		return -1;
	}
	while(1)
	{
		if (!nThreadSignal) 
		{
			break;
		}
		int i = 0;
		ipDev = "";
		macDev = "";
		res = pcap_next_ex(pAdaptHandle, &header, &pkt_data);
		if (!res)
		{
			continue;
		}
		memcpy(&arp_op, pkt_data + 20, 2);
		memcpy(arp_sha, pkt_data + 22, 6);
		memcpy(&arp_spa, pkt_data + 28, 4);
		ipDev += IpToStr(arp_spa);
		
		macDev += MacToStr(arp_sha);
		for (i = 6; i > 0; i--)
		{												
			if (arp_sha[i - 1] != bLocalMac[i - 1])
			{
				break;
			}
		}
		if(arp_op == htons(ARP_REPLY) && i)
		{
			AfxGetApp()->m_pMainWnd->SendMessage(WM_PACKET, WPARAM(&ipDev), LPARAM(&macDev));
		}
	}
	return 0;
}

void CARPAttackerDlg::OnBnClickedButtonAttackflood()
{
	// TODO: Add your control notification handler code here
	CARPAttackerFloodDlg dlg;
	dlg.m_localIp=bLocalIp;
	dlg.m_SelDeviceName=strSelDeviceName;
	dlg.m_localMac=bLocalMac;
	dlg.DoModal();
}

void CARPAttackerDlg::OnBnClickedButtonAttackone()
{
	// TODO: Add your control notification handler code here
	CString targetIP,targetMAC;
	int nId;
	POSITION pos=m_listNeighbor.GetFirstSelectedItemPosition();
	if(pos==NULL)
	{
		AfxMessageBox("请先选择一个攻击目标");
		return;
	}
	//得到行号，通过POSITION转化
	nId=(int)m_listNeighbor.GetNextSelectedItem(pos);
	targetIP=m_listNeighbor.GetItemText(nId,0);
	targetMAC=m_listNeighbor.GetItemText(nId,1);

	CARPAttackerCheatDlg dlg;
	dlg.m_localIp=bLocalIp;
	dlg.m_SelDeviceName=strSelDeviceName;
	dlg.m_localMac=bLocalMac;
	dlg.m_targetIP=targetIP;
	dlg.m_targetMac=targetMAC;
	dlg.DoModal();
}
