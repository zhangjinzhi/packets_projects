#pragma once
#include "afxcmn.h"

#include <pcap.h>
#include <string>
using namespace std;

// CARPAttackerCheatDlg dialog

class CARPAttackerCheatDlg : public CDialog
{
	DECLARE_DYNAMIC(CARPAttackerCheatDlg)

public:
	CARPAttackerCheatDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CARPAttackerCheatDlg();

// Dialog Data
	enum { IDD = IDD_DIALOG2 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	int m_interval;
	CIPAddressCtrl m_GateIP;
	unsigned long long m_localIp;
	unsigned char* m_localMac;
	string m_SelDeviceName;
	CString m_targetIP,m_targetMac;

	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();

	int m_mode;
};
