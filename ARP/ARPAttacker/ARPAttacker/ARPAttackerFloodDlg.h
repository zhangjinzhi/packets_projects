#pragma once

#include <pcap.h>
#include <string>
using namespace std;

// CARPAttackerFloodDlg dialog

class CARPAttackerFloodDlg : public CDialog
{
	DECLARE_DYNAMIC(CARPAttackerFloodDlg)

public:
	CARPAttackerFloodDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CARPAttackerFloodDlg();

// Dialog Data
	enum { IDD = IDD_DIALOG1 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	int m_interval;
	unsigned long long m_localIp;
	unsigned char* m_localMac;
	string m_SelDeviceName;

	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedOk();
};
