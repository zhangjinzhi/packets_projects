// ARPAttackerDlg.h : header file
//

#pragma once


#include "afxwin.h"

#define HAVE_REMOTE
#include <pcap.h>



// CARPAttackerDlg dialog
class CARPAttackerDlg : public CDialog
{
// Construction
public:
	CARPAttackerDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_ARPATTACKER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	void getLocalDev();
	afx_msg void OnBnClickedButtonscan();
	LRESULT CARPAttackerDlg::OnPacket(WPARAM wParam, LPARAM lParam);

	CListBox m_listLocalDev;
	CListCtrl m_listNeighbor;
	
	afx_msg void OnBnClickedButtonAttackflood();
	afx_msg void OnBnClickedButtonAttackone();
};

