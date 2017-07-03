// TraceRouteDlg.h : header file
//

#if !defined(AFX_TRACEROUTEDLG_H__CB641E57_FB69_4D97_BE55_41223F1764BC__INCLUDED_)
#define AFX_TRACEROUTEDLG_H__CB641E57_FB69_4D97_BE55_41223F1764BC__INCLUDED_
#include "Tracer.h"
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CTraceRouteDlg dialog

class CTraceRouteDlg : public CDialog
{
// Construction
public:
	CTraceRouteDlg(CWnd* pParent = NULL);	// standard constructor
	void InfoAdd(CString);

// Dialog Data
	//{{AFX_DATA(CTraceRouteDlg)
	enum { IDD = IDD_TRACEROUTE_DIALOG };
	CString	m_strResult;
	CString	m_strAddress;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CTraceRouteDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CTraceRouteDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnButtonTrace();
	afx_msg void OnButton2();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	CTracer* pTrc;
public:
	afx_msg void OnEnChangeEditAddress();
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_TRACEROUTEDLG_H__CB641E57_FB69_4D97_BE55_41223F1764BC__INCLUDED_)
