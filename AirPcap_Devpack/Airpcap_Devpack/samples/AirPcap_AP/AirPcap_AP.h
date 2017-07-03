/*
 * Copyright (c) 2007 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name CACE Technologies nor the names of its contributors 
 * may be used to endorse or promote products derived from this software 
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *===========================================================================*
 */

#ifndef AIRPCAP_AP_H
#define AIRPCAP_AP_H

#define _CRT_SECURE_NO_DEPRECATE
#include <windows.h>
#include <airpcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <conio.h>
#include <process.h>


#define PACKET_BUFFER_SIZE 256000		// Size of the user-level packet buffer
#define WAIT_INTERVAL_MS 1

typedef unsigned int		u_int32;
typedef int					int32;
typedef unsigned short		u_int16;
typedef short				int16;
typedef unsigned char		u_int8;
typedef signed char			int8;
typedef unsigned __int64	u_int64;
typedef signed __int64		int64;

#pragma pack(push, 1)

typedef struct _ppi_packet_header
{
	UCHAR	PphVersion;
	UCHAR	PphFlags;
	USHORT	PphLength;
	ULONG	PphDlt;
}ppi_packet_header, *p_ppi_packet_header;

C_ASSERT(sizeof(ppi_packet_header)== 8);

typedef struct _ppi_fieldheader {
	u_int16 pfh_type;		/* Type */
	u_int16 pfh_datalen;	/* Length of data */
} ppi_fieldheader, *p_ppi_fieldheader;

C_ASSERT(sizeof(ppi_fieldheader)== 4);

typedef struct _ppi_80211_common_header {
	u_int64 tsft;
	u_int16 flags;
	u_int16 rate;
	u_int16 frequency;
	u_int16 channel_type;
	u_int8  fhss_hopset;
	u_int8  fhss_pattern;
	int8	signal;
	int8	noise;
} ppi_80211_common_header, *p_ppi_80211_common_header;

C_ASSERT(sizeof(ppi_80211_common_header)== 20);

//
// Structure of a 48-bit Ethernet address.
//
typedef struct	_ether_addr {
	u_int8 octet[6];
}ether_addr, *p_ether_addr;

C_ASSERT(sizeof(ether_addr)== 6);

typedef struct _probe_header {
	u_int16 frame_control;
	u_int16 duration;
	ether_addr dst_eth;
	ether_addr src_eth;
	ether_addr bss_eth;
	u_int16 fragment : 4;
	u_int16 seq_num : 12;
}probe_header, *p_probe_header;

C_ASSERT(sizeof(probe_header)== 24);

#pragma pack(pop, 1)

void waitForExit(void*);
void makePackets(char* name, u_int8 channel);
void listenForProbeRequest(PAirpcapHandle Ad);
void sendProbeResponse(PAirpcapHandle Ad, p_ppi_packet_header p_ppi);
boolean getProbeRequest(PAirpcapHandle Ad, BYTE *PacketBuffer, ULONG BufferSize, p_ppi_packet_header *p_ppi);
void exitApp(int exitCode);
PAirpcapHandle getAirPcapAdapter();
void sendBeacon(PAirpcapHandle Ad);

//
// Adapter Information Functions
//
boolean isTxAdapter(PCHAR Name);
boolean isTxFrequencySupported(PCHAR name, UINT frequency);
boolean printTxFrequenciesByName(PCHAR name);
PCHAR getPrintableFrequency(UINT frequency);
boolean convertFrequencyToChannel(UINT frequency, PUINT tmpChannel);
boolean getTxFrequenciesByName(PCHAR name, PUINT *frequencyList, PUINT numFrequencies);
boolean getTxFrequenciesByHandle(PAirpcapHandle Ad, PUINT *frequencyList, PUINT numFrequencies);
UINT uint_compare(const void *a, const void *b);

#endif //AIRPCAP_AP_H