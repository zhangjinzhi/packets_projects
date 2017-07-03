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
 *
 * This program is a reference of how to use the airpcap API to receive 
 * 802.11 packets PPI-encoded radio information.
 * Note that the suggested method to receive packets is using WinPcap, as shown
 * in the "airpcap_and_libpcap" sample program.
 * After opening the adapter specified by the user, this program sets it to
 * receive 802.11 packets with radio information (PPI header), and then loops 
 * capturing packets, interpreting them, and printing them to the console.
 *
 *===========================================================================
 */

#define PACKET_BUFFER_SIZE 256000		// Size of the user-level packet buffer
#define WAIT_INTERVAL_MS 1000 

#define _CRT_SECURE_NO_DEPRECATE
#include <windows.h>
#include <stdio.h>
#include <airpcap.h>

void PrintPackets(BYTE *PacketBuffer, ULONG BufferSize);
void PrintFrameData(BYTE *Payload, UINT PayloadLen);
ULONG PpiPrint(const u_char *p, ULONG caplen);

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
int main()
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	INT i, Inum;
	AirpcapDeviceDescription *AllDevs, *TmpDev;
	BYTE* PacketBuffer;
	UINT BytesReceived;
	HANDLE ReadEvent;

	//
	// Get the device list
	//
	if(!AirpcapGetDeviceList(&AllDevs, Ebuf))
	{
		printf("Unable to retrieve the device list: %s\n", Ebuf);
		return -1;
	}

	//
	// Make sure that the device list is valid
	//
	if(AllDevs == NULL)
	{
		printf("No interfaces found! Make sure the airpcap software is installed and your adapter is properly plugged in.\n");
		return -1;
	}

	//
	// Print the list
	//
	for(TmpDev = AllDevs, i = 0; TmpDev; TmpDev = TmpDev->next)
	{
		printf("%d. %s", ++i, TmpDev->Name);
		if(TmpDev->Description)
		{
			printf(" (%s)\n", TmpDev->Description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}

	//
	// Ask the user to select an adapter
	//
	if(i == 0)
	{
		printf("\nNo interfaces found! Make sure the airpcap software is installed and your adapter is properly plugged in.\n");
		AirpcapFreeDeviceList(AllDevs);
		return -1;
	}
	
	printf("Enter the adapter number (1-%d):",i);
	scanf("%d", &Inum);
	
	// 
	// Check if the user specified a valid adapter
	//
	if(Inum < 1 || Inum > i)
	{
		printf("\nAdapter number out of range.\n");
		AirpcapFreeDeviceList(AllDevs);
		return -1;
	}

	//
	// Jump to the selected adapter
	//
	for(TmpDev = AllDevs, i = 0; i < Inum-1 ;TmpDev = TmpDev->next, i++);

	//
	// Open the adapter
	//
	Ad = AirpcapOpen(TmpDev->Name, Ebuf);
	if(!Ad)
	{
		printf("Error opening the adapter: %s\n", Ebuf);
		return -1;
	}

	//
	// We don't need the device list any more, free it
	//
	AirpcapFreeDeviceList(AllDevs);

	//
	// Set the link layer to 802.11 plus ppi headers
	//
	if(!AirpcapSetLinkType(Ad, AIRPCAP_LT_802_11_PLUS_PPI))
	{
		printf("Error setting the link layer: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		return -1;
	}

	//
	// Get the read event
	//
	if(!AirpcapGetReadEvent(Ad, &ReadEvent))
	{
		printf("Error getting the read event: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		return -1;
	}

	//
	// Allocate a 256k packet buffer
	//
	PacketBuffer = (BYTE*)malloc(PACKET_BUFFER_SIZE);
	if(!PacketBuffer)
	{
		printf("No memory for the packet buffer\n");
		AirpcapClose(Ad);
		return -1;
	}

	//
	// Everything is ok! 
	// Loop forever printing the packets
	//
	while(TRUE)
	{
	    // capture the packets
		if(!AirpcapRead(Ad, 
			PacketBuffer, 
			PACKET_BUFFER_SIZE, 
			&BytesReceived))
		{
			printf("Error receiving packets: %s\n", AirpcapGetLastError(Ad));
			free(PacketBuffer);
			AirpcapClose(Ad);
			return -1;
		}

		// parse the buffer and print the packets
		PrintPackets(PacketBuffer, BytesReceived);

		// wait until some packets are available. This prevents polling and keeps the CPU low. 
		WaitForSingleObject(ReadEvent, WAIT_INTERVAL_MS);
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////
// This function parses a buffer received from the driver and prints the
// contained packets.
///////////////////////////////////////////////////////////////////////
void PrintPackets(BYTE *PacketBuffer, ULONG BufferSize)
{
	BYTE *Buf;
	UINT Off = 0;
	u_int TLen, TLen1;
	PAirpcapBpfHeader Hdr;
	char *pChar;
	ULONG PpiHdrLen;

	Buf = PacketBuffer;
	Off=0;
	
	while(Off < BufferSize)
	{
		Hdr = (PAirpcapBpfHeader)(Buf + Off);
		TLen1 = Hdr->Originallen;
		TLen = Hdr->Caplen;
		printf("Packet length - captured portion: %ld, %ld\n", TLen1, TLen);
		Off += Hdr->Hdrlen;
				
		pChar =(char*)(Buf + Off);
		Off = AIRPCAP_WORDALIGN(Off + TLen);

		PpiHdrLen = PpiPrint(pChar, TLen);

		PrintFrameData(pChar + PpiHdrLen, TLen - PpiHdrLen);

		printf("\n");
	}
}

///////////////////////////////////////////////////////////////////////
// This function prints the content frame
///////////////////////////////////////////////////////////////////////
void PrintFrameData(BYTE *Payload, UINT PayloadLen)
{
	ULONG i, j, ulLines, ulen;
	BYTE *pLine, *Base;

	ulLines = (PayloadLen + 15) / 16;
	Base = Payload;

	printf("\n");

	for(i = 0; i < ulLines; i++)
	{
		
		pLine = Payload;
		
		printf("%08lx : ", (PCHAR)Payload - (PCHAR)Base );
		
		ulen = PayloadLen;
		ulen = ( ulen > 16 ) ? 16 : ulen;
		PayloadLen -= ulen;
		
		for(j=0; j<ulen; j++ )
			printf( "%02x ", *(BYTE *)Payload++ );
		
		if(ulen < 16 )
			printf( "%*s", (16-ulen)*3, " " );
		
		Payload = pLine;
		
		for(j = 0; j < ulen; j++, Payload++ )
		{
			printf("%c", isprint((unsigned char)*Payload) ? *Payload : '.' );
		}
		
		printf("\n");
	} 
}
