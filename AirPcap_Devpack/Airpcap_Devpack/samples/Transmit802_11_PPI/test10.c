/*
 * Copyright (c) 2006-2008 CACE Technologies, Davis (California)
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
 *
 *===========================================================================
 *
 * This example shows how to use airpcap and libpcap at the same time to 
 * transmit raw 802.11 frames.
 * The program transmits packets in two different ways:
 *   - raw 802.11: in this case, the packets will be transmitted at 1mbps
 *   - PPI: in this case, the program specifies the Tx rate, using the
 *          PPI header.
 *
 * The program needs files from both the airpcap and WinPcap developer's pack,
 * and ASSUMES THAT THE TWO DEVELOPER'S PACKS ARE UNPACKED IN THE SAME FOLDER.
 * You can get the WinPcap developer's pack from http://www.winpcap.org.
 * You can get the airpcap developer's pack from http://www.cacetech.com.
 *
 *===========================================================================
 */

//
// Program parameters
//
#define TX_PACKET_LEN 100 			// The length of the packet to be transmitted
#define N_TX_REPETITIONS 10			// Number of times each packet is transmitted

//
// The Tx frequencies we're going to send packets at
//
double TestTxRatesToTest [] =
{
	1, 
	2, 
	5.5, 
	11, 
	6, 
	9, 
	12,
	18,
	24,
	36,
	48,
	54
};


#define _CRT_SECURE_NO_DEPRECATE
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <airpcap.h>

//
// Stripped-down PPI header that will be prepended to the transmitted frames
//
#ifndef __MINGW32__
#pragma pack(push)
#pragma pack(1)
#endif // __MINGW32__
typedef struct _PPI_PACKET_HEADER
{
	UCHAR		PphVersion;
	UCHAR		PphFlags;
	USHORT		PphLength;
	ULONG		PphDlt;
	USHORT		PfhType;
	USHORT		PfhLength;
	ULONGLONG	TsfTimer;
	USHORT		Flags;
	USHORT		Rate;
	USHORT		ChannelFrequency;
	USHORT		ChannelFlags;
	UCHAR		FhssHopset;
	UCHAR		FhssPattern;
	CHAR		DbmAntSignal;
	CHAR		DbmAntNoise;
}
#ifdef __MINGW32__
__attribute__((__packed__))
#endif // __MINGW32__
PPI_PACKET_HEADER, *PPPI_PACKET_HEADER;
#ifndef __MINGW32__
#pragma pack(pop)
#endif // __MINGW32__

#define PPI_PFHTYPE_80211COMMON 2
#define PPI_PFHTYPE_80211COMMON_SIZE 20

//
// The buffer with the packet we're going to send
//
u_int8_t TxPacket[TX_PACKET_LEN + sizeof(PPI_PACKET_HEADER)];

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

int main()
{
	pcap_t *winpcap_adapter;
	u_int32_t inum, i, j;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int32_t freq_chan;
	PAirpcapHandle airpcap_handle;
	pcap_if_t *alldevs, *d;
	PPI_PACKET_HEADER *radio_header;
	u_int32_t tchannel = 1;
	AirpcapChannelInfo tchaninfo;

	//
	// Get the device list
	//
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}

	//
	// Make sure that the device list is valid
	//
	if(alldevs == NULL)
	{
		printf("No interfaces found! Make sure the winpcap software is installed and your adapter is properly plugged in.\n");
		return -1;
	}
	
	//
	// Print the list and ask for a selection
	//
	for(d = alldevs, i = 0; d; d=d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);
		
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	// 
	// Check if the user specified a valid adapter
	//
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//
	// Jump to the selected adapter
	//
	for(d = alldevs, i = 0; i < inum-1 ;d = d->next, i++);
	
	//
	// Ask for a channel to listen to
	//
	printf("Enter the channel or frequency:",i);
	scanf("%d", &freq_chan);
	
	// 
	// Check if the user specified a valid channel
	//
	if(freq_chan < 1 || freq_chan > 8000)
	{
		printf("\nChannel or frequency out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//
	// Open the adapter with WinPcap
	//
	if((winpcap_adapter = pcap_open_live(d->name,			// name of the device
		65536,												// portion of the packet to capture. 
															// 65536 grants that the whole packet will be captured on all the MACs.
		1,													// promiscuous mode (nonzero means promiscuous)
		1000,												// read timeout, in ms
		errbuf												// error buffer
		)) == NULL)
	{
		printf("Error opening adapter with winpcap (%s)\n", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}

	//
	// We don't need the device list any more, free it
	//
	pcap_freealldevs(alldevs);

	//
	// Get the airpcap handle so we can change wireless-specific settings
	//
	airpcap_handle = (PAirpcapHandle)pcap_get_airpcap_handle(winpcap_adapter);

	if(airpcap_handle == NULL)
	{
		printf("This adapter doesn't have wireless extensions. Quitting\n");
		pcap_close(winpcap_adapter);
		return -1;
	}

	//
	// Configure the AirPcap adapter
	//

	// Set the channel.
	// If the user provides a value below 500, we assume it's a channel number, otherwise we assume it's a frequency.
	if(freq_chan < 500)
	{
		if(!AirpcapSetDeviceChannel(airpcap_handle, freq_chan))
		{
			printf("Error setting the channel: %s\n", AirpcapGetLastError(airpcap_handle));
			pcap_close(winpcap_adapter);
			return -1;
		}
	}
	else
	{
		memset(&tchaninfo, 0, sizeof(tchaninfo));
		tchaninfo.Frequency = freq_chan;

		if(!AirpcapSetDeviceChannelEx(airpcap_handle, tchaninfo))
		{
			printf("Error setting the channel: %s\n", AirpcapGetLastError(airpcap_handle));
			pcap_close(winpcap_adapter);
			return -1;
		}
	}


	////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////
	// First, we transmit the packet without PPI information.
	// Not using the PPI header makes packet crafting process simpler, because we just
	// but we don't provide the packet data in a buffer. However, we don't have
	// control on the tx rate: the packets will always go out at 1 Mbps.
	////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////

	//
	// Set the link layer to bare 802.11
	//
	if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11))
	{
		printf("Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle));
		pcap_close(winpcap_adapter);
		return -1;
	}

	//
	// Initialize the Tx packet with an increasing value
	//
	for(i = 0; i < TX_PACKET_LEN; i++)
	{
		TxPacket[i] = i & 0xff;
	}

	//
	// Now transmit the packet the specified number of times
	//
	for(i = 0; i < N_TX_REPETITIONS; i++)
	{
		if(pcap_sendpacket(winpcap_adapter, TxPacket, (TX_PACKET_LEN)) != 0)
		{
			printf("Error sending the packet: %s\n", pcap_geterr(winpcap_adapter));
			pcap_close(winpcap_adapter);
			return -1;
		}
	}

	//
	// Notify the user that all went well
	//
	printf("Successfully sent the raw 802.11 packet %u times.\n", N_TX_REPETITIONS);

	////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////
	// Second, we transmit the packet with PPI information.
	// This allows us to specify the tx rate. We repeat the transmission for all the 
	// rates specified in the TestTxRatesToTest array
	////////////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////

	for(j = 0; j < sizeof(TestTxRatesToTest) / sizeof(TestTxRatesToTest[0]); j++)
	{
		//
		// Set the link layer to 802.11 + PPI
		//
		if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_PPI))
		{
			printf("Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle));
			pcap_close(winpcap_adapter);
			return -1;
		}

		//
		// Create the PPI header
		//
		radio_header = (PPI_PACKET_HEADER*)TxPacket;
		radio_header->PphDlt = 105;								// 802.11
		radio_header->PphLength = sizeof(PPI_PACKET_HEADER);	// header len: 32 bytes
		radio_header->PfhType = PPI_PFHTYPE_80211COMMON;		// Common header is the first header
		radio_header->PfhLength = PPI_PFHTYPE_80211COMMON_SIZE;	// Common header size is 20
		radio_header->Rate = (UCHAR)(TestTxRatesToTest[j] * 2);	// Frame rate
		radio_header->DbmAntSignal = 0;							// Currently not supported

		//
		// Initialize the Tx packet buffer with the transmission rate.
		//
		for(i = sizeof(PPI_PACKET_HEADER); i < TX_PACKET_LEN + sizeof(PPI_PACKET_HEADER); i++)
		{
			TxPacket[i] = (UCHAR)TestTxRatesToTest[j];
		}

		//
		// Now transmit the packet the specified number of times
		//
		for(i = 0; i < N_TX_REPETITIONS; i++)
		{
			if(pcap_sendpacket(winpcap_adapter, 
				TxPacket, 
				TX_PACKET_LEN + sizeof(PPI_PACKET_HEADER)) != 0)
			{
				printf("Error sending the packet: %s\n", pcap_geterr(winpcap_adapter));
				pcap_close(winpcap_adapter);
				return -1;
			}
		}

		//
		// Notify the user that all went well
		//
		printf("Successfully sent the PPI 802.11 packet %u times at %u Mbps.\n", N_TX_REPETITIONS, (u_int32_t)TestTxRatesToTest[j]);

	}

	//
	// Close the libpcap handler. Note that We don't need to close the AirPcap handler, because 
	// pcap_close takes care of it.
	//
	pcap_close(winpcap_adapter);
	return 0;
}
