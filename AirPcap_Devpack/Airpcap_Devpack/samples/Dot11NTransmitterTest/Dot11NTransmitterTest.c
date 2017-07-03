/*
 * Copyright (c) 2008 CACE Technologies, Davis (California)
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
 * This test sends packets with an AirPcap Nx adapter using the PPI
 * encapsulation and MCS rates. It also allows to send packets with A-MPDU
 * aggregation
 *
 *===========================================================================
 */

//
// Program parameters
//

#define _CRT_SECURE_NO_DEPRECATE
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <airpcap.h>
#include "PpiHeader.h"

#define MAX_PACKET_SIZE		4084

static ULONG g_CckRates[]=
{
	1000,
	2000,
	5500,
	11000
};

static ULONG g_OfdmRates[] = 
{
	6000,
	9000,
	12000,
	18000,
	24000,
	36000,
	48000,
	54000
};


//
// The Packet we're going to send
//
#define DEST_MAC_1	0x00
#define DEST_MAC_2	0x80
#define DEST_MAC_3	0x48
#define DEST_MAC_4	0x4a
#define DEST_MAC_5	0x93
#define DEST_MAC_6	0x67

u_int8_t g_PingPacket[] =
{
0x08, 0x02, 0x2c, 0x00, DEST_MAC_1, DEST_MAC_2, DEST_MAC_3, DEST_MAC_4, DEST_MAC_5, DEST_MAC_6, 
0x00, 0x13, 0x10, 0x6a, 0x29, 0x58, 0x00, 0x90, 0x4b, 0x45, 0x36, 0x62, 0x30, 0x47,
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3c, 0xaa, 0x5c, 0x00, 0x00,
0x80, 0x01, 0x74, 0xf6, 0xc0, 0xa8, 0x4d, 0x03, 0xc0, 0xa8, 0x4d, 0x1a, 0x08, 0x00, 0xc5, 0x59,
0x02, 0x00, 0x86, 0x02, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65,
0x66, 0x67, 0x68, 0x69, 0x7c, 0xf0, 0x3a, 0x0c, 0x73, 0xbb, 0x01, 0xd0              
};


//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

main()
{	
	pcap_t *winpcap_adapter;
	u_int32_t inum, i;
	LONG extChannel;
	char errbuf[PCAP_ERRBUF_SIZE];
	ULONG frequency;
	PAirpcapHandle airpcap_handle;
	pcap_if_t *alldevs, *d;
	CHAR pPacket[MAX_PACKET_SIZE + sizeof(AIRPCAP_PPI_N_HEADER)];
	AirpcapChannelInfo channelInfo;
	PAirpcapDeviceCapabilities pDevCaps;
	ULONG effectivePacketSize;
	ULONG maxAggr;
	PAIRPCAP_PPI_HEADER pHeader = (PAIRPCAP_PPI_HEADER)pPacket;
	ULONG j;
	ULONG aggr;
	UCHAR mcs, sgi, ht40;
	PAIRPCAP_PPI_N_HEADER pDot11NHeader = (PAIRPCAP_PPI_N_HEADER)pPacket;

	memset(pPacket, 0,  sizeof(pPacket));

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
	do
	{
		printf("Enter the channel frequency (2412 - 5825): ");
	}
	while(scanf("%u", &frequency) == 0 || frequency < 2412 || frequency > 5825);

	//
	// Ask which extension channel to use (used only for AirPcap Nx adapters)
	//
	do
	{
		printf("Enter the extension channel (+1 0 -1): ");
	}
	while(scanf("%d", &extChannel) == 0 || (extChannel != 0 && extChannel != -1 && extChannel != +1));
	
	do
	{
		printf("Effective packet size (4 - %u): ", MAX_PACKET_SIZE);
	}
	while(scanf("%u", &effectivePacketSize) == 0 || (effectivePacketSize < 4) || (effectivePacketSize > MAX_PACKET_SIZE));

	do
	{
		printf("Num aggregates in an A-MPDU (0-100, 0 means no aggregation): ");
	}
	while(scanf("%u", &maxAggr) == 0 || (maxAggr > 100));

	channelInfo.ExtChannel = (CHAR)extChannel;
	channelInfo.Flags = 0;
	channelInfo.Frequency = frequency;
	channelInfo.Reserved[0] = 0;
	channelInfo.Reserved[1] = 0;

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
	airpcap_handle = pcap_get_airpcap_handle(winpcap_adapter);

	if(airpcap_handle == NULL)
	{
		printf("This adapter doesn't have wireless extensions. Quitting\n");
		pcap_close(winpcap_adapter);
		return -1;
	}

	//
	// Configure the AirPcap adapter
	//
	if (!AirpcapGetDeviceCapabilities(airpcap_handle, &pDevCaps))
	{
		printf("Error getting the device capabilities: %s\n", AirpcapGetLastError(airpcap_handle));
		pcap_close(winpcap_adapter);
		return -1;
	}

	if (pDevCaps->CanTransmit == FALSE)
	{
		printf("This adapter does not support transmission!\n");
		pcap_close(winpcap_adapter);
		return -1;
	}

	//
	//Set the channel
	//
	if(!AirpcapSetDeviceChannelEx(airpcap_handle, channelInfo))
	{
		printf("Error setting the channel: %s\n", AirpcapGetLastError(airpcap_handle));
		pcap_close(winpcap_adapter);
		return -1;
	}

	if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_PPI))
	{
		printf("Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle));
		pcap_close(winpcap_adapter);
		return -1;
	}

	//
	// 802.11 frame
	// 
	memset(pHeader, 0, sizeof(*pHeader));

	//
	// forge the packet
	//
	AIRPCAP_PPI_HEADER_INIT(pHeader);

	//
	// This means that the PPI header encapsulates an 802.11 packet
	//
	pHeader->PacketHeader.PphDlt = 105;

	memcpy(pHeader + 1, g_PingPacket, sizeof(g_PingPacket));

	if (frequency < 3000)
	{
		//
		// cck, only supported on b/g frequencies
		//
		for (j = 0; j < sizeof(g_CckRates)/sizeof(g_CckRates[0]); j++)
		{
			printf("Transmitting CCK rate %u kbps\n", g_CckRates[j]);
			pHeader->Dot11CommonHeaderData.Rate = (USHORT)(g_CckRates[j] / 500);

			//
			// Now transmit the packet
			//
			if(pcap_sendpacket(winpcap_adapter, (const u_char*)pPacket, sizeof(*pHeader) + effectivePacketSize) != 0)
			{
				printf("Error sending the packet: %s\n", pcap_geterr(winpcap_adapter));
			}
		}
	}

	//
	// ofdm
	//
	for (j = 0; j < sizeof(g_OfdmRates)/sizeof(g_OfdmRates[0]); j++)
	{
		printf("Transmitting OFDM rate %u kbps\n", g_OfdmRates[j]);
		pHeader->Dot11CommonHeaderData.Rate = (USHORT)(g_OfdmRates[j] / 500);

		//
		// Now transmit the packet
		//
		if(pcap_sendpacket(winpcap_adapter, (const u_char*)pPacket, sizeof(*pHeader) + effectivePacketSize) != 0)
		{
			printf("Error sending the packet: %s\n", pcap_geterr(winpcap_adapter));
		}
	}

	if (pDevCaps->SupportedMedia & AIRPCAP_MEDIUM_802_11_N)
	{
		//
		// 802.11 N frame
		// 
		memset(pDot11NHeader, 0, sizeof(*pDot11NHeader));

		//
		// forge the packet
		//
		AIRPCAP_PPI_N_HEADER_INIT(pDot11NHeader);

		//
		// This means that the PPI header encapsulates an 802.11 packet
		//
		pDot11NHeader->PacketHeader.PphDlt = 105;

		memcpy(pDot11NHeader + 1, g_PingPacket, sizeof(g_PingPacket));

		for (sgi = 0; sgi <= 1; sgi ++)
		{
			if (sgi == 0)
			{
				pDot11NHeader->Dot11nMacPhyExtensionData.Flags &= ~PPI_FLD_802_11N_MAC_EXT_FLAG_RX_GUARD_INTERVAL;
			}
			else
			{
				pDot11NHeader->Dot11nMacPhyExtensionData.Flags |= PPI_FLD_802_11N_MAC_EXT_FLAG_RX_GUARD_INTERVAL;
			}

			for (ht40 = 0; ht40 <= ((extChannel == 0)?0:1); ht40++)
			{

				if (ht40 == 0)
				{
					pDot11NHeader->Dot11nMacPhyExtensionData.Flags &= ~PPI_FLD_802_11N_MAC_EXT_FLAG_HT20_40;
				}
				else
				{
					pDot11NHeader->Dot11nMacPhyExtensionData.Flags |= PPI_FLD_802_11N_MAC_EXT_FLAG_HT20_40;
				}

				for(mcs = 0; mcs <= 15; mcs++)
				{
					pDot11NHeader->Dot11nMacPhyExtensionData.MCS = mcs;

					printf("Transmitting HT-OFDM MCS = %u HT40 = %u SGI = %u, aggr = %u\n",
						mcs, 
						ht40,
						sgi, 
						maxAggr);

					//
					// Now transmit the packet
					//
					if (maxAggr == 0)
					{
						if (AirpcapWrite(airpcap_handle, (PCHAR)pDot11NHeader, effectivePacketSize + sizeof(*pDot11NHeader)) == FALSE)
						{
							printf("Error sending the packet: %s\n", AirpcapGetLastError(airpcap_handle));
						}
					}

					for (aggr = 0; aggr < maxAggr; aggr++)
					{
						ULONG originalFlags = pDot11NHeader->Dot11nMacPhyExtensionData.Flags;

						pDot11NHeader->Dot11nMacPhyExtensionData.Flags |= PPI_FLD_802_11N_MAC_EXT_FLAG_AGGREGATE;

						if (aggr != maxAggr - 1)
						{
							pDot11NHeader->Dot11nMacPhyExtensionData.Flags |= PPI_FLD_802_11N_MAC_EXT_FLAG_MORE_AGGREGATES;
						}

						if (AirpcapWrite(airpcap_handle, (PCHAR)pDot11NHeader, effectivePacketSize) == FALSE)
						{
							printf("Error sending the packet: %s\n", AirpcapGetLastError(airpcap_handle));
						}

						pDot11NHeader->Dot11nMacPhyExtensionData.Flags = originalFlags;
					}
				}
			}
		}
	}

	//
	// Close the libpcap handler. Note that We don't need to close the AirPcap handler, because 
	// pcap_close takes care of it.
	//
	pcap_close(winpcap_adapter);
	return 0;
}
