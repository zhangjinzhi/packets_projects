/*
 * Copyright (c) 2006-2007 CACE Technologies, Davis (California)
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
 * This example shows how to use airpcap and libpcap at the same time to set 
 * the wireless adapter parameters and then capture the packets in the usual
 * way.
 * The program needs files from both the airpcap and WinPcap developer's pack,
 * and ASSUMES THAT THE TWO DEVELOPER'S PACKS ARE UNPACKED IN THE SAME FOLDER.
 * You can get the WinPcap developer's pack from http://www.winpcap.org.
 * You can get the airpcap developer's pack from http://www.cacetech.com.
 *
 *===========================================================================
 */

#define _CRT_SECURE_NO_DEPRECATE
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <airpcap.h>

#define LINE_LEN 16

ULONG RadiotapPrint(const u_char *p, ULONG caplen);

main()
{
	pcap_t *winpcap_adapter;
	u_int inum, i;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int channel;
	PAirpcapHandle airpcap_handle;
	pcap_if_t *alldevs, *d;
	ULONG RadioHdrLen;
	
	
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
	printf("Enter the channel (1-14):",i);
	scanf("%d", &channel);
	
	// 
	// Check if the user specified a valid channel
	//
	if(channel < 1 || channel > 14)
	{
		printf("\nChannel out of range.\n");
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
	airpcap_handle = pcap_get_airpcap_handle(winpcap_adapter);

	if(airpcap_handle == NULL)
	{
		printf("This adapter doesn't have wireless extensions. Quitting\n");
		pcap_close(winpcap_adapter);
		return -1;
	}

	//
	// Set the channel
	//
	if(!AirpcapSetDeviceChannel(airpcap_handle, channel))
	{
		printf("Error setting the channel: %s\n", AirpcapGetLastError(airpcap_handle));
		pcap_close(winpcap_adapter);
		return -1;
	}

	//
	// Set the link layer to 802.11 plus radio headers
	//
	if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_RADIO))
	{
		printf("Error setting the link layer: %s\n", AirpcapGetLastError(airpcap_handle));
		pcap_close(winpcap_adapter);
		return -1;
	}

	// 
	// Read the packets
	//
	while((res = pcap_next_ex(winpcap_adapter, &header, &pkt_data)) >= 0)
	{

		if(res == 0)
		{
			// 
			// Timeout elapsed
			//
			continue;
		}

		//
		// print pkt timestamp and pkt len
		//
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);			
		
		//
		// Print radio information
		//
		RadioHdrLen = RadiotapPrint(pkt_data, header->caplen);

		//
		// The 802.11 packet follows the radio header
		//
		pkt_data += RadioHdrLen;

		//
		// Print the packet
		//
		printf("\nPacket bytes:\n");
		for (i=1; (i < header->caplen + 1 - RadioHdrLen) ; i++)
		{
			printf("%.2x ", pkt_data[i - 1]);
			if ( (i % LINE_LEN) == 0) printf("\n");
		}
		
		printf("\n\n");		
	}

	if(res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(winpcap_adapter));
	}

	//
	// Close the libpcap handler. We don't need to close the AirPcap one, because 
	// pcap_close takes care of it.
	//
	pcap_close(winpcap_adapter);
	return 0;
}
