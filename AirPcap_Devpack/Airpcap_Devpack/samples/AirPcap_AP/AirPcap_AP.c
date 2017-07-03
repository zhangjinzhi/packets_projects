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
 * This program allows the user to test the Tx function of the AirPcap 
 * adapter by creating a fake AP. This fake AP should be visible from any
 * computer in the area.
 *
 *===========================================================================
 */

#include "AirPcap_AP.h"

u_int8* beacon;
u_int8* probe;

u_int beacon_total_length;
u_int probe_total_length;

#define BEACON_PACKET_HEADER_LENGTH 68
#define PROBE_PACKET_HEADER_LENGTH 68
#define PACKET_TAIL_LENGTH 19
#define CHANNEL_OFFSET 12

//
// The first part of the Beacon packet.
//
u_int8 beacon_packet_header[BEACON_PACKET_HEADER_LENGTH] = 
{
	0x00, 0x00, 0x20, 0x00, 0x69, 0x00, 0x00, 0x00,  0x02, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,  0x6c, 0x09, 0xa0, 0x00, 0x00, 0x00, 0xe8, 0x9c, 
	0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xca, 0xce, 0xca, 0xce, 0xca, 0xce, 
	0xca, 0xce, 0xca, 0xce, 0xca, 0xce, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x32, 0x00, 0x11, 0x00};

//
// The first part of the Probe Response packet.
//
u_int8 probe_response_packet_header[PROBE_PACKET_HEADER_LENGTH] = 
{
	0x00, 0x00, 0x20, 0x00, 0x69, 0x00, 0x00, 0x00,  0x02, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,  0x6c, 0x09, 0xa0, 0x00, 0x00, 0x00, 0xe8, 0x9c, 
	0x50, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xca, 0xce, 0xca, 0xce, 0xca, 0xce, 
	0xca, 0xce, 0xca, 0xce, 0xca, 0xce, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x64, 0x00, 0x11, 0x00};

//
// The second part of both the Probe Response and Beacon packets
//
u_int8 packet_header_tail[PACKET_TAIL_LENGTH] = 
{
	0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12,  0x18, 0x24, 0x03, 0x01, 0x03, 0x05, 0x04, 0x00, 
	0x01, 0x00, 0x00};



////////////////////////////////////////////////////////////////////////
//							main
////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
	PAirpcapHandle Ad;
	u_int channel;
	char name[255];
	char* p;

	beacon_total_length = 0;
	probe_total_length = 0;

	//
	// Ask the user to select an adapter. Configure it and open it.
	//
	Ad = getAirPcapAdapter();
	if (Ad == NULL)
	{
		exitApp(-1);
	}

	//
	// Get adapter channel
	//
	if (!AirpcapGetDeviceChannel(Ad, &channel))
	{
		printf("Error: error getting adapter channel.");
		exitApp(-1);
	}

	while(TRUE)
	{
		//
		// Get AP name from user
		//
		printf("AP Name: ");
		flushall();         /* kill any characters left in buffer */
		fgets(name, sizeof(name), stdin);

		//
		// Remove the ending \n from the string
		//
		if((p = strchr(name, '\n')) != NULL)
			*p = '\0';

		//
		// Max length of AP name is 32 characters
		//
		if (strlen(name) <= 32)
		{
			break;
		}
		else
		{
			printf("Error: AP name too long. Name must be 32 characters or less.\n\n");
		}
	}

	//
	// Now that we know the AP name and channel we
	// can make the beacon and probe response packets.
	//
	makePackets(name, (u_int8)channel);

	//
	// Start the listening thread
	//
	_beginthread(listenForProbeRequest, 0, Ad);

	//
	// Start looking for user exit key
	//
	_beginthread(waitForExit, 0, NULL);

	//
	// Notify the user that we are up and running
	//
	printf("\nStarted on channel %u!\n", channel);

	while (TRUE)
	{
		//
		// Send off a beacon
		//
		if (!AirpcapWrite(Ad, (char*)beacon, beacon_total_length))
		{
			printf("\nError sending beacon: %s\n", AirpcapGetLastError(Ad));
			exitApp(-1);
		}

		//
		// Wait 50ms
		//
		Sleep(50);
	}

	return 0;
}


////////////////////////////////////////////////////////////////////////
//						waitForExit
////////////////////////////////////////////////////////////////////////
// Waits for the user to push a key, then exits the application.
//
// Params: params - Not used.
//
// Returns - None.
////////////////////////////////////////////////////////////////////////
void waitForExit(void* params)
{
	printf("\nPress enter key to stop and exit");
	flushall();         /* kill any characters left in buffer */
	getchar();

	exit(0);
}


////////////////////////////////////////////////////////////////////////
//						makePackets
////////////////////////////////////////////////////////////////////////
// Crafts the beacon and probe response packets using the AP name and
// channel supplied by the user.
//
// Params:	name - The desired name of the AP.
//			channel - The desired channel of the AP.
//
// Returns - None.
////////////////////////////////////////////////////////////////////////
void makePackets(char* name, u_int8 channel)
{
	//
	// Max length of AP name is 32 characters
	//
	if (strlen(name) > 32)
	{
		printf("Error: AP name too long.");
		exitApp(-1);
	}

	/* Start - Beacon Creation */
		// Get space for the new packet
		beacon = (u_int8*)malloc(strlen(name) + 2 + BEACON_PACKET_HEADER_LENGTH + PACKET_TAIL_LENGTH);

		// Move the front of the packet into place
		memcpy(beacon, beacon_packet_header, BEACON_PACKET_HEADER_LENGTH);

		// Set the rate based on the channel. For A range channels,
		// set to 6Mbs for BG channels set to 1Mbs
		if (channel > 14)
		{
			((p_ppi_80211_common_header)((u_int8*)beacon + sizeof(ppi_packet_header) + sizeof(ppi_fieldheader)))->rate = 12;
		}
		else
		{
			((p_ppi_80211_common_header)((u_int8*)beacon + sizeof(ppi_packet_header) + sizeof(ppi_fieldheader)))->rate = 2;
		}

		// Place the tag identifier for the ESSID into the packet
		*(u_int8*)(beacon + BEACON_PACKET_HEADER_LENGTH) = 0;

		// Insert the length of the ESSID
		*(u_int8*)(beacon + BEACON_PACKET_HEADER_LENGTH + 1) = strlen(name);

		// Insert the ESSID
		strcpy((char*)(beacon + 2 + BEACON_PACKET_HEADER_LENGTH), name);

		// Append the tail of the packet
		memcpy(beacon + 2 + BEACON_PACKET_HEADER_LENGTH + strlen(name), packet_header_tail, PACKET_TAIL_LENGTH);

		// Set the channel
		*(u_int8*)(beacon + 2 + BEACON_PACKET_HEADER_LENGTH + strlen(name) + CHANNEL_OFFSET) = channel;

		// Upade the beacon_total_length variable to be the new length
		beacon_total_length = 2 + BEACON_PACKET_HEADER_LENGTH + strlen(name) + PACKET_TAIL_LENGTH;
	/* End - Beacon Creation */

	/* Start - Probe Respone Creation */
		// Get space for the new packet
		probe = (u_int8*)malloc(strlen(name) + 2 + PROBE_PACKET_HEADER_LENGTH + PACKET_TAIL_LENGTH);

		// Move the front of the packet into place
		memcpy(probe, probe_response_packet_header, PROBE_PACKET_HEADER_LENGTH);

		// Place the tag identifier for the ESSID into the packet
		*(u_int8*)(probe + PROBE_PACKET_HEADER_LENGTH) = 0;

		// Insert the length of the ESSID
		*(u_int8*)(probe + PROBE_PACKET_HEADER_LENGTH + 1) = strlen(name);

		// Insert the ESSID
		strcpy((char*)(probe + 2 + PROBE_PACKET_HEADER_LENGTH), name);

		// Append the tail of the packet
		memcpy(probe + 2 + PROBE_PACKET_HEADER_LENGTH + strlen(name), packet_header_tail, PACKET_TAIL_LENGTH);

		// Set the channel
		*(u_int8*)(probe + 2 + PROBE_PACKET_HEADER_LENGTH + strlen(name) + CHANNEL_OFFSET) = channel;

		// Upade the beacon_total_length variable to be the new length
		probe_total_length = 2 + PROBE_PACKET_HEADER_LENGTH + strlen(name) + PACKET_TAIL_LENGTH;
	/* End - Probe Respone Creation */
}


////////////////////////////////////////////////////////////////////////
//						listenForProbeRequest
////////////////////////////////////////////////////////////////////////
// Listens for a probe request and sends the response.
//
// Params:	Ad - An open handle to a device.
//
// Returns - None.
////////////////////////////////////////////////////////////////////////
void listenForProbeRequest(PAirpcapHandle Ad)
{
	HANDLE ReadEvent;
	p_ppi_packet_header p_ppi;
	BYTE* PacketBuffer;
	UINT BytesReceived;

	//
	// Get the read event
	//
	if(!AirpcapGetReadEvent(Ad, &ReadEvent))
	{
		printf("Error getting the read event: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		exitApp(-1);
	}

	//
	// Allocate a 256k packet buffer
	//
	PacketBuffer = (BYTE*)malloc(PACKET_BUFFER_SIZE);
	if(!PacketBuffer)
	{
		printf("No memory for the packet buffer\n");
		AirpcapClose(Ad);
		exitApp(-1);
	}

	//
	// Everything is ok! 
	// Look for Probe Request
	//
	while (TRUE)
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
			exitApp(-1);
		}

		// Look for Echo Request. When found, take it from there.
		if(getProbeRequest(Ad, PacketBuffer, BytesReceived, &p_ppi))
		{
			sendProbeResponse(Ad, p_ppi);
		}

		// wait until some packets are available. This prevents polling and keeps the CPU low. 
		WaitForSingleObject(ReadEvent, WAIT_INTERVAL_MS);
	}

	//
	// Make sure we clean up after
	//
	free(PacketBuffer);

	//
	// Exit, printing the exit message
	//
	exitApp(0);
}


////////////////////////////////////////////////////////////////////////
//						sendProbeResponse
////////////////////////////////////////////////////////////////////////
// Sends the echo request and looks for a response.
//
// Params:	Ad - An open handle to a device.
//			p_ppi - Pointer to the first byte of the request buffer
//
// Returns - None.
////////////////////////////////////////////////////////////////////////
void sendProbeResponse(PAirpcapHandle Ad, p_ppi_packet_header p_ppi)
{
	int i;
	p_probe_header src_pr_hdr, dst_pr_hdr;
	p_ppi_80211_common_header dst_ppi_common_hdr, src_ppi_common_hdr;

	//
	// Match the transmit rate of the probe response to the 
	// recieve rate of the probe request. We must make sure that
	// the needed section of PPI is in place before we start
	// copying the rate, however.
	//
	if (((p_ppi_fieldheader)((u_int8*)p_ppi + sizeof(ppi_packet_header)))->pfh_type == 2 &&
		((p_ppi_fieldheader)((u_int8*)p_ppi + sizeof(ppi_packet_header)))->pfh_datalen == 20)
	{
		dst_ppi_common_hdr = (p_ppi_80211_common_header)((u_int8*)probe + sizeof(ppi_packet_header) + sizeof(ppi_fieldheader));
		src_ppi_common_hdr = (p_ppi_80211_common_header)((u_int8*)p_ppi + sizeof(ppi_packet_header) + sizeof(ppi_fieldheader));
		dst_ppi_common_hdr->rate = src_ppi_common_hdr->rate;
	}

	//
	// Get the Probe Request Header and the Probe Response Header
	//
	src_pr_hdr = (p_probe_header)((u_int8*)p_ppi + p_ppi->PphLength);
	dst_pr_hdr = (p_probe_header)((u_int8*)probe + ((p_ppi_packet_header)(probe))->PphLength);

	// 
	// Copy the source ethernet address from the probe request into
	// the destination address of the probe response. Also copy the
	// source ethernet address from the probe request to the BSSID
	// address of the probe response.
	//
	memcpy(dst_pr_hdr->dst_eth.octet, src_pr_hdr->src_eth.octet, 6);
	memcpy(dst_pr_hdr->bss_eth.octet, src_pr_hdr->src_eth.octet, 6);

	//
	// Send three times
	//
	for (i=0; i<3; i++)
	{
		AirpcapWrite(Ad, (char*)probe, probe_total_length);
		Sleep(1);
	}
}


////////////////////////////////////////////////////////////////////////
//						exitApp
////////////////////////////////////////////////////////////////////////
// Exit from the application with the given code.
//
// Params:	exitCode - The exit code.
//
// Returns - None.
////////////////////////////////////////////////////////////////////////
void exitApp(int exitCode)
{
	printf("\nPress any key to exit");
	flushall();         /* kill any characters left in buffer */
	getchar();

	exit(exitCode);
}


////////////////////////////////////////////////////////////////////////
//						getProbeRequest
////////////////////////////////////////////////////////////////////////
// Finds an probe request by listening on the given device. When the 
// probe request is found, set p_ppi to the first byte of the request
// and return true.
//
// Params:	Ad - An open handle to a device.
//			PacketBuffer - The packet buffer to search through.
//			BufferSize - The size of the given packet buffer.
//			p_ppi - Pointer to a PPI header pointer. On success, p_ppi
//					will be set to the first byte in the found probe
//					request, NULL otherwise.
//
// Returns - true on success, false otherwise.
////////////////////////////////////////////////////////////////////////
boolean getProbeRequest(PAirpcapHandle Ad, BYTE *PacketBuffer, ULONG BufferSize, p_ppi_packet_header *p_ppi)
{
	BYTE *Buf;
	u_int TLen, TLen1;
	UINT Off = 0;
	PAirpcapBpfHeader Hdr;
	p_ppi_packet_header pPpiPacketHeader;
	p_probe_header probe_hdr;

	Buf = PacketBuffer;
	Off=0;
	
	//
	// Loop through the packet buffer looking for the Echo request.
	//
	while(Off < BufferSize)
	{
		Hdr = (PAirpcapBpfHeader)(Buf + Off);
		TLen1 = Hdr->Originallen;
		TLen = Hdr->Caplen;
		Off += Hdr->Hdrlen;
		
		//
		// Assign pPpiPacketHeader to the head of the current packet in the buffer
		//
		pPpiPacketHeader = (p_ppi_packet_header)(Buf + Off);
		probe_hdr = (p_probe_header)(Buf + Off + pPpiPacketHeader->PphLength);

		//
		// Check to see if the current packet is an ICMP packet.
		// If so, assign iph to the start of the IP header.
		//
		if (((probe_hdr->frame_control) & 0xf6)== 0x40)
		{
			*p_ppi = pPpiPacketHeader;
			return TRUE;
		}

		Off = AIRPCAP_WORDALIGN(Off + TLen);
	}
	return FALSE;
}

////////////////////////////////////////////////////////////////////////
//						getAirPcapAdapter
////////////////////////////////////////////////////////////////////////
// Lists the adapters and asks the user to select and adapter and a
// frequency.
//
// Returns - Handle to the selected adapter with the channel already 
//			 set and PPI selected.
////////////////////////////////////////////////////////////////////////
PAirpcapHandle getAirPcapAdapter()
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	UINT freq_chan = 8;
	UINT i, Inum, range;
	AirpcapDeviceDescription *AllDevs, *TmpDev;
	AirpcapChannelInfo tchaninfo;

	//
	// Get the device list
	//
	if(!AirpcapGetDeviceList(&AllDevs, Ebuf))
	{
		printf("Unable to retrieve the device list: %s\n", Ebuf);
		return NULL;
	}

	//
	// Make sure that the device list is valid
	//
	if(AllDevs == NULL)
	{
		printf("No interfaces found! Make sure the airpcap software is installed and your adapter is properly plugged in.\n");
		return NULL;
	}

	//
	// Print the list
	//
	for(TmpDev = AllDevs, i = 0; TmpDev; TmpDev = TmpDev->next)
	{
		printf("%d. ", ++i);
		
		//
		// If the adapter is a Tx adapter, say so.
		//
		if (isTxAdapter(TmpDev->Name))
		{
			printf("Tx - ");
		}

		//
		// Print adapter name and description
		//
		printf("%s", TmpDev->Name);
		if(TmpDev->Description)
		{
			printf(" (%s)\n", TmpDev->Description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}
	printf("\n");

	//
	// Store the range of valid adapters for future use.
	//
	range = i;

	//
	// If there are no valid adapters
	//
	if(range == 0)
	{
		printf("\nNo interfaces found! Make sure the airpcap software is installed and your adapter is properly plugged in.\n");
		AirpcapFreeDeviceList(AllDevs);
		return NULL;
		}

	//
	// Loop because the user may have selected an invalid adapter.
	//
	while (1)
	{
		//
		// Ask for the user to select an adapter.
		//
		printf("Enter the adapter number (1-%d): ",range);
		flushall();         /* kill any characters left in buffer */
		scanf("%d", &Inum);
		
		//
		// Check if the user specified a valid adapter
		//
		if(Inum < 1 || Inum > range)
		{
			printf("Error: Invalid adapter selection.\n\n");
			continue;
		}

		//
		// Jump to the selected adapter
		//
		for(TmpDev = AllDevs, i = 0; i < Inum-1 ;TmpDev = TmpDev->next, i++);

		//
		// Make sure the adapter is a Tx capable one.
		//
		if (!isTxAdapter(TmpDev->Name))
		{
			printf("Error: The selected adapter does not support transmission.\n\n");
		}
		else
		{
			break;
		}
	}

	//
	// Loop, as the user may specify an invalid channel.
	//
	while (1)
	{
		//
		// Ask for a channel to listen to
		//
		printf("Enter the channel or frequency: ",i);
		scanf("%d", &freq_chan);
		
		// 
		// Check if the user specified a valid channel
		//
		if(freq_chan < 1 || freq_chan > 8000)
		{
			printf("\nChannel or frequency out of range.\n");
			AirpcapFreeDeviceList(AllDevs);
			return NULL;
		}

		//
		// Make sure the user picked a valid Tx channel.
		//
		if (!isTxFrequencySupported(TmpDev->Name, freq_chan))
		{
			printf("\nThe selected frequency does not support transmission.\nPlease select from the list of supported channels below:\n\n");
			
			//
			// Print the list of channels the adapter supports Tx on.
			//
			printTxFrequenciesByName(TmpDev->Name);
			printf("\n\n");
		}
		else
		{
			break;
		}
	}

	//
	// Open the adapter
	//
	Ad = AirpcapOpen(TmpDev->Name, Ebuf);
	if(!Ad)
	{
		printf("Error opening the adapter: %s\n", Ebuf);
		return NULL;
	}

	//
	// We don't need the device list any more, free it
	//
	AirpcapFreeDeviceList(AllDevs);

	//
	// Set the link layer to 802.11 plus PPI headers
	//
	if(!AirpcapSetLinkType(Ad, AIRPCAP_LT_802_11_PLUS_PPI))
	{
		printf("Error setting the link layer: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		return NULL;
	}

	// Set the channel.
	// If the user provides a value below 500, we assume it's a channel number, otherwise we assume it's a frequency.
	if(freq_chan < 500)
	{
		if(!AirpcapSetDeviceChannel(Ad, freq_chan))
		{
			printf("Error setting the channel: %s\n", AirpcapGetLastError(Ad));
			AirpcapClose(Ad);
			return NULL;
		}
	}
	else
	{
		memset(&tchaninfo, sizeof(tchaninfo), 0);
		tchaninfo.Frequency = freq_chan;

		if(!AirpcapSetDeviceChannelEx(Ad, tchaninfo))
		{
			printf("Error setting the channel: %s\n", AirpcapGetLastError(Ad));
			AirpcapClose(Ad);
			return NULL;
		}
	}

	return Ad;
}


////////////////////////////////////////////////////////////////////////
//						isTxAdapter
////////////////////////////////////////////////////////////////////////
// Determines whether a given device supports Tx or not.
//
// Params:	Name - The formal name of the device.
//
// Returns - True if the given device supports Tx, false otherwise.
////////////////////////////////////////////////////////////////////////
boolean isTxAdapter(PCHAR Name)
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	PAirpcapChannelInfo frequencyList, tmpFrequency;
	UINT numFrequencies;
	UINT i;

	//
	// Always return false for the Multi-Channel Aggregator
	//
	if (strncmp(Name, "\\\\.\\airpcap_any", 16) == 0)
		return FALSE;

	//
	// Open adapter
	//
	Ad = AirpcapOpen(Name, Ebuf);
	if(!Ad)
	{
		printf("Error opening the adapter: %s\n", Ebuf);
		return FALSE;
	}

	//
	// Get the list of supported channels. This returns an array of structs
	// that contains a flag for Tx.
	//
	if (!AirpcapGetDeviceSupportedChannels(Ad, &frequencyList, &numFrequencies))
	{
		printf("Error retrieving list of supported channels for adapter %s\n", Name);
		AirpcapClose(Ad);
		return FALSE;
	}

	//
	// Loop through the array of returned channels and look for one thats 
	// supports Tx.
	//
	for(i=0; i<numFrequencies; i++)
	{
		tmpFrequency = frequencyList + i;
		if (tmpFrequency->Flags & AIRPCAP_CIF_TX_ENABLED)
		{
			AirpcapClose(Ad);
			return TRUE;
		}
	}

	//
	// No channels supported Tx.
	//
	AirpcapClose(Ad);
	return FALSE;
}


////////////////////////////////////////////////////////////////////////
//						isTxFrequencySupported
////////////////////////////////////////////////////////////////////////
// Determines whether a given channel supports Tx or not.
//
// Params:	name - The formal name of the device.
//			frequency - The channel or frequency to test
//
// Returns - True if the given channel supports Tx, false otherwise.
////////////////////////////////////////////////////////////////////////
boolean isTxFrequencySupported(PCHAR name, UINT frequency)
{
	PUINT frequencyList;
	UINT numFrequencies;
	UINT i;

	//
	// If the given frequency is below 500 assume the user meant
	// channel.
	//
	if (frequency < 500)
	{
		//
		// Convert channel to frequency
		//
		if (!AirpcapConvertChannelToFrequency(frequency, &frequency))
		{
			printf("Error converting channel to frequency\n");
			return FALSE;
		}
	}

	//
	// Get the list of Tx frequencies supported by the device
	//
	if (!getTxFrequenciesByName(name, &frequencyList, &numFrequencies))
	{
		printf("Error printing the supported frequencies\n");
		return FALSE;
	}

	//
	// Loop through the frequency list looking for the supplied frequency.
	// If the found frequency matches the supplied one, return true.
	for(i=0; i<numFrequencies; i++)
	{
		if (frequencyList[i] == frequency)
		{
			free(frequencyList);
			return TRUE;
		}
	}

	//
	// Make sure to clean up afterwards
	//
	free(frequencyList);
	return FALSE;
}


////////////////////////////////////////////////////////////////////////
//						printTxFrequenciesByName
////////////////////////////////////////////////////////////////////////
// Prints the list of supported Tx channels to screen.
//
// Params:	name - The formal name of the device.
//
// Returns - True on success, False otherwise.
////////////////////////////////////////////////////////////////////////
boolean printTxFrequenciesByName(PCHAR name)
{
	PUINT frequencyList;
	UINT numFrequencies;
	PCHAR outputString;
	UINT i;

	//
	// Get the list of supported Tx channels
	//
	if (!getTxFrequenciesByName(name, &frequencyList, &numFrequencies))
	{
		printf("Error printing the supported frequencies\n");
		return FALSE;
	}

	//
	// Loop through the list and output it to the screen
	//
	for(i=0; i<numFrequencies; i++)
	{
		//
		// Get the nicely formatted version of the frequency (and channel)
		//
		outputString = getPrintableFrequency(*(frequencyList+i));

		//
		// Arrange the output into 3 columns
		//
		if (i%3 == 0)
		{
			printf("\n%-18s", outputString);
		}
		else
		{
			printf("%-18s", outputString);
		}

		//
		// Cleanup
		//
		free(outputString);
	}

	free(frequencyList);
	return TRUE;
}


////////////////////////////////////////////////////////////////////////
//						getPrintableFrequency
////////////////////////////////////////////////////////////////////////
// Prints the frequency (and channel) in a nicely formatted manner.
//
// Params:	frequency - The frequency to format.
//
// Returns - A handle to the formatted string. This string must be 
//			 freed.
////////////////////////////////////////////////////////////////////////
PCHAR getPrintableFrequency(UINT frequency)
{
	UINT tmpChannel;
	PCHAR outputString = NULL;
	const UINT maxStringLen = 100;

	//
	// Get some space
	//
	outputString = (PCHAR)malloc(maxStringLen);

	//
	// Print the strings
	//
	if (frequency < 3000) /* BG */
	{
		if (convertFrequencyToChannel(frequency, &tmpChannel))
		{
			_snprintf(outputString, maxStringLen, "%u MHz [BG %u]", frequency, tmpChannel); /* Has a channel */
		}
		else
		{
			_snprintf(outputString, maxStringLen, "%u MHz [BG]", frequency); /* Doesn't have a channel */
		}
	}
	else if (frequency >= 3000 && frequency < 6500) /* A */
	{
		if (convertFrequencyToChannel(frequency, &tmpChannel))
		{
			_snprintf(outputString, maxStringLen, "%u MHz [A %u]", frequency, tmpChannel); /* Has a channel */
		}
		else
		{
			_snprintf(outputString, maxStringLen, "%u MHz [A]", frequency); /* Doesn't have a channel */
		}
	}
	return outputString;
}


////////////////////////////////////////////////////////////////////////
//						convertFrequencyToChannel
////////////////////////////////////////////////////////////////////////
// Converts the given frequency to the channel.
//
// Params:	frequency - The frequency to convert.
//			tmpChannel - Pointer to the channel returned.
//
// Returns - True on success, False otherwise. True indicates tmpChannel
//			 is set, False indicates tmpChannel is not set.
////////////////////////////////////////////////////////////////////////
boolean convertFrequencyToChannel(UINT frequency, PUINT tmpChannel)
{
	if (frequency >= 2412 && frequency <= 2472 && ((frequency-2412)%5) == 0) // Normal BG
	{
		*tmpChannel = (frequency - 2407)/5;
		return TRUE;
	}
	else if (frequency == 2484) // 14 BG
	{
		*tmpChannel = 14;
		return TRUE;
	}
	else if (frequency >= 5000 && frequency <= 6000 && (frequency%5) == 0) // A
	{
		*tmpChannel = (frequency - 5000)/5;
		return TRUE;
	}
	else if (frequency >= 4920 && frequency <= 4995 && (frequency%5) == 0) // Lower A
	{
		*tmpChannel = (frequency - 4920)/5 + 240;
		return TRUE;
	}

	return FALSE;
}


////////////////////////////////////////////////////////////////////////
//						getTxFrequenciesByName
////////////////////////////////////////////////////////////////////////
// Gets the list of supported Tx channels.
//
// Params:	name - The formal name of the device.
//			frequencyList - The array of supported channels
//			numFrequencies - The number of elements in the frequencyList
//							 array.  Also the number of Tx channels the
//							 device supports.
//
// Returns - True on success, False otherwise.
////////////////////////////////////////////////////////////////////////
boolean getTxFrequenciesByName(PCHAR name, PUINT *frequencyList, PUINT numFrequencies)
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	boolean response;

	//
	// Open the device
	//
	Ad = AirpcapOpen(name, Ebuf);
	if(!Ad)
	{
		printf("Error opening the adapter: %s\n", Ebuf);
		frequencyList = NULL;
		*numFrequencies = 0;
		return FALSE;
	}

	//
	// Toss the request over to the sister function for processing.
	//
	response = getTxFrequenciesByHandle(Ad, frequencyList, numFrequencies);

	//
	// Make sure to close the adapter we opened.
	//
	AirpcapClose(Ad);

	return response;
}


////////////////////////////////////////////////////////////////////////
//						getTxFrequenciesByHandle
////////////////////////////////////////////////////////////////////////
// Gets the list of supported Tx channels.
//
// Params:	Ad - An open handle to a device.
//			frequencyList - The array of supported channels
//			numFrequencies - The number of elements in the frequencyList
//							 array.  Also the number of Tx channels the
//							 device supports.
//
// Returns - True on success, False otherwise.
////////////////////////////////////////////////////////////////////////
boolean getTxFrequenciesByHandle(PAirpcapHandle Ad, PUINT *frequencyList, PUINT numFrequencies)
{
	PAirpcapChannelInfo frequencies, tmpFrequency;
	UINT tmpNumFrequencies;
	UINT tmpFrequencies[512] = {0};

	UINT i, ii;
	UINT c = 0;
	boolean skip;

	//
	// Get the list of supported channels from the adapter.
	//
	if (!AirpcapGetDeviceSupportedChannels(Ad, &frequencies, &tmpNumFrequencies))
	{
		printf("Error retrieving list of supported channels\n");
		return FALSE;
	}

	//
	// Loop through the array of supported channels and copy the Tx
	// one over to the tmpFrequencies array.
	//
	for(i=0; i<tmpNumFrequencies; i++)
	{
		skip = FALSE;
		tmpFrequency = frequencies + i;

		//
		// We don't need two copies of the same frequency
		//
		for (ii=0; ii<i; ii++)
		{
			if (tmpFrequency->Frequency == tmpFrequencies[ii])
			{
				skip = TRUE;
			}
		}

		if (!skip && (tmpFrequency->Flags & AIRPCAP_CIF_TX_ENABLED))
		{
			tmpFrequencies[c++] = tmpFrequency->Frequency;
		}
	}

	//
	// Set the number of frequencies
	//
	*numFrequencies = c;

	//
	// Sort the frequencies lowest to highest.
	//
	//qsort (tmpFrequencies, *numFrequencies, sizeof(UINT), uint_compare);

	//
	// Get the space needed to hold the amount of elements we are
	// going to copy over from the tmpFrequencies array to the 
	// frequencyList array.
	//
	*frequencyList = (PUINT)malloc(sizeof(UINT) * (*numFrequencies));

	//
	// Loop through the tmpFrequencies array and copy over the
	// elements to the frequencyList array.
	//
	for(i=0; i<(*numFrequencies); i++)
	{
		*(UINT*)(*frequencyList + i) = tmpFrequencies[i];
	}

	return TRUE;
}


////////////////////////////////////////////////////////////////////////
//						uint_compare
////////////////////////////////////////////////////////////////////////
// Compares two UINTs.  Needed for qsort.
//
// Params:	a - First UINT to compare.
//			b - Second UINT to compare.
//
// Returns - If a < b return negative.
//			 If a = b return zero.
//			 If a > b return positive.
////////////////////////////////////////////////////////////////////////
UINT uint_compare(const void *a, const void *b)
{
  return (*(int*)a - *(int*)b);
}