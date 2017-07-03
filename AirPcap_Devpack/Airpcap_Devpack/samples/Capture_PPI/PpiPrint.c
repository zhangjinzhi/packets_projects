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
 */

#include <windows.h>
#include <stdio.h>
#include "PpiHeader.h"

#define DLT_IEEE802_11		105

void Print80211Common(PPPI_FIELD_802_11_COMMON pField);
void Print80211MacExtension(PPPI_FIELD_802_11N_MAC_EXTENSION pField);
void Print80211MacPhyExtension(PPPI_FIELD_802_11N_MAC_PHY_EXTENSION pField);


//////////////////////////////////////////////////////////////////////
// This function decodes and prints the PPI header
//
// Parameters:
//	p		pointer to the packet data
//  caplen	length of the captured packet data
//
// Return Value:
//  Length of the PPI header
//////////////////////////////////////////////////////////////////////
ULONG PpiPrint(const u_char *p, ULONG caplen)
{
	PPPI_PACKET_HEADER pPpiPacketHeader;
	PPPI_FIELD_HEADER	pFieldHeader;
	ULONG len;
	ULONG position = 0;

	//
	// Sanity checks
	//
	if (caplen < sizeof(*pPpiPacketHeader)) 
	{
		// Packet smaller than the PPI fixed header
		return 0;
	}

	pPpiPacketHeader = (PPPI_PACKET_HEADER)p;

	len = pPpiPacketHeader->PphLength;

	if(caplen < len) 
	{
		// Packet smaller than the PPI fixed header
		return 0;
	}

	position = sizeof(*pPpiPacketHeader);

	//
	// let's start printing
	//
	if (pPpiPacketHeader->PphDlt == DLT_IEEE802_11)
	{
		printf("Encapsulated link type = 802.11\n");
	}
	else
	{
		printf("Encapsulated link type = <%u>\n", pPpiPacketHeader->PphDlt);
	}

	if (pPpiPacketHeader->PphFlags != 0)
	{
		printf("Unknown flag value in the PPI packet header (%2.2x)\n", pPpiPacketHeader->PphFlags);
		return len;
	}

	if (pPpiPacketHeader->PphVersion != PPH_PH_VERSION)
	{
		printf("Unknown PPI packet header version (%u)\n", pPpiPacketHeader->PphVersion);
		return len;
	}

	do
	{
		//
		// now we suppose to have an 802.11-Common header
		//
		if (len < sizeof(*pFieldHeader) + position)
		{
			break;
		}

		pFieldHeader = (PPPI_FIELD_HEADER)(p + position);
		position += sizeof(*pFieldHeader);

		switch(pFieldHeader->PfhType)
		{
		case PPI_FIELD_TYPE_802_11_COMMON:
			if (pFieldHeader->PfhLength != sizeof(PPI_FIELD_802_11_COMMON) || caplen - position < sizeof(PPI_FIELD_802_11_COMMON))
			{
				//
				// the header is bogus, just skip it
				//
				printf("Bogus 802.11-Common Field. Skipping it.\n");
			}
			else
			{
				Print80211Common((PPPI_FIELD_802_11_COMMON)(p + position));
			}
			break;

		case PPI_FIELD_TYPE_802_11N_MAC_EXTENSION:
			if (pFieldHeader->PfhLength != sizeof(PPI_FIELD_802_11N_MAC_EXTENSION) || caplen - position < sizeof(PPI_FIELD_802_11N_MAC_EXTENSION))
			{
				//
				// the header is bogus, just skip it
				//
				printf("Bogus 802.11n-MAC Extension Field. Skipping it.\n");
			}
			else
			{
				Print80211MacExtension((PPPI_FIELD_802_11N_MAC_EXTENSION)(p + position));
			}
			break;

		case PPI_FIELD_TYPE_802_11N_MAC_PHY_EXTENSION:
			if (pFieldHeader->PfhLength != sizeof(PPI_FIELD_802_11N_MAC_PHY_EXTENSION) || caplen - position < sizeof(PPI_FIELD_802_11N_MAC_PHY_EXTENSION))
			{
				//
				// the header is bogus, just skip it
				//
				printf("Bogus 802.11n-MAC+PHY Extension Field. Skipping it.\n");
			}
			else
			{
				Print80211MacPhyExtension((PPPI_FIELD_802_11N_MAC_PHY_EXTENSION)(p + position));
			}
			break;

		default:
			//
			// we do not know this field. Just print type and length and skip
			//
			printf("Unknown PPI Header field (type=%u length=%u)\n", pFieldHeader->PfhType, pFieldHeader->PfhLength);

		}
		
		position += pFieldHeader->PfhLength;
	}
	while(TRUE);

	return len;
}

void Print80211Common(PPPI_FIELD_802_11_COMMON pField)
{
	printf("-- 802.11-Common --\n");

	if (pField->Flags & PPI_FLD_802_11_COMMON_FLAG_TSFT_MS)
	{
		printf("TSF timer = %I64u ms\n", pField->TsfTimer);
	}
	else
	{
		printf("TSF timer = %I64u us\n", pField->TsfTimer);
	}

	printf("The FCS is %s at the end of the packet.\n",
		(pField->Flags & PPI_FLD_802_11_COMMON_FLAG_FCS_PRESENT)? "present": "not present");

	printf("The FCS at the end of the packet is %s.\n",
		(pField->Flags & PPI_FLD_802_11_COMMON_FLAG_WRONG_FCS)? "wrong": "correct");

	printf("The packet was received from the PHY %s.\n",
		(pField->Flags & PPI_FLD_802_11_COMMON_FLAG_PHY_ERROR)? "with errors": "without errors");

	printf("Rx rate = %uMbps\n", pField->Rate/2);

	switch(pField->ChannelFrequency)
	{
	case 2412:	printf("Channel: 1 [BG]\n"); break;
	case 2417:	printf("Channel: 2 [BG]\n"); break;
	case 2422:	printf("Channel: 3 [BG]\n"); break;
	case 2427:	printf("Channel: 4 [BG]\n"); break;
	case 2432:	printf("Channel: 5 [BG]\n"); break;
	case 2437:	printf("Channel: 6 [BG]\n"); break;
	case 2442:	printf("Channel: 7 [BG]\n"); break;
	case 2447:	printf("Channel: 8 [BG]\n"); break;
	case 2452:	printf("Channel: 9 [BG]\n"); break;
	case 2457:	printf("Channel: 10 [BG]\n"); break;
	case 2462:	printf("Channel: 11 [BG]\n"); break;
	case 2467:	printf("Channel: 12 [BG]\n"); break;
	case 2472:	printf("Channel: 13 [BG]\n"); break;
	case 2484:	printf("Channel: 14 [BG]\n"); break;

	case 5170:	printf("Channel: 34 [A]\n"); break;
	case 5180:	printf("Channel: 36 [A]\n"); break;
	case 5190:	printf("Channel: 38 [A]\n"); break;
	case 5200:	printf("Channel: 40 [A]\n"); break;
	case 5210:	printf("Channel: 42 [A]\n"); break;
	case 5220:	printf("Channel: 44 [A]\n"); break;
	case 5230:	printf("Channel: 46 [A]\n"); break;
	case 5240:	printf("Channel: 48 [A]\n"); break;
	case 5260:	printf("Channel: 52 [A]\n"); break;
	case 5280:	printf("Channel: 56 [A]\n"); break;

	case 5300:	printf("Channel: 60 [A]\n"); break;
	case 5320:	printf("Channel: 64 [A]\n"); break;
	case 5745:	printf("Channel: 149 [A]\n"); break;
	case 5765:	printf("Channel: 153 [A]\n"); break;
	case 5785:	printf("Channel: 157 [A]\n"); break;
	case 5805:	printf("Channel: 161 [A]\n"); break;

	default:
		printf("Channel: %u MHz\n", pField->ChannelFrequency);
	}

	printf("Channel type:");

	if(pField->ChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_OFDM)
	{
		printf(" 802.11g");
	}

	if(pField->ChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_CCK)
	{
		printf(" 802.11b");
	}

	if(pField->ChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_2GHZ)
	{
		printf(", 2Ghz spectrum");
	}

	if(pField->ChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_5GHZ)
	{
		printf(", 5Ghz spectrum");
	}

	if (pField->ChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_PASV_SCAN)
	{
		printf(", passive scan");
	}

	printf("\n");

	printf("Channel hopping set %d, pattern %d\n", 
		pField->FhssHopset,
		pField->FhssPattern);

	if (pField->DbmAntSignal != -128)
		printf("Signal Strength: %d dBm\n", pField->DbmAntSignal);
	else
		printf("Signal Strength: <unknown>\n");

	if (pField->DbmAntNoise != -128)
		printf("Noise level: %d dBm\n", pField->DbmAntNoise);
	else
		printf("Noise level: <unknown>\n");

}


void Print80211MacExtension(PPPI_FIELD_802_11N_MAC_EXTENSION pField)
{
	printf("-- 802.11n MAC Extension --\n");

	printf("Flags:\n");

	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_GREENFIELD)
	{
		printf("\tGreenField packet\n");
	}
	
	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_HT20_40)
	{
		printf("\tHT40\n");
	}
	else
	{
		printf("\tHT20\n");
	}

	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_RX_GUARD_INTERVAL)
	{
		printf("\tShort guard interval\n");
	}
	else
	{
		printf("\tNormal guard interval\n");
	}

	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_DUPLICATE_RX)
	{
		printf("\tDuplicate Rx\n");
	}


	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_AGGREGATE)
	{
		printf("\tPacket is part of an A-MPDU aggregate (A-MPDU ID = %u)", pField->AMpduId);

		if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_MORE_AGGREGATES)
		{
			printf("\n");
		}
		else
		{
			printf(" Packet is also the last packet of the aggregate.\n");
		}

	}

	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_DELIMITER_CRC_ERROR_AFTER)
	{
		printf("\tThere was a CRC error in the A-MPDU delimiter after this frame. No more frames of this A-MPDU aggregate are present.\n");
	}

	printf("\n");

	printf("Number of zero-length pad delimiters = %u\n", pField->NumDelimiters);

}

void Print80211MacPhyExtension(PPPI_FIELD_802_11N_MAC_PHY_EXTENSION pField)
{
	printf("-- 802.11n MAC+PHY Extension --\n");

	printf("Flags:\n");

	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_GREENFIELD)
	{
		printf("\tGreenField packet\n");
	}
	
	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_HT20_40)
	{
		printf("\tHT40\n");
	}
	else
	{
		printf("\tHT20\n");
	}

	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_RX_GUARD_INTERVAL)
	{
		printf("\tShort guard interval\n");
	}
	else
	{
		printf("\tNormal guard interval\n");
	}

	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_DUPLICATE_RX)
	{
		printf("\tDuplicate Rx\n");
	}


	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_AGGREGATE)
	{
		printf("\tPacket is part of an A-MPDU aggregate (A-MPDU ID = %u)", pField->AMpduId);

		if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_MORE_AGGREGATES)
		{
			printf("\n");
		}
		else
		{
			printf(" Packet is also the last packet of the aggregate.\n");
		}

	}

	if (pField->Flags & PPI_FLD_802_11N_MAC_EXT_FLAG_DELIMITER_CRC_ERROR_AFTER)
	{
		printf("\tThere was a CRC error in the A-MPDU delimiter after this frame. No more frames of this A-MPDU aggregate are present.\n");
	}

	printf("\n");

	printf("Number of zero-length pad delimiters = %u\n", pField->NumDelimiters);

	printf("Modulation Coding Scheme (MCS) = ");
	if (pField->MCS == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->MCS);
	}
	
	printf("Number of streams = ");

	if (pField->NumStreams == 0)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->NumStreams);
	}

	printf("RSSI-Combined = ");
	if (pField->RssiCombined == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiCombined);
	}

	printf("RSSI Antenna 0 Control Channel   = ");
	if (pField->RssiAnt0Ctl == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiAnt0Ctl);
	}

	printf("RSSI Antenna 0 Extension Channel = ");
	if (pField->RssiAnt0Ext == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiAnt0Ext);
	}
	
	printf("RSSI Antenna 1 Control Channel   = ");
	if (pField->RssiAnt1Ctl == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiAnt1Ctl);
	}

	printf("RSSI Antenna 1 Extension Channel = ");
	if (pField->RssiAnt1Ext == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiAnt1Ext);
	}
	
	printf("RSSI Antenna 2 Control Channel   = ");
	if (pField->RssiAnt2Ctl == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiAnt2Ctl);
	}

	printf("RSSI Antenna 2 Extension Channel = ");
	if (pField->RssiAnt2Ext == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiAnt2Ext);
	}
	
	printf("RSSI Antenna 3 Control Channel   = ");
	if (pField->RssiAnt3Ctl == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiAnt3Ctl);
	}

	printf("RSSI Antenna 3 Extension Channel = ");
	if (pField->RssiAnt3Ext == 255)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->RssiAnt3Ext);
	}
	
	
	switch(pField->ExtChannelFrequency)
	{
	case 0: 
		// 
		// No extension channel
		//
		break;

	case 2412:	printf("Extension channel: 1 [BG]\n"); break;
	case 2417:	printf("Extension channel: 2 [BG]\n"); break;
	case 2422:	printf("Extension channel: 3 [BG]\n"); break;
	case 2427:	printf("Extension channel: 4 [BG]\n"); break;
	case 2432:	printf("Extension channel: 5 [BG]\n"); break;
	case 2437:	printf("Extension channel: 6 [BG]\n"); break;
	case 2442:	printf("Extension channel: 7 [BG]\n"); break;
	case 2447:	printf("Extension channel: 8 [BG]\n"); break;
	case 2452:	printf("Extension channel: 9 [BG]\n"); break;
	case 2457:	printf("Extension channel: 10 [BG]\n"); break;
	case 2462:	printf("Extension channel: 11 [BG]\n"); break;
	case 2467:	printf("Extension channel: 12 [BG]\n"); break;
	case 2472:	printf("Extension channel: 13 [BG]\n"); break;
	case 2484:	printf("Extension channel: 14 [BG]\n"); break;

	case 5170:	printf("Extension channel: 34 [A]\n"); break;
	case 5180:	printf("Extension channel: 36 [A]\n"); break;
	case 5190:	printf("Extension channel: 38 [A]\n"); break;
	case 5200:	printf("Extension channel: 40 [A]\n"); break;
	case 5210:	printf("Extension channel: 42 [A]\n"); break;
	case 5220:	printf("Extension channel: 44 [A]\n"); break;
	case 5230:	printf("Extension channel: 46 [A]\n"); break;
	case 5240:	printf("Extension channel: 48 [A]\n"); break;
	case 5260:	printf("Extension channel: 52 [A]\n"); break;
	case 5280:	printf("Extension channel: 56 [A]\n"); break;

	case 5300:	printf("Extension channel: 60 [A]\n"); break;
	case 5320:	printf("Extension channel: 64 [A]\n"); break;
	case 5745:	printf("Extension channel: 149 [A]\n"); break;
	case 5765:	printf("Extension channel: 153 [A]\n"); break;
	case 5785:	printf("Extension channel: 157 [A]\n"); break;
	case 5805:	printf("Extension channel: 161 [A]\n"); break;

	default:
		printf("Extension channel: %u MHz\n", pField->ExtChannelFrequency);
	}

	printf("Extension channel type:");

	if(pField->ExtChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_OFDM)
	{
		printf(" 802.11g");
	}

	if(pField->ExtChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_CCK)
	{
		printf(" 802.11b");
	}

	if(pField->ExtChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_2GHZ)
	{
		printf(", 2Ghz spectrum");
	}

	if(pField->ExtChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_5GHZ)
	{
		printf(", 5Ghz spectrum");
	}

	if (pField->ExtChannelFlags & PPI_FLD_802_11_COMMON_CHN_FLAGS_PASV_SCAN)
	{
		printf(", passive scan");
	}

	printf("\n");

	printf("RF signal at antenna 0 = ");
	if (pField->DbmAnt0Signal == -128)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%d dBm\n", pField->DbmAnt0Signal);
	}

	printf("RF noise at antenna 0  = ");
	if (pField->DbmAnt0Noise == -128)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%d dBm\n", pField->DbmAnt0Noise);
	}

	printf("RF signal at antenna 1 = ");
	if (pField->DbmAnt1Signal == -128)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%d dBm\n", pField->DbmAnt1Signal);
	}

	printf("RF noise at antenna 1  = ");
	if (pField->DbmAnt1Noise == -128)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%d dBm\n", pField->DbmAnt1Noise);
	}

	printf("RF signal at antenna 2 = ");
	if (pField->DbmAnt2Signal == -128)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%d dBm\n", pField->DbmAnt2Signal);
	}

	printf("RF noise at antenna 2  = ");
	if (pField->DbmAnt2Noise == -128)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%d dBm\n", pField->DbmAnt2Noise);
	}

	printf("RF signal at antenna 3 = ");
	if (pField->DbmAnt3Signal == -128)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%d dBm\n", pField->DbmAnt3Signal);
	}

	printf("RF noise at antenna 3  = ");
	if (pField->DbmAnt3Noise == -128)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%d dBm\n", pField->DbmAnt3Noise);
	}

	printf("Error Vector Magnitude (EVM) for chain 0 = ");
	if (pField->EVM0 == 0)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->EVM0);
	}

	printf("Error Vector Magnitude (EVM) for chain 1 = ");
	if (pField->EVM1 == 0)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->EVM1);
	}

	printf("Error Vector Magnitude (EVM) for chain 2 = ");
	if (pField->EVM2 == 0)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->EVM2);
	}

	printf("Error Vector Magnitude (EVM) for chain 3 = ");
	if (pField->EVM3 == 0)
	{
		printf("<INVALID>\n");
	}
	else
	{
		printf("%u\n", pField->EVM3);
	}
}

