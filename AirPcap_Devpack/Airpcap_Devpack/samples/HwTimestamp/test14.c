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
 *===========================================================================*
 *
 * Read the Hardware counter used to timestamp packets
 *
 *===========================================================================
 */

#define WAIT_INTERVAL_MS 1000 

#define _CRT_SECURE_NO_DEPRECATE
#include <windows.h>
#include <stdio.h>
#include <airpcap.h>
#include <conio.h>

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
int main()
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	INT i, Inum;
	AirpcapDeviceDescription *AllDevs, *TmpDev;

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

	while(!_kbhit())
	{
		AirpcapDeviceTimestamp timestamp;

		if (AirpcapGetDeviceTimestamp(Ad, &timestamp) == FALSE)
		{
			printf("Error reading the hw counter: %s\n", AirpcapGetLastError(Ad));
		}
		else
		{
			printf("------------------------------------------\n");
			printf("Software timestamp (before) = %I64u\n", timestamp.SoftwareTimestampBefore);
			printf("Device timestamp            = %I64u\n", timestamp.DeviceTimestamp);
			printf("Software timestamp (after)  = %I64u\n", timestamp.SoftwareTimestampAfter);
			printf("------------------------------------------\n");
		}

		Sleep(1000);
	}

	AirpcapClose(Ad);

	return 0;
}
