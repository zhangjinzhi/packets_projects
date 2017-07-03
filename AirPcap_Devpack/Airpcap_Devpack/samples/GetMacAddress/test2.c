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
 *===========================================================================*
 *
 * This program open an adapter, retrieves its mac address, and prints it on 
 * the screen.
 *
 *===========================================================================
 */

#include <windows.h>
#include <stdio.h>
#include <airpcap.h>

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
int main()
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
   	AirpcapDeviceDescription *Desc, *tDesc;
	UINT i = 0;
	AirpcapMacAddress MacAddress;

	//
	// Get the list of adapters
	//
	if(AirpcapGetDeviceList(&Desc, Ebuf) == -1)
	{
		printf("Unable to get the list of Adapters: %s\n", Ebuf);
		return -1;
	}

	//
	// Make sure that the device list is valid
	//
	if(Desc == NULL)
	{
		printf("No interfaces found! Make sure the airpcap software is installed and your adapter is properly plugged in.\n");
		return -1;
	}

	//
	// Scan through the list of adapters 
	//
	for(tDesc = Desc; tDesc; tDesc = tDesc->next)
	{
		//
		// Print basic info
		//
		printf("%u) %s (%s)\n",
			++i,
			tDesc->Name,
			tDesc->Description);
		
		//
		// Try to open the adapter
		//
		Ad = AirpcapOpen(tDesc->Name, Ebuf);
		if(!Ad)
		{
			printf("Error opening the adapter: %s\n", Ebuf);
			return -1;
		}

		//
		// Get the MAC address
		//
		if(!AirpcapGetMacAddress(Ad, &MacAddress))
		{
			printf("Error retrieving the MAC address: %s\n", AirpcapGetLastError(Ad));
			return -1;
		}

		//
		// Print the address
		//
		printf("\t\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			MacAddress.Address[0],
			MacAddress.Address[1],
			MacAddress.Address[2],
			MacAddress.Address[3],
			MacAddress.Address[4],
			MacAddress.Address[5]);

		//
		// Success! Close the adapter
		//
		AirpcapClose(Ad);
	}

	return 1;
}
