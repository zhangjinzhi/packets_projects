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
 * This program sets the channel the specified airpcap adapter is listening on,
 * and saves it as the default channel for that adapter. In this way, successive
 * accesses to the adapter will use this channel.
 *
 *===========================================================================
 */

#include <windows.h>
#include <stdio.h>
#include <airpcap.h>

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	UINT Channel;

	//
	// Validate input
	//
	if(argc != 3)
	{
		printf("Usage: %s <adaptername> <channel>\n\n", argv[0]);
		return -1;
	}

	//
	// Open the adapter
	//
	Ad = AirpcapOpen(argv[1], Ebuf);
	if(!Ad)
	{
		printf("Error opening the adapter: %s\n", Ebuf);
		return -1;
	}

	//
	// Print the previuos channel
	//
	if(!AirpcapGetDeviceChannel(Ad, &Channel))
	{
		printf("Error getting the channel: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		return -1;
	}

	printf("Old channel was %d \n", Channel);

	//
	// Set the new channel
	//
	Channel = atoi(argv[2]);

	if(!AirpcapSetDeviceChannel(Ad, Channel))
	{
		printf("Error setting the channel: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		return -1;
	}

	//
	// Store the changes in the default adapter configuration
	//
	if(!AirpcapStoreCurConfigAsAdapterDefault(Ad))
	{
		printf("Error saving the configuration to the registry: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		return -1;
	}

	//
	// Success! Close the adapter
	//
	AirpcapClose(Ad);

	printf("Channel %d set succesfully\n", Channel);

	return 0;
}
