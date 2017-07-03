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


#ifndef __PPI_HEADER_H__
#define __PPI_HEADER_H__

#pragma pack(push, 1)

#define PPH_PH_FLAG_PADDING	((UCHAR)0x01)
#define PPH_PH_VERSION		((UCHAR)0x00)

typedef struct _PPI_PACKET_HEADER
{
	UCHAR	PphVersion;
	UCHAR	PphFlags;
	USHORT	PphLength;
	ULONG	PphDlt;
}
	PPI_PACKET_HEADER, *PPPI_PACKET_HEADER;

typedef struct _PPI_FIELD_HEADER
{
	USHORT PfhType;
	USHORT PfhLength;
}
	PPI_FIELD_HEADER, *PPPI_FIELD_HEADER;

//
// Field 2: 802.11-Common. Common (pre-n and .11n) radio information
//
#define		PPI_FIELD_TYPE_802_11_COMMON		((USHORT)0x02)

#define		PPI_FLD_802_11_COMMON_FLAG_FCS_PRESENT	((USHORT)0x0001)
#define		PPI_FLD_802_11_COMMON_FLAG_TSFT_MS		((USHORT)0x0002)
#define		PPI_FLD_802_11_COMMON_FLAG_WRONG_FCS	((USHORT)0x0004)
#define		PPI_FLD_802_11_COMMON_FLAG_PHY_ERROR	((USHORT)0x0008)

#define		PPI_FLD_802_11_COMMON_CHN_FLAGS_TURBO	((USHORT)0x0010)
#define		PPI_FLD_802_11_COMMON_CHN_FLAGS_CCK		((USHORT)0x0020)
#define		PPI_FLD_802_11_COMMON_CHN_FLAGS_OFDM	((USHORT)0x0040)
#define		PPI_FLD_802_11_COMMON_CHN_FLAGS_2GHZ	((USHORT)0x0080)
#define		PPI_FLD_802_11_COMMON_CHN_FLAGS_5GHZ	((USHORT)0x0100)
#define		PPI_FLD_802_11_COMMON_CHN_FLAGS_PASV_SCAN		((USHORT)0x0200)
#define		PPI_FLD_802_11_COMMON_CHN_FLAGS_DYN_CCK_OFDM	((USHORT)0x0400)
#define		PPI_FLD_802_11_COMMON_CHN_FLAGS_GFSK	((USHORT)0x0800)

typedef struct _PPI_FIELD_802_11_COMMON
{
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
	PPI_FIELD_802_11_COMMON, *PPPI_FIELD_802_11_COMMON;

#define		PPI_FIELD_TYPE_802_11N_MAC_EXTENSION	((UCHAR)0x03)

#define PPI_FLD_802_11N_MAC_EXT_FLAG_GREENFIELD				((ULONG)0x00000001)
#define PPI_FLD_802_11N_MAC_EXT_FLAG_HT20_40   				((ULONG)0x00000002)
#define PPI_FLD_802_11N_MAC_EXT_FLAG_RX_GUARD_INTERVAL		((ULONG)0x00000004)
#define PPI_FLD_802_11N_MAC_EXT_FLAG_DUPLICATE_RX			((ULONG)0x00000008)
#define PPI_FLD_802_11N_MAC_EXT_FLAG_AGGREGATE				((ULONG)0x00000010)
#define PPI_FLD_802_11N_MAC_EXT_FLAG_MORE_AGGREGATES		((ULONG)0x00000020)
#define PPI_FLD_802_11N_MAC_EXT_FLAG_DELIMITER_CRC_ERROR_AFTER ((ULONG)0x00000040)

typedef struct _PPI_FIELD_802_11N_MAC_EXTENSION
{
	ULONG		Flags;
	ULONG		AMpduId;
	UCHAR		NumDelimiters;
	UCHAR		Reserved[3];

}
	PPI_FIELD_802_11N_MAC_EXTENSION, *PPPI_FIELD_802_11N_MAC_EXTENSION;

#define		PPI_FIELD_TYPE_802_11N_MAC_PHY_EXTENSION	((UCHAR)0x04)

typedef struct _PPI_FIELD_802_11N_MAC_PHY_EXTENSION
{
	ULONG		Flags;
	ULONG		AMpduId;
	UCHAR		NumDelimiters;
	UCHAR		MCS;
	UCHAR		NumStreams;
	UCHAR		RssiCombined;
	UCHAR		RssiAnt0Ctl;
	UCHAR		RssiAnt1Ctl;
	UCHAR		RssiAnt2Ctl;
	UCHAR		RssiAnt3Ctl;
	UCHAR		RssiAnt0Ext;
	UCHAR		RssiAnt1Ext;
	UCHAR		RssiAnt2Ext;
	UCHAR		RssiAnt3Ext;
	USHORT		ExtChannelFrequency;
	USHORT		ExtChannelFlags;
	CHAR		DbmAnt0Signal;
	CHAR		DbmAnt0Noise;
	CHAR		DbmAnt1Signal;
	CHAR		DbmAnt1Noise;
	CHAR		DbmAnt2Signal;
	CHAR		DbmAnt2Noise;
	CHAR		DbmAnt3Signal;
	CHAR		DbmAnt3Noise;
	ULONG		EVM0;
	ULONG		EVM1;
	ULONG		EVM2;
	ULONG		EVM3;
}
	PPI_FIELD_802_11N_MAC_PHY_EXTENSION, *PPPI_FIELD_802_11N_MAC_PHY_EXTENSION;

//
// Here we have the definition of the header that we use internally in the driver
//

typedef struct _ATH_PPI_HEADER
{
	PPI_PACKET_HEADER		PacketHeader;
	PPI_FIELD_HEADER		Dot11CommonFieldHeader;
	PPI_FIELD_802_11_COMMON Dot11CommonHeaderData;
	PPI_FIELD_HEADER		Dot11nMacExtensionFieldHeader;
	union
	{
		PPI_FIELD_802_11N_MAC_EXTENSION	Dot11nMacExtensionData;
		PPI_FIELD_802_11N_MAC_PHY_EXTENSION	Dot11nMacPhyExtensionData;
	};
}

	ATH_PPI_HEADER, *PATH_PPI_HEADER;

#pragma pack(pop)

#define SIZEOF_PPI_LEGACY_HEADER (sizeof(PPI_PACKET_HEADER) + sizeof(PPI_FIELD_HEADER) + sizeof(PPI_FIELD_802_11_COMMON))
#define SIZEOF_PPI_11N_MAC_HEADER (				\
	sizeof(PPI_PACKET_HEADER)				\
	+ sizeof(PPI_FIELD_HEADER)				\
	+ sizeof(PPI_FIELD_802_11_COMMON)	\
	+ sizeof(PPI_FIELD_HEADER)				\
	+ sizeof(PPI_FIELD_802_11N_MAC_EXTENSION)\
	)

#define SIZEOF_PPI_11N_MAC_PHY_HEADER (				\
	sizeof(PPI_PACKET_HEADER)				\
	+ sizeof(PPI_FIELD_HEADER)				\
	+ sizeof(PPI_FIELD_802_11_COMMON)	\
	+ sizeof(PPI_FIELD_HEADER)				\
	+ sizeof(PPI_FIELD_802_11N_MAC_PHY_EXTENSION)\
	)

#define ATH_PPI_HEADER_INIT_LEGACY(__hdr__) do														\
{																								\
	(__hdr__)->PacketHeader.PphVersion				= PPH_PH_VERSION;							\
	(__hdr__)->PacketHeader.PphFlags				= 0;										\
	(__hdr__)->PacketHeader.PphLength				= SIZEOF_PPI_LEGACY_HEADER;				\
	(__hdr__)->Dot11CommonFieldHeader.PfhType		= PPI_FIELD_TYPE_802_11_COMMON;			\
	(__hdr__)->Dot11CommonFieldHeader.PfhLength		= sizeof(PPI_FIELD_802_11_COMMON);		\
}while(FALSE)

#define ATH_PPI_HEADER_INIT_11N_MAC(__hdr__) do														\
{																								\
	(__hdr__)->PacketHeader.PphVersion				= PPH_PH_VERSION;							\
	(__hdr__)->PacketHeader.PphFlags				= 0;										\
	(__hdr__)->PacketHeader.PphLength				= SIZEOF_PPI_11N_MAC_HEADER;				\
	(__hdr__)->Dot11CommonFieldHeader.PfhType		= PPI_FIELD_TYPE_802_11_COMMON;			\
	(__hdr__)->Dot11CommonFieldHeader.PfhLength		= sizeof(PPI_FIELD_802_11_COMMON);		\
	(__hdr__)->Dot11nMacExtensionFieldHeader.PfhType	= PPI_FIELD_TYPE_802_11N_MAC_EXTENSION;	\
	(__hdr__)->Dot11nMacExtensionFieldHeader.PfhLength= sizeof(PPI_FIELD_802_11N_MAC_EXTENSION);	\
}while(FALSE)

#define ATH_PPI_HEADER_INIT_11N_MAC_PHY(__hdr__) do														\
{																								\
	(__hdr__)->PacketHeader.PphVersion				= PPH_PH_VERSION;							\
	(__hdr__)->PacketHeader.PphFlags				= 0;										\
	(__hdr__)->PacketHeader.PphLength				= SIZEOF_PPI_11N_MAC_PHY_HEADER;				\
	(__hdr__)->Dot11CommonFieldHeader.PfhType		= PPI_FIELD_TYPE_802_11_COMMON;			\
	(__hdr__)->Dot11CommonFieldHeader.PfhLength		= sizeof(PPI_FIELD_802_11_COMMON);		\
	(__hdr__)->Dot11nMacExtensionFieldHeader.PfhType	= PPI_FIELD_TYPE_802_11N_MAC_PHY_EXTENSION;	\
	(__hdr__)->Dot11nMacExtensionFieldHeader.PfhLength= sizeof(PPI_FIELD_802_11N_MAC_PHY_EXTENSION);	\
}while(FALSE)



#endif //__PPI_HEADER_H__
