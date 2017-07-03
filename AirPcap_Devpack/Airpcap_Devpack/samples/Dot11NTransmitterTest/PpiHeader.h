/*
 * Copyright (c) 2007 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
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

#ifndef __PPI_AIRPCAP_H__
#define __PPI_AIRPCAP_H__

#pragma pack(push, 1)

//
// For some reason, cygnus includes a definition of C_ASSERT
// that doesn't work if you use C_ASSERT in a header file, 
// after each structure definition
//
#ifndef _MSC_VER
#ifdef C_ASSERT
#undef C_ASSERT
#endif //C_ASSERT
#define C_ASSERT(expr) extern char __C_ASSERT__[(expr)?1:-1]
#endif //_MSC_VER

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

C_ASSERT(sizeof(PPI_FIELD_802_11N_MAC_EXTENSION) == 12);

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

C_ASSERT(sizeof(PPI_FIELD_802_11N_MAC_PHY_EXTENSION) == 48);

typedef struct _AIRPCAP_PPI_HEADER
{
	PPI_PACKET_HEADER		PacketHeader;
	PPI_FIELD_HEADER		Dot11CommonFieldHeader;
	PPI_FIELD_802_11_COMMON Dot11CommonHeaderData;
}
AIRPCAP_PPI_HEADER, *PAIRPCAP_PPI_HEADER;

typedef struct _AIRPCAP_PPI_N_HEADER
{
	PPI_PACKET_HEADER		PacketHeader;
	PPI_FIELD_HEADER		Dot11CommonFieldHeader;
	PPI_FIELD_802_11_COMMON Dot11CommonHeaderData;
	PPI_FIELD_HEADER		Dot11nMacPhyExtensionFieldHeader;
	PPI_FIELD_802_11N_MAC_PHY_EXTENSION	Dot11nMacPhyExtensionData;
}
AIRPCAP_PPI_N_HEADER, *PAIRPCAP_PPI_N_HEADER;

C_ASSERT(sizeof(AIRPCAP_PPI_N_HEADER) == 84);

#pragma pack(pop)

#define SIZEOF_PPI_LEGACY_HEADER (sizeof(PPI_PACKET_HEADER) + sizeof(PPI_FIELD_HEADER) + sizeof(PPI_FIELD_802_11_COMMON))
#define SIZEOF_PPI_N_HEADER (sizeof(PPI_PACKET_HEADER) \
							+ sizeof(PPI_FIELD_HEADER) \
							+ sizeof(PPI_FIELD_802_11_COMMON) \
							+ sizeof(PPI_FIELD_HEADER) \
							+ sizeof(PPI_FIELD_802_11N_MAC_PHY_EXTENSION))


#define AIRPCAP_PPI_N_HEADER_INIT(__hdr__) do													\
{																							\
	(__hdr__)->PacketHeader.PphVersion				= PPH_PH_VERSION;						\
	(__hdr__)->PacketHeader.PphFlags				= 0;									\
	(__hdr__)->PacketHeader.PphLength				= SIZEOF_PPI_N_HEADER;				\
	(__hdr__)->Dot11CommonFieldHeader.PfhType		= PPI_FIELD_TYPE_802_11_COMMON;			\
	(__hdr__)->Dot11CommonFieldHeader.PfhLength		= sizeof(PPI_FIELD_802_11_COMMON);		\
	(__hdr__)->Dot11nMacPhyExtensionFieldHeader.PfhType		= PPI_FIELD_TYPE_802_11N_MAC_PHY_EXTENSION;			\
	(__hdr__)->Dot11nMacPhyExtensionFieldHeader.PfhLength		= sizeof(PPI_FIELD_802_11N_MAC_PHY_EXTENSION);		\
}while(FALSE)

#define AIRPCAP_PPI_HEADER_INIT(__hdr__) do													\
{																							\
	(__hdr__)->PacketHeader.PphVersion				= PPH_PH_VERSION;						\
	(__hdr__)->PacketHeader.PphFlags				= 0;									\
	(__hdr__)->PacketHeader.PphLength				= SIZEOF_PPI_LEGACY_HEADER;				\
	(__hdr__)->Dot11CommonFieldHeader.PfhType		= PPI_FIELD_TYPE_802_11_COMMON;			\
	(__hdr__)->Dot11CommonFieldHeader.PfhLength		= sizeof(PPI_FIELD_802_11_COMMON);		\
}while(FALSE)

#endif //__PPI_AIRPCAP_H__
