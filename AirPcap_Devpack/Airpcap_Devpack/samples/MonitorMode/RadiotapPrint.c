/*-
 * Copyright (c) 2005, CACE Technologies.
 * Portions Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of CACE Technologies or David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
 * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This code is a stripped-down, self-contained version of the tcpdump 
 * radiotap decoder, written by David Young
 *
 */

#include <windows.h>
#include <stdio.h>
#include "ieee80211_radiotap.h"

struct cpack_state 
{
	UCHAR					*c_buf;
	UCHAR					*c_next;
	ULONG					 c_len;
};

//////////////////////////////////////////////////////////////////////
// Macros and functions to extract values from the radiotap header
//////////////////////////////////////////////////////////////////////
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)
#define	BIT(n)	(1 << n)
#define	IS_EXTENDED(__p)	\
	    (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

#define EXTRACT_LE_8BITS(p) (*(p))
#define EXTRACT_LE_16BITS(p) \
	((USHORT)((USHORT)*((const UCHAR *)(p) + 1) << 8 | \
		     (USHORT)*((const UCHAR *)(p) + 0)))
#define EXTRACT_LE_32BITS(p) \
	((ULONG)((ULONG)*((const UCHAR *)(p) + 3) << 24 | \
		     (ULONG)*((const UCHAR *)(p) + 2) << 16 | \
		     (ULONG)*((const UCHAR *)(p) + 1) << 8 | \
		     (ULONG)*((const UCHAR *)(p) + 0)))
#define EXTRACT_LE_64BITS(p) \
	((ULONGLONG)((ULONGLONG)*((const UCHAR *)(p) + 7) << 56 | \
		     (ULONGLONG)*((const UCHAR *)(p) + 6) << 48 | \
		     (ULONGLONG)*((const UCHAR *)(p) + 5) << 40 | \
		     (ULONGLONG)*((const UCHAR *)(p) + 4) << 32 | \
	             (ULONGLONG)*((const UCHAR *)(p) + 3) << 24 | \
		     (ULONGLONG)*((const UCHAR *)(p) + 2) << 16 | \
		     (ULONGLONG)*((const UCHAR *)(p) + 1) << 8 | \
		     (ULONGLONG)*((const UCHAR *)(p) + 0)))

static UCHAR *
cpack_next_boundary(UCHAR *buf, UCHAR *p, size_t alignment)
{
	size_t misalignment = (size_t)(p - buf) % alignment;

	if (misalignment == 0)
		return p;

	return p + (alignment - misalignment);
}

static UCHAR *
cpack_align_and_reserve(struct cpack_state *cs, size_t wordsize)
{
	UCHAR *next;

	// Ensure alignment.
	next = cpack_next_boundary(cs->c_buf, cs->c_next, wordsize);

	// Too little space for wordsize bytes?
	if (next - cs->c_buf + wordsize > cs->c_len)
		return NULL;

	return next;
}

int
cpack_init(struct cpack_state *cs, UCHAR *buf, size_t buflen)
{
	memset(cs, 0, sizeof(*cs));

	cs->c_buf = buf;
	cs->c_len = buflen;
	cs->c_next = cs->c_buf;

	return 0;
}

int
cpack_uint64(struct cpack_state *cs, ULONGLONG *u)
{
	UCHAR *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_64BITS(next);

	// Move pointer past the ULONGLONG.
	cs->c_next = next + sizeof(*u);
	return 0;
}

int
cpack_uint32(struct cpack_state *cs, ULONG *u)
{
	UCHAR *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_32BITS(next);

	// Move pointer past the ULONG.
	cs->c_next = next + sizeof(*u);
	return 0;
}

int
cpack_uint16(struct cpack_state *cs, USHORT *u)
{
	UCHAR *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_16BITS(next);

	// Move pointer past the USHORT.
	cs->c_next = next + sizeof(*u);
	return 0;
}

int
cpack_uint8(struct cpack_state *cs, UCHAR *u)
{
	// No space left?
	if ((size_t)(cs->c_next - cs->c_buf) >= cs->c_len)
		return -1;

	*u = *cs->c_next;

	// Move pointer past the UCHAR.
	cs->c_next++;
	return 0;
}

#define cpack_int8(__s, __p)	cpack_uint8((__s),  (UCHAR*)(__p))
#define cpack_int16(__s, __p)	cpack_uint16((__s), (USHORT*)(__p))
#define cpack_int32(__s, __p)	cpack_uint32((__s), (ULONG*)(__p))
#define cpack_int64(__s, __p)	cpack_uint64((__s), (ULONGLONG*)(__p))


//////////////////////////////////////////////////////////////////////
// Print one of the fields in the radiotap header.
// This is the function that needs to be changed to support additional 
// radiotap fields.
//////////////////////////////////////////////////////////////////////
UINT PrintRadiotapField(struct cpack_state *s, ULONG bit)
{
	union 
	{
		CHAR		i8;
		UCHAR		u8;
		SHORT		i16;
		USHORT		u16;
		ULONG		u32;
		ULONGLONG	u64;
	} u, u2;
	int rc;

	//
	// Extract the field in the u and u2 variables
	//
	switch (bit) 
	{
	case IEEE80211_RADIOTAP_FLAGS:
	case IEEE80211_RADIOTAP_RATE:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_ANTENNA:
		rc = cpack_uint8(s, &u.u8);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		rc = cpack_int8(s, &u.i8);
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
		rc = cpack_uint16(s, &u.u16);
		if (rc != 0)
			break;
		rc = cpack_uint16(s, &u2.u16);
		break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
		rc = cpack_uint16(s, &u.u16);
		break;
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
		rc = cpack_uint8(s, &u.u8);
		break;
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
		rc = cpack_int8(s, &u.i8);
		break;
	case IEEE80211_RADIOTAP_TSFT:
		rc = cpack_uint64(s, &u.u64);
		break;
	case IEEE80211_RADIOTAP_FCS:
		rc = cpack_uint32(s, &u.u32);
		break;
	default:
		// this bit indicates a field whose
		// size we do not know, so we cannot
		// proceed.
		printf("Unknown field 0x%08x", bit);
		return -1;
	}

	if(rc != 0) 
	{
		//
		// Unaligned field
		//
		printf("Wrong alignment");
		return rc;
	}

	//
	// Print the value
	//
	switch (bit) 
	{
	case IEEE80211_RADIOTAP_CHANNEL:
		printf("Channel frequency: %u MHz\n", u.u16);
		
		switch(u.u16) 
		{
		case 2412:
			printf("Channel number: 1\n");
			break;
		case 2417:
			printf("Channel number: 2\n");
			break;
		case 2422:
			printf("Channel number: 3\n");
			break;
		case 2427:
			printf("Channel number: 4\n");
			break;
		case 2432:
			printf("Channel number: 5\n");
			break;
		case 2437:
			printf("Channel number: 6\n");
			break;
		case 2442:
			printf("Channel number: 7\n");
			break;
		case 2447:
			printf("Channel number: 8\n");
			break;
		case 2452:
			printf("Channel number: 9\n");
			break;
		case 2457:
			printf("Channel number: 10\n");
			break;
		case 2462:
			printf("Channel number: 11\n");
			break;
		case 2467:
			printf("Channel number: 12\n");
			break;
		case 2472:
			printf("Channel number: 13\n");
			break;
		case 2484:
			printf("Channel number: 14\n");
			break;
		};
		
		printf("Channel type:");

		if(u2.u16 & IEEE80211_CHAN_OFDM)
		{
			printf(" 802.11g", u2.u16);
		}
		else
		{
			printf(" 802.11b", u2.u16);
		}

		if(u2.u16 & IEEE80211_CHAN_2GHZ)
		{
			printf(", 2Ghz spectrum", u2.u16);
		}

		if(u2.u16 & IEEE80211_CHAN_5GHZ)
		{
			printf(", 5Ghz spectrum", u2.u16);
		}

		printf("\n");
		break;
	case IEEE80211_RADIOTAP_FHSS:
		printf("channel hoping set %d, pattern %d ", u.u16 & 0xff, (u.u16 >> 8) & 0xff);
		break;
	case IEEE80211_RADIOTAP_RATE:
		printf("Rate: %2.1f Mb/s\n", (.5 * ((u.u8) & 0x7f)));
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		printf("Signal Strength: %ddB\n", u.i8);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		printf("Noise level: %ddB", u.i8);
		break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
		printf("Signal Strength: %ddB\n", u.u8);
		break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
		printf("Noise level: %ddB", u.u8);
		break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
		printf("Signal Quality: %u\n", u.u16);
		break;
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
		printf("Tx power: %d\n", -(int)u.u16);
		break;
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
		printf("Tx power: %ddB\n", -(int)u.u8);
		break;
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
		printf("Tx power: %ddBm\n", u.i8);
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		if(u.u8 & IEEE80211_RADIOTAP_F_CFP)
		{
			printf("cfp ");
		}
		if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE)
		{
			printf("short preamble ");
		}
		if (u.u8 & IEEE80211_RADIOTAP_F_FRAG)
		{
			printf("fragmented ");
		}
		if (u.u8 & IEEE80211_RADIOTAP_F_FCS)
		{
			printf("Frame includes FCS\n");
		}
		else
		{
			printf("Frame doesn't include FCS\n");
		}

		break;
	case IEEE80211_RADIOTAP_ANTENNA:
		printf("antenna n. %d\n", u.u8);
		break;
	case IEEE80211_RADIOTAP_TSFT:
		printf("heardware timestamp: %I64uus\n", u.u64);
		break;
	case IEEE80211_RADIOTAP_FCS:
		printf("Frame Check Sequence: 0x%.4x\n", htonl(u.u32));
		break;
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////
// This function decodes and prints the radiotap header
//
// Paramaters:
//	p		pointer to the packet data
//  caplen	length of the captured packet data
//
// Return Value:
//  Length of the radiotap header
//////////////////////////////////////////////////////////////////////
ULONG RadiotapPrint(const u_char *p, ULONG caplen)
{
	struct cpack_state cpacker;
	struct ieee80211_radiotap_header *hdr;
	ULONG present, next_present;
	ULONG *presentp, *last_presentp;
	enum ieee80211_radiotap_type bit;
	int bit0;
	const u_char *iter;
	ULONG len;

	//
	// Sanity checks
	//
	if (caplen < sizeof(*hdr)) 
	{
		// Packet smaller than the radiotap fixed header
		return 0;
	}

	hdr = (struct ieee80211_radiotap_header *)p;

	len = EXTRACT_LE_16BITS(&hdr->it_len);

	if(caplen < len) 
	{
		// Packet smaller than the radiotap header
		return 0;
	}

	for (last_presentp = &hdr->it_present;
	     IS_EXTENDED(last_presentp) &&
	     (u_char*)(last_presentp + 1) <= p + len;
	     last_presentp++);

	// are there more bitmap extensions than bytes in header?
	if(IS_EXTENDED(last_presentp)) 
	{
		return 0;
	}

	iter = (u_char*)(last_presentp + 1);

	if (cpack_init(&cpacker, (UCHAR*)iter, len - (iter - p)) != 0) 
	{
		return 0;
	}

	//
	// Scan the fields, and print each of them
	//
	for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp; presentp++, bit0 += 32) 
	{
		for (present = EXTRACT_LE_32BITS(presentp); present; present = next_present) 
		{
			// clear the least significant bit that is set
			next_present = present & (present - 1);

			// extract the least significant bit that is set
			bit = (enum ieee80211_radiotap_type)(bit0 + BITNO_32(present ^ next_present));
			
			// print the field
			if(PrintRadiotapField(&cpacker, bit) != 0)
			{
				//
				// Error decoding the field, exit from the loop
				//
				return len;
			}
		}
	}

	return len;
}
