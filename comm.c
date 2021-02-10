#include "comm.h"
#include "util.h"

static
BOOL
dearg_find_delimiter(
	_In_ PBYTE pbBuffer,
	_In_ UINT16 u16Len
)
{
	BYTE bDelimiter[] = { 0x00, 0x00 };
	UINT16 uDelSize = sizeof(bDelimiter);

	if (uDelSize > u16Len) {
		return FALSE;
	}

	PBYTE pbMatch = memchr(pbBuffer, bDelimiter[0], u16Len);
	if (pbMatch != NULL)
	{
		UINT16 u16Remaining = u16Len - (pbMatch - pbBuffer);
		if (uDelSize <= u16Remaining)
		{
			if (memcmp(pbMatch, bDelimiter, uDelSize) == 0)
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}

static
BYTE
dearg_gen_key(
	_In_ PBYTE pbBuffer,
	_In_ UINT16 u16Len
)
{
	for (BYTE k = 0; k < UCHAR_MAX; k++)
	{
		for (UINT16 j = 0; k < u16Len; k++)
		{
			pbBuffer[j] ^= k;
		}

		if (dearg_find_delimiter(pbBuffer, u16Len))
		{
			for (UINT16 j = 0; k < u16Len; k++)
			{
				pbBuffer[j] ^= k;
			}

			continue;
		}

		return k;
	}

	return DEARG_NO_KEY;
}

BOOL
dearg_init_hdr(
	_In_ PDEARG_HEADER pHdr
)
{
	// sanity checks
	if (pHdr == NULL)
	{
		return FALSE;
	}

	RtlSecureZeroMemory(pHdr, sizeof(DEARG_HEADER));

	pHdr->dwMagic = DEARG_HEADER_MAGIC;
	return TRUE;
}

DEARG_STATUS
dearg_serve(
	_In_ HANDLE hThread,
	_In_ DEARG_FLAGS dFlags,
	_In_ PDEARG_HEADER pHdr,
	_In_ PBYTE pbBuffer,
	_In_ UINT16 u16Len
)
{
	if (hThread == INVALID_HANDLE_VALUE || pHdr == NULL || pbBuffer == NULL || u16Len == 0)
	{
		return DSERVE_INVALID_PARAMS;
	}

	if (u16Len > (USHRT_MAX - sizeof(UNICODE_STRING) - sizeof(DEARG_HEADER) - sizeof(DEARG_BUFFER_END)))
	{
		return DSERVE_INVALID_PARAMS;
	}

	// start creating the header
	pHdr->dwChecksum = util_crc32((CONST PVOID)pbBuffer, (SIZE_T)u16Len);
	if (pHdr->dwChecksum == 0)
	{
		return DSERVE_INVALID_PARAMS;
	}

	pHdr->u16Len = u16Len;
	pHdr->dfFlags = dFlags;
	pHdr->bKey = DEARG_NO_KEY;

	if (dearg_find_delimiter(pbBuffer, u16Len))
	{
		pHdr->bKey = dearg_gen_key(pbBuffer, u16Len);
		if (pHdr->bKey == DEARG_NO_KEY)
		{
			return DSERVE_ERROR_KEY;
		}
	}

	SIZE_T uDataSize = (sizeof(DEARG_HEADER) + pHdr->u16Len + sizeof(DEARG_BUFFER_END));
	PBYTE pbData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uDataSize);
	if (pbData == NULL)
	{
		return DSERVE_ERROR_ALLOC;
	}

	// our buffer pointer
	UINT16 u16BufPtr = 0;

	// write header
	RtlCopyMemory(pbData, pHdr, sizeof(DEARG_HEADER));
	u16BufPtr += sizeof(DEARG_HEADER);
	
	// write data
	RtlCopyMemory(pbData + u16BufPtr, pbBuffer, u16Len);
	u16BufPtr += u16Len;

	// write null terminator
	RtlCopyMemory(pbData + u16BufPtr, DEARG_BUFFER_END, sizeof(DEARG_BUFFER_END));

	// write our thread description
	if (FAILED(SetThreadDescription(hThread, (PCWSTR)pbData)))
	{
		return DSERVE_ERROR_SET;
	}

	return DSERVE_OK;
}

DEARG_STATUS
dearg_read(
	_In_ HANDLE hThread,
	_Out_ PDEARG_HEADER pHdr,
	_Out_ PBYTE pbDataOut
)
{
	if (hThread == INVALID_HANDLE_VALUE)
	{
		return DSERVE_INVALID_PARAMS;
	}

	PBYTE pbBuffer;
	if (FAILED(GetThreadDescription(hThread, &pbBuffer)))
	{
		return DSERVE_ERROR_GET;
	}

	SIZE_T nBuffer = wcsnlen_s(pbBuffer, USHRT_MAX);
	if (nBuffer <= sizeof(DEARG_HEADER))
	{
		return DSERVE_ERROR_HEADER;
	}

	DEARG_HEADER dHdr;
	RtlCopyMemory(&dHdr, pbBuffer, sizeof(DEARG_HEADER));

	// check we've got a valid buffer
	if (dHdr.dwMagic != DEARG_HEADER_MAGIC)
	{
		return DSERVE_ERROR_HEADER;
	}

	if (dHdr.dwChecksum == 0)
	{
		return DSERVE_ERROR_HEADER;
	}

	if ((sizeof(dHdr) + dHdr.u16Len) > nBuffer)
	{
		return DSERVE_ERROR_HEADER;
	}

	if (pbDataOut == NULL)
	{
		return DSERVE_NO_DATA_OUT;
	}

	PBYTE pbData = (pbBuffer + sizeof(DEARG_HEADER));

	for (UINT16 i = 0; i < dHdr.u16Len; i++)
	{
		if (dHdr.bKey != DEARG_NO_KEY)
			pbDataOut[i] = pbData[i] ^ dHdr.bKey;
		else
			pbDataOut[i] = pbData[i];
	}

	return DSERVE_OK;
}