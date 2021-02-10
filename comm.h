#pragma once

#include <Windows.h>
#include <Winternl.h>
#include <winnt.h>

#pragma comment(lib, "OneCoreUAP.lib")

#define DEARG_HEADER_MAGIC 0x1337BEEF
#define DEARG_BUFFER_END "\x00\x00"
#define DEARG_NO_KEY 0xFF

typedef enum DEARG_FLAGS {
	DEARG_WRITE = 1,
	DEARG_READ = 2,
	DEARG_READWRITE = 3
} DEARG_FLAGS;

#pragma pack(push, 1)
typedef struct DEARG_HEADER {
	DWORD32 dwMagic;
	DEARG_FLAGS dfFlags;
	DWORD32 dwChecksum;
	UINT16 u16Len;
	BYTE bKey;
} DEARG_HEADER, *PDEARG_HEADER;
#pragma pack(pop)

typedef enum DEARG_STATUS {
	DSERVE_OK,
	DSERVE_ERROR_KEY,
	DSERVE_ERROR_SET, 
	DSERVE_ERROR_GET,
	DSERVE_ERROR_ALLOC,
	DSERVE_ERROR_HEADER,
	DSERVE_INVALID_PARAMS,
	DSERVE_NO_DATA_OUT
} DEARG_STATUS, *PDEARG_STATUS;

BOOL
dearg_init_hdr(
	PDEARG_HEADER pHdr
);

DEARG_STATUS
dearg_serve(
	HANDLE hThread,
	DEARG_FLAGS dFlags,
	PDEARG_HEADER pHdr,
	PBYTE pbBuffer,
	UINT16 u16Len
);

DEARG_STATUS
dearg_read(
	_In_ HANDLE hThread,
	_Out_ PDEARG_HEADER pHdr,
	_Out_ PBYTE pbDataOut
);