#include "util.h"

typedef ULONG (NTAPI *xRtlCrc32)(
    _In_reads_bytes_(Size) const void* Buffer,
    _In_ size_t Size,
    _In_ DWORD InitialCrc
);

static xRtlCrc32 fnRtlCrc32 = NULL;

DWORD32 
util_crc32(
    _In_ PBYTE pbBuffer,
    _In_ SIZE_T uLen
)
{
    if (fnRtlCrc32 == NULL)
    {
        HMODULE hNtMod = GetModuleHandleW(L"ntdll.dll");
        if (hNtMod == NULL)
        {
            return 0;
        }

        FARPROC fpCrc32Addr = GetProcAddress(hNtMod, "RtlCrc32");
        if (fpCrc32Addr == NULL)
        {
            return 0;
        }

        fnRtlCrc32 = (xRtlCrc32)fpCrc32Addr;
    }

    return fnRtlCrc32(pbBuffer, uLen, 0);
}