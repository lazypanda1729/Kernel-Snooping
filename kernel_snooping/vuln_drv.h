#pragma once

#include "main_stuff.h"

static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;

static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

struct RTCORE64_MEMORY_READ
{
	BYTE Pad0[8];

	DWORD64 Address;

	BYTE Pad1[8];

	DWORD ReadSize;

	DWORD Value;

	BYTE Pad3[16];
};

struct RTCORE64_MEMORY_WRITE
{
	BYTE Pad0[8];

	DWORD64 Address;

	BYTE Pad1[8];

	DWORD ReadSize;

	DWORD Value;

	BYTE Pad3[16];
};

DWORD ReadMemoryPrimitive(HANDLE device, DWORD size, DWORD64 address);

DWORD ReadMemoryDWORD(HANDLE device, DWORD64 address);

DWORD64 ReadMemoryDWORD64(HANDLE device, DWORD64 address);

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value);

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value);