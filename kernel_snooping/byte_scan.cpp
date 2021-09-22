#include "byte_scan.h"


DWORD64 get_PspSetCreateProcessNotifyRoutine(HANDLE device, DWORD64 PsSetCreateProcessNotifyRoutine_address)
{

	int count = 0;

	// Locate JMP/CALL

	while (count != MAX_SEARCH_LEN)
	{

		BYTE byte = (BYTE)ReadMemoryPrimitive(device, 1, PsSetCreateProcessNotifyRoutine_address);

		if (byte == 0xE8 || byte == 0xE9)
		{
			break;
		}

		PsSetCreateProcessNotifyRoutine_address++;

		count++;
	}

	DWORD64 rip_address = PsSetCreateProcessNotifyRoutine_address;

	DWORD64 offset = 0;

	// Get the offset bytes
	for (int i = 4, k = 24; i > 0; i--, k = k - 8)
	{

		BYTE offset_byte = (BYTE)ReadMemoryPrimitive(device, 1, PsSetCreateProcessNotifyRoutine_address + i);

		offset = ((DWORD)offset_byte << k) + offset;

	}

	// check sign bit
	if ((offset & 0x00000000ff000000) == 0x00000000ff000000)
		offset = offset | 0xffffffff00000000; // sign extend in case of a negative offset

		// Calculate the address of PspSetCreateProcessNotifyRoutine
	DWORD64 PspSetCreateProcessNotifyRoutine_address = rip_address + offset + 5;

	return PspSetCreateProcessNotifyRoutine_address;

}


DWORD64 get_PspCreateProcessNotifyRoutine_arr(HANDLE device, DWORD64 PspSetCreateProcessNotifyRoutine_address)
{

	// Locate LEA instruction
	// First 2 bytes: 0x4C , 0x8D
	// the third byte is taken from the set: 0x05 , 0x0D , 0x15 , 0x1D , 0x25 , 0x2D , 0x35 , 0x3D

	int count = 0;

	while (count != MAX_SEARCH_LEN)
	{

		DWORD bytes = (DWORD)ReadMemoryPrimitive(device, 4, PspSetCreateProcessNotifyRoutine_address);

		if (   ((bytes & (0x00ffffff)) == 0x00058D4C)  // 4C8D05 i.e. r8
			|| ((bytes & (0x00ffffff)) == 0x000D8D4C)  // 4C8D0D i.e. r9
			|| ((bytes & (0x00ffffff)) == 0x00158D4C)  // 4C8D15 i.e. r10
			|| ((bytes & (0x00ffffff)) == 0x001D8D4C)  // 4C8D1D i.e. r11
			|| ((bytes & (0x00ffffff)) == 0x00258D4C)  // 4C8D25 i.e. r12
			|| ((bytes & (0x00ffffff)) == 0x002D8D4C)  // 4C8D2D i.e. r13
			|| ((bytes & (0x00ffffff)) == 0x00358D4C)  // 4C8D35 i.e. r14
			|| ((bytes & (0x00ffffff)) == 0x003D8D4C)) // 4C8D3D i.e. r15 
		{

			break;

		}

		PspSetCreateProcessNotifyRoutine_address++;

		count++;
	}

	DWORD64 rip_address = PspSetCreateProcessNotifyRoutine_address;

	DWORD64 offset = 0;

	// get the offset bytes

	for (int i = 6, k = 24; i > 2; i--, k = k - 8)
	{

		BYTE offset_byte = (BYTE)ReadMemoryPrimitive(device, 1, PspSetCreateProcessNotifyRoutine_address + i);

		offset = ((DWORD)offset_byte << k) + offset;

	}

	// check sign bit
	if ((offset & 0x00000000ff000000) == 0x00000000ff000000)
		offset = offset | 0xffffffff00000000; // sign extend in case of a negative offset


	// Calculate the address of PspSetCreateProcessNotifyRoutine
	DWORD64 PspCreateProcessNotifyRoutine_array_address = rip_address + offset + 7;

	return PspCreateProcessNotifyRoutine_array_address;

}

