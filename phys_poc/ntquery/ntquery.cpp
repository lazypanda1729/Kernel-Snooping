#include <iostream>
#include <windows.h>

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


typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NtQuerySystemInformation_t resolve(void)
{

	HMODULE ntdllHandle = GetModuleHandleW(L"ntdll.dll");

	NtQuerySystemInformation_t func = (NtQuerySystemInformation_t)GetProcAddress(ntdllHandle, "NtQuerySystemInformation");

	if (func == NULL)
	{
		goto exit;
	}

	printf("[+] ntdll!NtQuerySystemInformation: 0x%p\n", func);

	return func;
	
exit:

	return (NtQuerySystemInformation_t)1;
}

ULONG64 find_kthread(HANDLE dummythreadHandle)
{

	NTSTATUS retValue = STATUS_INFO_LENGTH_MISMATCH;
	NtQuerySystemInformation_t NtQuerySystemInformation = resolve();

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

	CloseHandle(dummythreadHandle);

	return (ULONG64)retValue;
}


void fake_func() {};

HANDLE create_thread(void)
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


int main()
{

	HANDLE thread_handle = create_thread();

	DWORD64 kthread_addr = find_kthread(thread_handle);

	printf("[+] kthread at address: 0x%llx\n", kthread_addr);

	getchar();

	return 0;

}

