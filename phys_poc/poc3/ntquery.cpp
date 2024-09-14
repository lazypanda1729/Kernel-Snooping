#include "ntquery.h"


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

