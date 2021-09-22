
#include "helper_functions.h"


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

		printf("[+] Failed to enumerate device drivers\n\n");

		return -1;
	
	}

	return kernel_image_base;
}


// enumerate all the loaded drivers in the system

BOOL enum_drivers(DWORD64 callback_address, char* target_driver, int index)
{

	LPVOID drivers[ARRAY_SIZE];

	DWORD cbNeeded;

	int driver_count = 0;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{

		char driver_name[MAX_PATH] = { 0 };

		driver_count = cbNeeded / sizeof(drivers[0]);

		for (int i = 0; i < driver_count; i++)
		{
			// callback address falls into the memmory range of the driver 
			if (((DWORD64)drivers[i] < callback_address) && (callback_address < (DWORD64)drivers[i + 1]))
			{

				// Get the driver name
				if (GetDeviceDriverBaseNameA(drivers[i], driver_name, MAX_PATH))
				{

					// check if its the target driver
					if (strcmp(driver_name, target_driver) == 0)
					{

						return true;

					}
				}
			}

		}
	}

}


DWORD64 get_PsSetCreateProcessNotifyRoutine(DWORD64 kernel_image_base)
{

	HMODULE ntoskrnl_handle = LoadLibraryW(L"ntoskrnl.exe");

	DWORD64 PsSetCreateProcessNotifyRoutineOffset = (DWORD64)(GetProcAddress(ntoskrnl_handle, "PsSetCreateProcessNotifyRoutine")) - ((DWORD64)ntoskrnl_handle);

	DWORD64 PsSetCreateProcessNotifyRoutine_address = kernel_image_base + PsSetCreateProcessNotifyRoutineOffset;

	return PsSetCreateProcessNotifyRoutine_address;

}


