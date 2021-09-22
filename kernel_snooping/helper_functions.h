#pragma once

#include "main_stuff.h"


#define ARRAY_SIZE 1024

#define MAX_SEARCH_LEN 200

DWORD64 find_kernel_base();

BOOL enum_drivers(DWORD64 callback_address, char* target_driver, int index);

DWORD64 get_PsSetCreateProcessNotifyRoutine(DWORD64 kernel_img_base);