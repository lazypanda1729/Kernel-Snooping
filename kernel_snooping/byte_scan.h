#pragma once

#include "main_stuff.h"


DWORD64 get_PspSetCreateProcessNotifyRoutine(HANDLE device, DWORD64 PsSetCreateProcessNotifyRoutine_address);

DWORD64 get_PspCreateProcessNotifyRoutine_arr(HANDLE device, DWORD64 PspSetCreateProcessNotifyRoutine_address);