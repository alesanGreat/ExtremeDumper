#pragma once

#include <windows.h>

#define LDHK_MONITOR_MSCORWKS    0x01
#define LDHK_MONITOR_CLR         0x02
#define LDHK_MONITOR_CORECLR     0x04
#define LDHK_MONITOR_MODULE_MASK 0x07

typedef struct LDHK_MONITOR_INFO {
	BYTE  Sleep;
	BYTE  Flags;
	DWORD LoadImageRVA_Mscorwks;
	DWORD LoadImageRVA_CLR;
	DWORD LoadImageRVA_CoreCLR;
} LDHK_MONITOR_INFO, * PLDHK_MONITOR_INFO;

EXTERN_C_START

// Run loop to monitor clr modules loading and hook it
_Success_(SUCCEEDED(return))
HRESULT WINAPI LoaderHookMonitorLoop(_In_ PLDHK_MONITOR_INFO pInfo);

// Create process with loader hook
_Success_(SUCCEEDED(return))
HRESULT WINAPI LoaderHookCreateProcess(_In_ PCWSTR applicationName, _Inout_opt_ PWSTR commandLine);

// Create process with loader hook and explicit working directory
_Success_(SUCCEEDED(return))
HRESULT WINAPI LoaderHookCreateProcessEx(_In_ PCWSTR applicationName, _Inout_opt_ PWSTR commandLine, _In_opt_ PCWSTR currentDirectory);

EXTERN_C_END
