#pragma once

#include <windows.h>
#include "internal.h"

extern "C"
{
	DWORD64 __cdecl getNTDLL64();
	HMODULE __cdecl getNTDLL32();
	BOOL __cdecl NtCreateThreadEx(HANDLE& hThread, HANDLE hProcess, PTHREAD_START_ROUTINE lpEntryFunc, LPVOID lpArg, CreateThreadFlags flags, DWORD access);
	BOOL __cdecl NtCreateThreadEx64(HANDLE& hThread, HANDLE hProcess, DWORD64 lpEntryFunc, DWORD64 lpArg, CreateThreadFlags flags, DWORD access);
	BOOL __cdecl NtQueueUserApc(HANDLE hThread, LPVOID func, LPVOID arg1, LPVOID arg2 = NULL, LPVOID arg3 = NULL);
	BOOL __cdecl NtQueueUserApc64(HANDLE hThread, DWORD64 func, DWORD64 arg1, DWORD64 arg2 = NULL, DWORD64 arg3 = NULL);
	BOOL __cdecl NtQueryInformationThread64(HANDLE hThread, THREADINFOCLASS threadInfoClass,
		PVOID threadInfo, ULONG threadInfoLen, PULONG returnLen);
	BOOL __cdecl NtQueryInformationThread(HANDLE hThread, THREADINFOCLASS threadInfoClass,
		PVOID threadInfo, ULONG threadInfoLen, PULONG returnLen);
	BOOL __cdecl NtQueryInformationProcess64(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	BOOL __cdecl NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
	BOOL __cdecl NtWow64QueryInformationProcess64(
		IN  HANDLE ProcessHandle,
		IN  ULONG  ProcessInformationClass,
		OUT PVOID  ProcessInformation64,
		IN  ULONG  Length,
		OUT PULONG ReturnLength OPTIONAL);
	DWORD64 __cdecl X64Call(DWORD64 func, int argC, ...);
	DWORD64 __cdecl GetModuleHandle64(const wchar_t* lpModuleName);
	DWORD64 __cdecl GetProcAddress64(DWORD64 hModule, const char* funcName);
	SIZE_T __cdecl VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength);
	DWORD64 __cdecl VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	BOOL __cdecl VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType);
	BOOL __cdecl VirtualProtectEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);
	BOOL __cdecl ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
	BOOL __cdecl WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
	BOOL __cdecl GetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext);
	BOOL __cdecl SetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext);
	VOID __cdecl SetLastErrorFromX64Call(DWORD64 status);
}
