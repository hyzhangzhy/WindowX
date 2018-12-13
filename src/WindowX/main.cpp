#include <Windows.h>
#include <stdio.h>
#include <CommCtrl.h>
#include <share.h>
#include <wchar.h>
#include <unordered_map>
#include <unordered_set>

#include "wow64ext.h"
#include "Tlhelp32.h"

#pragma region Global

const UINT WM_TRAY = WM_USER + 1;
HWND g_msgWnd;

wchar_t dllFullPath32[MAX_PATH];
wchar_t dllFullPath64[MAX_PATH];
BOOL isOSX64 = FALSE;

bool CheckProcessX64(HANDLE hProcess)
{
	if (!isOSX64) { return false; }
	else {
		BOOL res;
		IsWow64Process(hProcess, &res);
		return !res;
	}
}

#pragma endregion

#pragma region Remote

struct RemoteInfo
{
	HANDLE workerThread;
	HANDLE hWait;        //Windows ThreadPool wait handle, to monitor if our workerThread has been terminated.
	union
	{
		DWORD install32;
		DWORD64 install64;
	};
};

enum RemoteStatu
{
	WXR_NoWorker = 0,
	WXR_NoDLL,
	WXR_NoInstall,
	WXR_Ready
};

class RemoteCaller
{
public:
	RemoteCaller() {}


	RemoteCaller(bool p, DWORD processId, HANDLE pProcess) : isX64(p), pId(processId), hProcess(pProcess)
	{
		
	}

	//Get current window's process status.
	RemoteStatu GetRemoteStatu();
	
	//Check if phThread is our workerThread.
	bool IsWorkerThread(HANDLE phThread);

	//Inject WorkerThread. 
	bool CreateWorkerThread();

	//Inject the dll.
	bool ExecLoadDll();

	//Execute install procedure.
	bool ExecInstall(DWORD threadId, HWND t);

	//todo: Safely eject the dll.
	bool ExecUnLoadDll();

	//ShellCode initialization.
	static void ScInit() 
	{
		DWORD proc32;
		proc32 = (DWORD)GetProcAddress(getNTDLL32(), "NtDelayExecution");
		memcpy(scWorker32 + 8, &proc32, 4);
		proc32 = (DWORD)GetProcAddress(getNTDLL32(), "LdrGetDllHandle");
		memcpy(scLoadDll32 + 15, &proc32, 4);
		proc32 = (DWORD)GetProcAddress(getNTDLL32(), "LdrLoadDll");
		memcpy(scLoadDll32 + 35, &proc32, 4);
		proc32 = (DWORD)GetProcAddress(getNTDLL32(), "LdrGetProcedureAddress");
		memcpy(scLoadDll32 + 52, &proc32, 4);
		proc32 = (DWORD)GetProcAddress(getNTDLL32(), "NtSetEvent");
		memcpy(scLoadDll32 + 64, &proc32, 4);
	

		DWORD64 proc64;
		proc64 = GetProcAddress64(getNTDLL64(), "NtDelayExecution");
		memcpy(scWorker64 + 21, &proc64, 8);
		proc64 = GetProcAddress64(getNTDLL64(), "LdrGetDllHandle");
		memcpy(scLoadDll64 + 30, &proc64, 8);
		proc64 = GetProcAddress64(getNTDLL64(), "LdrLoadDll");
		memcpy(scLoadDll64 + 61, &proc64, 8);
		proc64 = GetProcAddress64(getNTDLL64(), "LdrGetProcedureAddress");
		memcpy(scLoadDll64 + 90, &proc64, 8);
		proc64 = GetProcAddress64(getNTDLL64(), "NtSetEvent");
		memcpy(scLoadDll64 + 109, &proc64, 8);
	}

	void pManagerErase(DWORD processId)
	{
		if (pManager.find(processId) == pManager.end()) { return; }

		CloseHandle(pManager[processId].workerThread);
		UnregisterWaitEx(pManager[processId].hWait, INVALID_HANDLE_VALUE);
		pManager.erase(processId);
	}

	/*void CleanWorkers()
	{
		std::unordered_map<DWORD, RemoteInfo>::iterator it = pManager.begin();
		while (it != pManager.end()) {
			DWORD exitCode;
			if (!GetExitCodeThread(it->second.workerThread, &exitCode) ||
				exitCode != STILL_ACTIVE) {
				CloseHandle(it->second.workerThread);
				it = pManager.erase(it);
			}
			else
				it++;
		}
	}*/

private:
	
	static unsigned char scWorker32[], scWorker64[], scLoadDll32[], scLoadDll64[];
	static std::unordered_map<DWORD, RemoteInfo> pManager; //ProcessId -> RemoteInfo
	HANDLE hProcess, hWait;

	DWORD pId;
	bool isX64;

	
	HANDLE CreateApcEvent(); //Create Remote Apc Event.
	void CloseApcEvent(HANDLE hRemote);

	//Windows ThreadPool callback procedure.
	static VOID CALLBACK CleanerProc(PVOID lpParam, BOOLEAN TimerOrWaitFired)
	{
		SetTimer(g_msgWnd, (DWORD)lpParam, 500, NULL);
	}
	
	
};

std::unordered_map<DWORD, RemoteInfo> RemoteCaller::pManager;

/*
label1:
	push 00000  ;Delay
	push 1      ;TRUR
	mov eax, 0  ;[NtDelayExecution]
	call eax
	jmp label1

	ret
*/
unsigned char RemoteCaller::scWorker32[] = {
	0x68, 0x00, 0x00, 0x00, 0x00,
	0x6a, 0x01,
	0xb8, 0x00, 0x00, 0x00, 0x00, 
	0xff, 0xd0, 
	0xeb, 0xf0,
	0xc3
};

/*

*/
unsigned char RemoteCaller::scLoadDll32[] = {
	0xbb, 0x00, 0x00, 0x00, 0x00,  //1
	0x53,
	0x8d, 0x43, 0x08,
	0x50,
	0x6a, 0x00,
	0x6a, 0x00,
	0xb8, 0x00, 0x00, 0x00, 0x00,  //15
	0xff, 0xd0,
	0x85, 0xc0,
	0x74, 0x10,
	0x53,
	0x8d, 0x43, 0x08,
	0x50,
	0x6a, 0x00,
	0x6a, 0x00,
	0xb8, 0x00, 0x00, 0x00, 0x00,  //35
	0xff, 0xd0,
	0x53,
	0x68, 0xe1, 0x00, 0x00, 0x00,
	0x6a, 0x00,
	0xff, 0x33,
	0xb8, 0x00, 0x00, 0x00, 0x00,  //52
	0xff, 0xd0,
	0x6a, 0x00, 
	0xff, 0x73, 0x04,
	0xb8, 0x00, 0x00, 0x00, 0x00,  //64
	0xff, 0xd0,
	0xc3
};

/*
label1:
	sub rsp, 0x28
	mov ecx, 0x1    ;TRUE
	mov rdx, 0x0    ;Delay
	mov rax, 0x0	;[NtDelayExecution]
	call rax
	add rsp, 0x28
	jmp label1
	
	ret
*/
unsigned char RemoteCaller::scWorker64[] = {
	0x48, 0x83, 0xec, 0x28, 
	0xb9, 0x01, 0x00, 0x00, 0x00, 
	0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //11
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //21
	0xff, 0xd0,
	0x48, 0x83, 0xc4, 0x28,
	0xeb, 0xdb,
	0xc3
};

/*

*/
unsigned char RemoteCaller::scLoadDll64[] = {
	0x48, 0x83, 0xec, 0x28,
	0x48, 0xbb, 0x00, 0x00, 0x3a, 0xd4, 0x74, 0x02, 0x00, 0x00,  //6
	0x48, 0x33, 0xc9,
	0x48, 0x33, 0xd2,
	0x4c, 0x8d, 0x43, 0x10,
	0x4c, 0x8d, 0x4b, 0x00,
	0x48, 0xb8, 0xc0, 0xa7, 0xce, 0x73, 0xfb, 0x7f, 0x00, 0x00, //26 + 4 = 30
	0xff, 0xd0,
	0x48, 0x85, 0xc0,
	0x74, 0x1a,
	0x48, 0x33, 0xc9,
	0x48, 0x33, 0xd2,
	0x4c, 0x8d, 0x43, 0x10,
	0x4c, 0x8d, 0x4b, 0x00,
	0x48, 0xb8, 0x80, 0xa6, 0xce, 0x73, 0xfb, 0x7f, 0x00, 0x00, //57 + 4 = 61
	0xff, 0xd0,
	0x48, 0x8b, 0x4b, 0x00,
	0x48, 0x33, 0xd2,
	0x41, 0xb8, 0xe1, 0x00, 0x00, 0x00,
	0x4c, 0x8d, 0x4b, 0x00,
	0x48, 0xb8, 0x70, 0xfe, 0xd2, 0x73, 0xfb, 0x7f, 0x00, 0x00, //86 + 4 = 90
	0xff, 0xd0,
	0x48, 0x8b, 0x4b, 0x08,
	0x48, 0x31, 0xd2,
	0x48, 0xb8, 0x81, 0x1d, 0x98, 0xbe, 0x1c, 0x00, 0x00, 0x00, //105 + 4 = 109
	0xff, 0xd0,
	0x48, 0x83, 0xc4, 0x28,
	0xc3
};

HANDLE RemoteCaller::CreateApcEvent()
{
	hWait = CreateEvent(NULL, true, false, L"WX_LOADDLL");
	HANDLE hWaitRemote = NULL;
	DuplicateHandle(GetCurrentProcess(), hWait, hProcess, &hWaitRemote, 0, FALSE, DUPLICATE_SAME_ACCESS);

	return hWaitRemote;
}

void RemoteCaller::CloseApcEvent(HANDLE hRemote)
{
	//Close the remote handle first.
	HANDLE hLocal = NULL;
	DuplicateHandle(hProcess, hRemote, GetCurrentProcess(), &hLocal, 0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);

	if (hLocal) { CloseHandle(hLocal); }
	
	//Then, close the local handle.
	if (hWait) {
		CloseHandle(hWait);
		hWait = NULL;
	}
}

bool RemoteCaller::IsWorkerThread(HANDLE phThread)
{
	bool res = false;
	if (isX64) {
		DWORD64 startAdd = 0;
		NtQueryInformationThread64(phThread, ThreadQuerySetWin32StartAddress, &startAdd, 8, NULL);
		DWORD64 test = 0;
		ReadProcessMemory64(hProcess, startAdd - 8, &test, 8, NULL);
		if (test == 0x8000000000000000) {
			//OutputDebugString(L"Worker Found!\n\n");
			pManager[pId].workerThread = phThread;
			res = true;
		}
	}
	else {
		DWORD startAdd = 0;
		NtQueryInformationThread(phThread, ThreadQuerySetWin32StartAddress, &startAdd, 4, NULL);
		DWORD test = 0;
		ReadProcessMemory(hProcess, (void*)(startAdd - 8), &test, 4, NULL);
		if (test == 0x8000000000000000) {
			//printf("Worker Founded! %llx\n", test);
			//printf("ThreadID: %d\n\n", GetThreadId(phThread));
			pManager[pId].workerThread = phThread;
			res = true;
		}
	}
	
	if (res)
		RegisterWaitForSingleObject(&pManager[pId].hWait, phThread, CleanerProc, (void*)pId, INFINITE, WT_EXECUTEONLYONCE);

	return res;
}

RemoteStatu RemoteCaller::GetRemoteStatu()
{
	if (pManager.find(pId) != pManager.end()) { return WXR_NoInstall; }
	else { return WXR_NoWorker; }
}


bool RemoteCaller::CreateWorkerThread()
{
	LARGE_INTEGER liDelay = { { 0 } };
	liDelay.QuadPart = 0x8000000000000000; //it is the smallest integer that a 64bit value can represent, so consider it as infinite; : -10 * 1000 * 30000; //30000ms

	unsigned char buffer[200];
	HANDLE hThread;
	if(!isX64) {
		DWORD stub32 = (DWORD)VirtualAllocEx(hProcess, NULL, sizeof(scWorker32) + sizeof(LARGE_INTEGER), MEM_COMMIT, PAGE_READWRITE);
		memcpy(buffer, &liDelay, sizeof(LARGE_INTEGER));
		memcpy(scWorker32 + 1, &stub32, 4);
		memcpy(buffer + 8, scWorker32, sizeof(scWorker32));
		WriteProcessMemory(hProcess, (void*)stub32, buffer, sizeof(scWorker32) + sizeof(LARGE_INTEGER), NULL);
		DWORD t;
		bool res1 = VirtualProtectEx(hProcess, (void*)(stub32 + 8), sizeof(scWorker32), PAGE_EXECUTE_READ, &t);
		//bool res2 = VirtualProtectEx(hProcess, (void*)stub32, 8, PAGE_READONLY, &t);

		Sleep(100);
		if (NtCreateThreadEx(hThread, hProcess, (PTHREAD_START_ROUTINE)(stub32 + 8), NULL, HideFromDebug, THREAD_ALL_ACCESS)) {
			pManager[pId].workerThread = hThread;
		}
	}
	else {
		DWORD64 stub64 = VirtualAllocEx64(hProcess, NULL, sizeof(scWorker64) + sizeof(LARGE_INTEGER), MEM_COMMIT, PAGE_READWRITE);
		memcpy(buffer, &liDelay, sizeof(LARGE_INTEGER));
		memcpy(scWorker64 + 11, &stub64, 8);
		memcpy(buffer + 8, scWorker64, sizeof(scWorker64));

		WriteProcessMemory64(hProcess, stub64, buffer, sizeof(scWorker64) + 8, NULL);
		DWORD t;
		bool res1 = VirtualProtectEx64(hProcess, stub64 + 8, sizeof(scWorker64), PAGE_EXECUTE_READ, &t);

		Sleep(100);
		if (NtCreateThreadEx64(hThread, hProcess, stub64 + 8, NULL, HideFromDebug, THREAD_ALL_ACCESS)) {
			pManager[pId].workerThread = hThread;
		}
	}

	RegisterWaitForSingleObject(&pManager[pId].hWait, hThread, CleanerProc, (void*)pId, INFINITE, WT_EXECUTEONLYONCE);

	return true;
}

bool RemoteCaller::ExecLoadDll()
{
	HANDLE hWaitRemote = CreateApcEvent();
	if (hWaitRemote == NULL) { return false; }
	
	unsigned char buffer[200];

	if (!isX64) {
		size_t pathLen = wcslen(dllFullPath32);
		size_t dataSize = pathLen * 2 + sizeof(_UNICODE_STRING_T<DWORD>) + 4 + 4;
		DWORD remoteData32 = (DWORD)VirtualAllocEx(hProcess, NULL, dataSize, MEM_COMMIT, PAGE_READWRITE);
		memcpy(scLoadDll32 + 1, &remoteData32, 4);
		
		_UNICODE_STRING_T<DWORD> tmp;
		tmp.Length = pathLen * 2;
		tmp.MaximumLength = pathLen * 2 + 2;
		tmp.Buffer = (DWORD)remoteData32 + 8 + sizeof(_UNICODE_STRING_T<DWORD>);

		memcpy(buffer + 4, &hWaitRemote, sizeof(hWaitRemote));
		memcpy(buffer + 8, &tmp, sizeof(_UNICODE_STRING_T<DWORD>));
		memcpy(buffer + 8 + sizeof(_UNICODE_STRING_T<DWORD>), dllFullPath32, pathLen * 2);

		WriteProcessMemory(hProcess, (void*)remoteData32, buffer, dataSize, NULL);
		
		LPVOID stub32 = VirtualAllocEx(hProcess, NULL, sizeof(scLoadDll32), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(hProcess, stub32, scLoadDll32, sizeof(scLoadDll32), NULL);

		ResetEvent(hWait);
		NtQueueUserApc(pManager[pId].workerThread, stub32, NULL);

		
		if (WaitForSingleObject(hWait, INFINITE) == WAIT_OBJECT_0) {
			DWORD funcAdd32;
			ReadProcessMemory(hProcess, (void*)remoteData32, &funcAdd32, 4, NULL);
			//NtQueueUserApc(pManager[hProcess].workerThread, (void*)funcAdd32, (void*)tIDtest);
			//printf("32bit DLL api address at: %x\n", funcAdd32);
			pManager[pId].install32 = funcAdd32;
			VirtualFreeEx(hProcess, stub32, sizeof(scLoadDll32), MEM_RELEASE);
			VirtualFreeEx(hProcess, (void*)remoteData32, dataSize, MEM_RELEASE);
		}
	}
	else {
		size_t pathLen = wcslen(dllFullPath64);
		size_t dataSize = pathLen * 2 + sizeof(_UNICODE_STRING_T<DWORD64>) + 8 + 8;
		DWORD64 remoteData64 = VirtualAllocEx64(hProcess, NULL, dataSize, MEM_COMMIT, PAGE_READWRITE);
		memcpy(scLoadDll64 + 6, &remoteData64, 8);

		_UNICODE_STRING_T<DWORD64> tmp;
		tmp.Length = pathLen * 2;
		tmp.MaximumLength = pathLen * 2 + 2;
		tmp.Buffer = remoteData64 + 16 + sizeof(_UNICODE_STRING_T<DWORD64>);

		DWORD64 t = (DWORD64)hWaitRemote;

		memcpy(buffer + 8, &t, 8);
		memcpy(buffer + 16, &tmp, sizeof(_UNICODE_STRING_T<DWORD64>));
		memcpy(buffer + 16 + sizeof(_UNICODE_STRING_T<DWORD64>), dllFullPath64, pathLen * 2);

		WriteProcessMemory64(hProcess, remoteData64, buffer, dataSize, NULL);

		DWORD64 stub64 = VirtualAllocEx64(hProcess, NULL, sizeof(scLoadDll64), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory64(hProcess, stub64, scLoadDll64, sizeof(scLoadDll64), NULL);
 		ResetEvent(hWait);
		NtQueueUserApc64(pManager[pId].workerThread, stub64, NULL);


		if (WaitForSingleObject(hWait, INFINITE) == WAIT_OBJECT_0) {
			DWORD64 funcAdd64;
			ReadProcessMemory64(hProcess, remoteData64, &funcAdd64, 8, NULL);
			//NtQueueUserApc(pManager[hProcess].workerThread, (void*)funcAdd32, (void*)tIDtest);
			//printf("64bit DLL api address at: %llx\n", funcAdd64);
			pManager[pId].install64 = funcAdd64;
			VirtualFreeEx64(hProcess, stub64, sizeof(scLoadDll64), MEM_RELEASE);
			VirtualFreeEx64(hProcess, remoteData64, dataSize, MEM_RELEASE);
		}
	}

	CloseApcEvent(hWaitRemote);

	return true;
}

bool RemoteCaller::ExecInstall(DWORD threadId, HWND t)
{
	if (!isX64) {
		NtQueueUserApc(pManager[pId].workerThread, (PAPCFUNC)pManager[pId].install32, (void*)threadId, (void*)t);
		return true;
	}
	else {
		NtQueueUserApc64(pManager[pId].workerThread, pManager[pId].install64, (DWORD64)threadId, (DWORD64)t);
		return true;
	}
	return false;
	
}

#pragma endregion

#pragma region Proc

//Specially handle ConsoleWindowClass.
//Reason：
//https://www.howtogeek.com/howto/4996/what-is-conhost.exe-and-why-is-it-running/
//https://www.oschina.net/translate/inside-the-windows-console
bool HandleConsoleWindow(IN HANDLE hProcess, OUT DWORD* processId, OUT DWORD* threadId)
{
	//Find conhost.exe process id.
	if (isOSX64) {
		DWORD64 consoleHostPId;
		bool res = NtQueryInformationProcess64(hProcess, ProcessConsoleHostProcess, &consoleHostPId, 8, NULL);
		if (!res) { return false; }

		*processId = (DWORD)consoleHostPId & ~3;
	}
	else {
		DWORD consoleHostPId;
		bool res = NtQueryInformationProcess(hProcess, ProcessConsoleHostProcess, &consoleHostPId, 4, NULL);
		if (!res) { return false; }

		*processId = consoleHostPId & ~3;
	}

	//if is unsafe to use SetWindowLongPtr for window subclassing, reason： https://blogs.msdn.microsoft.com/oldnewthing/20031111-00/?p=41883
	//todo: find the threadId.
	*threadId = NULL;
	return true;
}

VOID CALLBACK WinEventProcCallback(HWINEVENTHOOK hWinEventHook, DWORD dwEvent, HWND hWnd, LONG idObject, LONG idChild, DWORD dwEventThread, DWORD dwmsEventTime)
{
	if (dwEvent == EVENT_SYSTEM_FOREGROUND)
	{
		if ((GetWindowLongPtr(hWnd, GWL_EXSTYLE) & WS_EX_WINDOWEDGE) > 0) {
			if (!IsWindowVisible(hWnd)) {
				Sleep(500);
				if (!IsWindowVisible(hWnd)) {
					Sleep(500);
					if (!IsWindowVisible(hWnd)) { return; }
				}
			}

			//WXR_Ready: Already installed.
			if (GetProp(hWnd, L"WX_BASIC") != NULL) { return; }

			char c[100];
			GetClassNameA(hWnd, c, 100);

			//You can add exclusions here.
			if (strcmp(c, "MsoSplash") == 0 ) { return; }

			DWORD processId;
			DWORD threadId = GetWindowThreadProcessId(hWnd, &processId);
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
			if (hProcess == NULL) { return; }

			bool isCurpX64 = CheckProcessX64(hProcess);

			//Handle ConsoleWindowClass.
			if (strcmp(c, "ConsoleWindowClass") == 0) {
				if (!HandleConsoleWindow(hProcess, &processId, &threadId)) { return; }

				CloseHandle(hProcess);
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
				if (hProcess == NULL) { return; }

				//The bits of conhost.exe is related to the OS.
				isCurpX64 = isOSX64;
			}
			
			RemoteCaller caller(isCurpX64, processId, hProcess);
			RemoteStatu statu = caller.GetRemoteStatu();

			if (statu < 1) { caller.CreateWorkerThread(); }

			if (statu < 2) { caller.ExecLoadDll(); }

			if (statu < 3) { caller.ExecInstall(threadId, hWnd); }

			Sleep(100);
			CloseHandle(hProcess);
		}
	}
}

LRESULT __stdcall WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) {
	case WM_TIMER: {
		RemoteCaller caller;
		caller.pManagerErase(wParam);
		KillTimer(hWnd, wParam);
		return 0;
	}
	case WM_CREATE: {
		NOTIFYICONDATA stData;
		ZeroMemory(&stData, sizeof(stData));
		stData.cbSize = sizeof(stData);
		stData.hWnd = hWnd;
		stData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
		stData.uCallbackMessage = WM_TRAY;
		stData.hIcon = LoadIcon(NULL, MAKEINTRESOURCE(IDI_APPLICATION));
		wcscpy_s(stData.szTip, L"WindowX");
		if (!Shell_NotifyIcon(NIM_ADD, &stData))
			return -1;
		return 0;
	}
	case WM_TRAY: {
		switch (lParam) {
		case WM_RBUTTONDOWN: {
			HMENU hMenu = CreatePopupMenu();
			if (hMenu) {
				POINT stPoint;
				GetCursorPos(&stPoint);
				InsertMenu(hMenu, 0xFFFFFFFF, MF_STRING, 40002, L"退出");
				SetForegroundWindow(hWnd);
				TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON, stPoint.x, stPoint.y, 0, hWnd, NULL);
				DestroyMenu(hMenu);
			}
		}
		
		}
		return 0;
		
	}
	case WM_COMMAND: {
		switch (LOWORD(wParam)) {
		case 40002:
			DestroyWindow(hWnd);
			return 0;
		}
	}
	case WM_DESTROY: {
		NOTIFYICONDATA stData;
		ZeroMemory(&stData, sizeof(stData));
		stData.cbSize = sizeof(stData);
		stData.hWnd = hWnd;
		Shell_NotifyIcon(NIM_DELETE, &stData);
		PostQuitMessage(0);
		return 0;
	}
	
	default:
		break;
	}

	return DefWindowProc(hWnd, message, wParam, lParam);
}

#pragma endregion

#pragma region ProgramInit

std::unordered_set<DWORD> pIds;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	char className[50];
	GetClassNameA(hwnd, className, 50);
	if (IsWindowVisible(hwnd) && ((GetWindowLongPtr(hwnd, GWL_EXSTYLE) & WS_EX_WINDOWEDGE) > 0) 
		&& strcmp(className, "Windows.UI.Core.CoreWindow") != 0) {
		DWORD pId, tId;
		tId = GetWindowThreadProcessId(hwnd, &pId);

		if (strcmp(className, "ConsoleWindowClass") == 0) {
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
			if (hProcess == NULL) { return TRUE; }
			if (!HandleConsoleWindow(hProcess, &pId, &tId)) { return TRUE; }

			CloseHandle(hProcess);
		}

		pIds.insert(pId);
	}
	return TRUE;
}

void ScanRetriveWorkerThreads()
{
	EnumWindows(EnumWindowsProc, NULL);

	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 tEntry = { 0 };
	tEntry.dwSize = sizeof(THREADENTRY32);

	for (BOOL success = Thread32First(hThreadSnapshot, &tEntry);
		success != FALSE;
		success = Thread32Next(hThreadSnapshot, &tEntry)) {
		if (pIds.find(tEntry.th32OwnerProcessID) == pIds.end()) { continue; }

		HANDLE tmp = OpenThread(THREAD_ALL_ACCESS, FALSE, tEntry.th32ThreadID);
		if (tmp == NULL) { continue; }

		HANDLE tmp1 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tEntry.th32OwnerProcessID);
		if (tmp1 == NULL) { continue; }

		RemoteCaller c(CheckProcessX64(tmp1), tEntry.th32OwnerProcessID, tmp1);

		if (c.IsWorkerThread(tmp)) { 
			c.ExecLoadDll(); 
			pIds.erase(tEntry.th32OwnerProcessID); 
		}		
		else {
			CloseHandle(tmp);
		}
		CloseHandle(tmp1);
	}

	pIds.clear();
	pIds = std::unordered_set<DWORD>();
	CloseHandle(hThreadSnapshot);
}



BOOL SetDebugPrivilege()
{
	BOOL bRet = FALSE;
	HANDLE hToken = NULL;
	LUID luid = { 0 };
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		}
	}
	return bRet;
}

#pragma endregion

//Important: For security sake, do not run it with administrator privileges.
//为了安全，不要以管理员权限运行!!!
int WINAPI WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR lpCmdLine,
	int nCmdShow)
{
#ifdef _DEBUG
	//AllocConsole();
	//AttachConsole(GetCurrentProcessId());
	//freopen("CON", "w", stdout);
#endif // _DEBUG


	//SetDebugPrivilege(); //If you insist on running it with administrator privileges, uncomment this line.

	GetModuleFileName(NULL, dllFullPath32, MAX_PATH - 8);
	(wcsrchr(dllFullPath32, L'\\'))[0] = 0;
	wcscat_s(dllFullPath32, L"\\WX32.dll");
	FILE* fp;
	_wfopen_s(&fp, dllFullPath32, L"r");
	if (fp == NULL) { return -1; }
	fclose(fp);

	IsWow64Process(GetCurrentProcess(), &isOSX64);
	if (isOSX64) {
		GetModuleFileName(NULL, dllFullPath64, MAX_PATH - 8);
		(wcsrchr(dllFullPath64, L'\\'))[0] = 0;
		wcscat_s(dllFullPath64, L"\\WX64.dll");
		FILE* fp;
		_wfopen_s(&fp, dllFullPath64, L"r");
		if (fp == NULL) { return -1; }
		fclose(fp);
	}

	WNDCLASS wx = { 0 };
	wx.lpfnWndProc = WndProc;
	wx.hInstance = hInstance;
	wx.lpszClassName = L"WindowX_1";

	if (!RegisterClass(&wx)) { return -2; }

	if (!(g_msgWnd = CreateWindow(L"WindowX_1",  L"", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL))) { return -3; }

	RemoteCaller::ScInit();

	ScanRetriveWorkerThreads();

	HWINEVENTHOOK a = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, NULL,
		WinEventProcCallback, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	UnhookWinEvent(a);
	return 0;
}
