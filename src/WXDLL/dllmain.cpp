// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
//#include "stdio.h"
//#include "share.h"
//#include "time.h"
//#include "stdlib.h"
#include "Commctrl.h"
#pragma comment(lib, "Comctl32.lib")
static int titleBarHeight;
static HINSTANCE hInst;
static UINT WX_HOOK;

/*void DebugWrite(const char* t)
{
	FILE* stream;
	stream = _fsopen("C:\\Users\\zhy\\Desktop\\DBGlog.txt", "a", _SH_DENYNO);
	fputs(t, stream);
	fclose(stream);
}*/

/*void SendToWX(DWORD info)
{
	HWND WindowX = FindWindow(L"WindowX_1", NULL);

	if (WindowX == NULL) { return; }

	COPYDATASTRUCT CopyData;
	CopyData.dwData = 0x1502;
	CopyData.cbData = 4;
	CopyData.lpData = &info;
	SendMessage(WindowX, WM_COPYDATA, NULL, (LPARAM)&CopyData);
}*/

#pragma region Features

BOOL SetLayeredWnd(HWND window)
{
	LONG r = GetWindowLong(window, GWL_EXSTYLE);
	if (r == 0) { return FALSE; }
	else if ((r & WS_EX_LAYERED) > 0) { return TRUE; }
	else {
		return SetWindowLong(window, GWL_EXSTYLE, r | WS_EX_LAYERED) &&
			SetLayeredWindowAttributes(window, 0, 255, LWA_ALPHA);
	}
}

BOOL SetWindowTrans(HWND window, unsigned char opacity)
{
	return SetLayeredWindowAttributes(window, 0, opacity, LWA_ALPHA);
}

unsigned char pre_op = 255;
BOOL topMost, lock;
BOOL OnShake(HWND hwnd)
{
	if (!topMost) {
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOSENDCHANGING);
		SetWindowTrans(hwnd, 150);
		SetCursor(LoadCursor(hInst, MAKEINTRESOURCE(225)));
		pre_op = 150;
	}
	else {
		HWND owner;
		if ((owner = GetWindow(hwnd, GW_OWNER)) != NULL && GetWindowLong(owner, GWL_EXSTYLE) & WS_EX_TOPMOST) {
			return TRUE;
		}
		SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOSENDCHANGING);
		SetWindowTrans(hwnd, 200);
		SetCursor(LoadCursor(NULL, IDC_ARROW));
		pre_op = 255;
	}
	topMost = !topMost;
	return TRUE;
}

BOOL enter = FALSE, first = TRUE;
char firstMove = 1;
LONG cur, pre; //x 坐标：当前和以前的位置，用来探测摇晃
DWORD start, end; //开始结束节点
char flag; //上一次的转向标志
char turns = 0; //转向的次数

//获取移动的方向，用来判断转向
char getFlag(LONG cur, LONG pre)
{
	if (cur < pre) { return 0; }
	else if (cur == pre) { return -1; }
	else { return 1; }
}

//检测是否触发了摇晃, 通过判断1.5秒内转向的次数
void CheckShake(LONG pCur, HWND curWnd)
{
	//DebugWrite("Check Shake\n");
	if (firstMove == 1) {
		pre = cur = pCur;
		firstMove = 0; start = GetTickCount();
		flag = -1;
	}
	else if (firstMove == 2) {
		end = GetTickCount();
		double check = (double)(end - start) / 1000.0;
		if (check > 1) {
			firstMove = 0;
			start = GetTickCount();
		}
	}
	else {
		cur = pCur;
		char newFlag = getFlag(cur, pre);
		if (flag == -1) { flag = newFlag; }
		else {
			if (newFlag != -1) {
				if (newFlag ^ flag) { /*OutputDebugStringA("Turn");DebugWrite("Turn\n");*/ turns++; }
				flag = newFlag;
			}
		}
		end = GetTickCount();
		double check = (double)(end - start) / 1000.0;
		if (check < 1.5 && check > 0) {
			if (turns >= 4) {
				//DebugWrite("Begin shake\n");
				//加锁，防止在OnShake时候有可能触发WM_WINDOWPOSCHANGING造成死锁！
				lock = true; 
				OnShake(curWnd); turns = -2; firstMove = 2; start = GetTickCount();
				lock = false;
				//DebugWrite("End shake\n");
			}
		}
		else {
			start = GetTickCount();
			turns = 0;
		}
		pre = cur;
	}
}

LRESULT CALLBACK RollUpWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	if (msg == WM_GETMINMAXINFO) {
		LPMINMAXINFO lp = (LPMINMAXINFO)lParam;
		lp->ptMinTrackSize.y = titleBarHeight;
		lp->ptMaxTrackSize.y = titleBarHeight + 5;
		return 0;
	}
	return DefSubclassProc(hWnd, msg, wParam, lParam);
}

LRESULT CALLBACK WXExtraWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	switch (msg) {
	case WM_MOUSEWHEEL: {
		if (LOWORD(wParam) == MK_SHIFT) {
			SendMessage((HWND)GetProp(hWnd, L"WX_MASTER"), msg, wParam, lParam);
			return 0;
		}
		break;
	}
	case WM_NCRBUTTONDOWN: {
		if (wParam == HTMINBUTTON) {
			SendMessage((HWND)GetProp(hWnd, L"WX_MASTER"), msg, wParam, lParam);
			return 0;
		}
		break;
	}
	case WM_NCRBUTTONUP: {
		if (wParam == HTMINBUTTON) {
			SendMessage((HWND)GetProp(hWnd, L"WX_MASTER"), msg, wParam, lParam);
			return 0;
		}
		break;
	}

	case WM_NCDESTROY:
		RemoveWindowSubclass(hWnd, WXExtraWndProc, 2835);
		SetTimer((HWND)GetProp(hWnd, L"WX_MASTER"), 151140225, 1000, NULL);
		RemoveProp(hWnd, L"WX_MASTER");
		//OutputDebugString(L"Gone");
		break;

	default:
		break;
	}

	return DefSubclassProc(hWnd, msg, wParam, lParam);
}

HWND WndDigDown(HWND hWnd, POINT pt)
{
	HWND next = RealChildWindowFromPoint(hWnd, pt);

	if (next == NULL || !IsWindowVisible(next) || next == hWnd) { return hWnd; }
	else {
		return WndDigDown(next, pt);
	}
}

BOOL TryInstallExtra(HWND master)
{
	RECT t, tt;
	GetClientRect(master, &t);
	GetWindowRect(master, &tt);

	long test_y = titleBarHeight - 1 - (tt.bottom - tt.top - t.bottom);
	POINT test = { t.right - 20, test_y };
	HWND t1 = WndDigDown(master, test);
	/*char className[50];
	GetClassNameA(t1, className, 50);
	OutputDebugStringA(className);
	OutputDebugString(L"Try1");*/
	if (t1 != master && t1 != NULL) {
		//OutputDebugString(L"Try22");
		if (SetWindowSubclass(t1, WXExtraWndProc, 2835, 0)) {
			//OutputDebugString(L"Set");
			SetProp(t1, L"WX_MASTER", master);
			return TRUE;
		}
	}

	return FALSE;
}

BOOL ActionRollUp(HWND master)
{
	HANDLE test = GetProp(master, L"WX_ROLLUP");	
	RECT t;
	GetWindowRect(master, &t);
	if (test == NULL) {
		SetProp(master, L"WX_ROLLUP", (void*)(t.bottom - t.top));
		SetWindowSubclass(master, RollUpWndProc, 2836, 0);
		SetWindowPos(master, NULL, -1, -1, t.right - t.left, titleBarHeight, SWP_NOZORDER | SWP_NOMOVE);
		return TRUE;
	}
	else {
		RemoveWindowSubclass(master, RollUpWndProc, 2836);
		RemoveProp(master, L"WX_ROLLUP");
		SetWindowPos(master, NULL, -1, -1, t.right - t.left, (int)test, SWP_NOZORDER | SWP_NOMOVE);
		return FALSE;
	}
}

BOOL isMove = FALSE;
BOOL MainFeature(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	BOOL needBlock = FALSE;

	switch (msg) {
	case WM_WINDOWPOSCHANGING:
		//OutputDebugStringA("CHANG ing");
		if (!lock && enter && isMove) { //摇晃功能
			POINT x;
			GetCursorPos(&x);
			CheckShake(x.x, hWnd);
		}
		break;
	case WM_SYSCOMMAND:
		if ((wParam & 0xfff0) == SC_MOVE) {
			isMove = true;
		}
		else if ((wParam & 0xfff0) == SC_SIZE) {
			isMove = false;
		}
		break;
	case WM_ENTERSIZEMOVE:
		//SetLayeredWnd(hWnd);

		topMost = GetWindowLong(hWnd, GWL_EXSTYLE) & WS_EX_TOPMOST;
		GetLayeredWindowAttributes(hWnd, 0, &pre_op, NULL);
		if (isMove) {
			if (topMost) { SetCursor(LoadCursor(hInst, MAKEINTRESOURCE(225))); }
			if (pre_op > 200) { //移动透明功能
				SetWindowTrans(hWnd, 200);
			}
		}
		enter = TRUE;

		break;
	case WM_EXITSIZEMOVE:
		SetWindowTrans(hWnd, pre_op);
		first = TRUE;
		firstMove = TRUE;
		isMove = FALSE;
		enter = FALSE;
		turns = 0;
		break;
	case WM_MOUSEWHEEL: { //shift + 滚轮调整透明度
		if (GET_KEYSTATE_WPARAM(wParam) == MK_SHIFT) {
			//OutputDebugString(L"test");
			GetLayeredWindowAttributes(hWnd, 0, &pre_op, NULL);
			if ((short)HIWORD(wParam) > 0) {
				if (pre_op <= 250) {
					pre_op += 5;
				}
				else {
					pre_op = 255;
				}
				SetWindowTrans(hWnd, pre_op);
			}
			else {
				if (pre_op >= 30) {
					pre_op -= 5;
				}
				else {
					pre_op = 25;
				}
				SetWindowTrans(hWnd, pre_op);
			}
			needBlock = TRUE;
		}

		break;
	}

	case WM_NCRBUTTONDOWN:
		if (wParam == HTMINBUTTON) {
			needBlock = TRUE;
		}
		break;
	case WM_NCRBUTTONUP: //右键最小化按钮卷起窗口
		if (wParam == HTMINBUTTON) {
			ActionRollUp(hWnd);
			needBlock = TRUE;
		}
		break;
	case WM_TIMER:
		if (wParam == 151140225) {
			TryInstallExtra(hWnd);
			KillTimer(hWnd, wParam);
			needBlock = TRUE;
		}
		break;

	default:
		break;
	}

	return needBlock;
}

LRESULT CALLBACK WXWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	if (msg == WM_NCDESTROY) {
		//OutputDebugStringA("remove");
		RemoveWindowSubclass(hWnd, WXWndProc, 2834);
		RemoveProp(hWnd, L"WX_BASIC");
		return DefSubclassProc(hWnd, msg, wParam, lParam);
	}
		
	BOOL needBlock = MainFeature(hWnd, msg, wParam, lParam);

	if (needBlock) { return 0; }
	else { return DefSubclassProc(hWnd, msg, wParam, lParam); }
}

//特殊处理 ConsoleWindowClass 详细解释见main.cpp中
LONG_PTR OldWndProc = NULL;
LRESULT CALLBACK WXConsoleWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if (message == WM_CLOSE) {
		SetWindowLongPtr(hWnd, GWLP_WNDPROC, OldWndProc);
		RemoveProp(hWnd, L"WX_BASIC");
		//OutputDebugString(L"send detach");
		//SendToWX(GetCurrentProcessId());
		return CallWindowProc((WNDPROC)OldWndProc, hWnd, message, wParam, lParam);
	}

	BOOL needBlock = MainFeature(hWnd, message, wParam, lParam);

	if (needBlock) { return 0; }
	else { return CallWindowProc((WNDPROC)OldWndProc, hWnd, message, wParam, lParam); }
}

#pragma endregion

#pragma region Hook

/*HMODULE ModuleFromAddress(PVOID pv)
{
	MEMORY_BASIC_INFORMATION mbi;
	return VirtualQuery(pv, &mbi, sizeof mbi) != 0 ? static_cast<HMODULE>(mbi.AllocationBase) : nullptr;
}*/

LRESULT CALLBACK CallWndProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION) {
		CWPSTRUCT* info = (CWPSTRUCT*)lParam;
		if (info->message == WX_HOOK) {
			if (SetWindowSubclass(info->hwnd, WXWndProc, 2834, 0)) {
				bool aaa = SetProp(info->hwnd, L"WX_BASIC", (void*)1623);
				SetLayeredWnd(info->hwnd);
				SetTimer(info->hwnd, 151140225, 1000, NULL);
			}
			UnhookWindowsHookEx((HHOOK)info->wParam);
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/*LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode < 0) { return CallNextHookEx(NULL, nCode, wParam, lParam); }

	MSG* info = (MSG*)lParam;
	if (info->message == WM_RBUTTONUP) {
		if (wParam == HTMINBUTTON) {
			char out[400];
			GetClassNameA(info->hwnd, out, 200);
			
			//sprintf_s(out, "up right: %s", out);
			OutputDebugStringA(out);
		}
	}
	else if (info->message == WM_LBUTTONDOWN) {
		char out[400];
		GetClassNameA(info->hwnd, out, 200);OutputDebugStringA("LL");
		//sprintf_s(out, "down ncright: %s", out);
		OutputDebugStringA(out);
		//return 0;	
	}
	else if (info->message == WM_RBUTTONDOWN) {
		char out[400];
		GetClassNameA(info->hwnd, out, 200);
		//sprintf_s(out, "down right: %s", out);
		OutputDebugStringA(out);
		
		POINT t;
		GetCursorPos(&t);
	
		sprintf_s(out, "%d", SendMessage(info->hwnd, WM_NCHITTEST, NULL, MAKELPARAM(t.x, t.y)));
		OutputDebugStringA(out);
	}
	else if (info->message == WM_SYSCOMMAND) {
		if (info->wParam == SC_MINIMIZE) {
			OutputDebugString(L"123");
			info->message = 0;
			return 0;
		if (GetKeyState(VK_SHIFT) & 0x80000) {
			
			
		}
	}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}*/

void WINAPI Install(DWORD tId, HWND t)
{
	//OutputDebugString(L"Install Called");
	
	if (tId == NULL) {
		//特殊处理 ConsoleWindowClass
		//OutputDebugString(L"here");
		OldWndProc = SetWindowLongPtr(t, GWLP_WNDPROC, (LONG_PTR)WXConsoleWndProc);
		if (OldWndProc) {
			SetLayeredWnd(t);
			//OutputDebugString(L"123");
			bool aaa = SetProp(t, L"WX_BASIC", (void*)1623);
		}
		
	}
	else {
		HHOOK a = SetWindowsHookEx(WH_CALLWNDPROC, CallWndProc, 0, tId);
		SendMessage(t, WX_HOOK, (WPARAM)a, NULL);
	}
	


	
	//SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, 0, tId);
}
#pragma endregion

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	hInst = hModule;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		titleBarHeight = (GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CYCAPTION) +
			GetSystemMetrics(SM_CXPADDEDBORDER));
		WX_HOOK = RegisterWindowMessage(L"WX_HOOK__1");
		//hMProcess = ModuleFromAddress(CallWndProc);*/
		break;
	}

	case DLL_THREAD_ATTACH: {
		break;
	}

	case DLL_THREAD_DETACH: {
	
		
		break;
	}

	case DLL_PROCESS_DETACH: {
		//SendToWX(GetCurrentProcessId());
		break;
	}
	}
	return TRUE;
}


