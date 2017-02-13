// BioLog64.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "BioLog64.h"
#include "stdafx.h"
#include <Shellapi.h>
#include <Windows.h>
#include <Strsafe.h>
#include <CommCtrl.h>
#pragma comment(lib,"comctl32.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
HHOOK hook;
HMODULE lib;
bool HookInstalled = false;

// Forward declarations of functions included in this code module:
//LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	hInst = hInstance;

	//Inject Hook
	lib = LoadLibrary(L"D:\\Tom\\Documents\\Bio-Metric-Logger\\hookDLL\\x64\\Debug\\hookDll.dll");
	if (lib) {
		HOOKPROC procedure = (HOOKPROC)GetProcAddress(lib, "procedure"); //Get Procdeure address

		if (procedure) {
			hook = SetWindowsHookEx(WH_CALLWNDPROC, procedure, lib, 0); //Set up the hook
																		//hook2 = SetWindowsHookEx(WH_CALLWNDPROC, procedure2, lib2, 0);
			DWORD test = GetLastError();
			test = test;
		}
		else
			printf("Can't find function in dll!\n"); //Error if the DLL doesn't contain the addressed procedure
	}
	else {
		printf("Can't find dll!\n"); //Error if the DLL is missing
	}
	if (hook) {
		printf("Hook installed properly!\n\n");
		HookInstalled = true;
	}
	//End Inject Hook

	MSG msg;
	// Main message loop:
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}