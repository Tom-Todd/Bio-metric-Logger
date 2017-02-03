// BioLog32.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "BioLog32.h"
#include "stdafx.h"
#include <Shellapi.h>
#include <Windows.h>
#include <Strsafe.h>
//#include "sqlite3.h"
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
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    //LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    //LoadStringW(hInstance, IDC_BIOLOG32, szWindowClass, MAX_LOADSTRING);
    //MyRegisterClass(hInstance);

    // Perform application initialization:
    /*if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }*/
	//HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_BIOLOG32));
	hInst = hInstance;

	//Inject Hook
	lib = LoadLibrary(L"D:\\Tom\\Documents\\Bio-Metric-Logger\\hookDLL\\Debug\\hookDll.dll"); //Load DLL
	if (lib) {
		HOOKPROC procedure = (HOOKPROC)GetProcAddress(lib, "_procedure@12"); //Get Procdeure address

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
        //if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        //{
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        //}
    }
    return (int) msg.wParam;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
   /* case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;*/
    case WM_DESTROY:
		//Remove Hook
		FreeLibrary(lib);
		UnhookWindowsHookEx(hook);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}