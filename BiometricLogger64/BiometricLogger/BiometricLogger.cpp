#include "stdafx.h"
#include "BiometricLogger.h"
#include <Shellapi.h>
#include <Windows.h>
#include <Winuser.h>
#include <Strsafe.h>
#include "sqlite3.h"
#include <thread>
#include <atomic>
#include <CommCtrl.h>
#include "Semaphore.h"
#include <oleacc.h>
#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <mutex>
#include <AtlConv.h>
#pragma comment(lib,"comctl32.lib")
#pragma comment(lib, "user32.lib") 
#pragma comment(lib, "ole32")
#pragma comment(lib, "oleacc")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
NOTIFYICONDATA nid = {};
HHOOK hook;
HHOOK hook2;
HMODULE lib;
HMODULE lib2;
HWND hWnd;
STARTUPINFO si;
PROCESS_INFORMATION pi;
HWINEVENTHOOK LHook = 0;
//std::thread pipeThread32;
std::thread pipeThreadDLL;
std::atomic_bool running = true;
bool HookInstalled = false;
bool debuggingProgramHook = false;
std::atomic_int test = 0;
sqlite3 *database;
//Mutex for the database
std::mutex mutex;

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
void pipeListener();
void pipeListenerDLL();
int injectHook();
int startLog32();
void Hook();



int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow){
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_BIOMETRICLOGGER, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

	//Start a new thread to listen for messages from the 32 bit logger
	//pipeThread32 = std::thread(pipeListener);
	//Start a new thread to listen for messages from the hooks
	pipeThreadDLL = std::thread(pipeListenerDLL);
	//Inject the hook and check for error
	if(injectHook() == -1)return -1;
	//Start the 32 bit process and check for error
	//if(startLog32() == -1)return -1;
	sqlite3_open("Database.sqlite", &database);
	
	const char* sql = "CREATE TABLE PROGRAM_EVENTS("  
		/*"ID INT PRIMARY        KEY      NOT NULL,"*/ 
		"TIME				   TEXT     NOT NULL," 
		"PROGRAM_NAME          TEXT     NOT NULL," 
		"EVENT				   TEXT     NOT NULL," 
		"TYPE				   INT      NOT NULL);";

	const char* sql2 = "CREATE TABLE URLS("
		/*"ID INT PRIMARY        KEY      NOT NULL,"*/
		"URL				   TEXT     NOT NULL);";

	/* Execute SQL statement */
	int rc = sqlite3_exec(database, sql, NULL, NULL, NULL);
	int rc2 = sqlite3_exec(database, sql2, NULL, NULL, NULL);

	Hook();

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_BIOMETRICLOGGER));
    MSG msg;
    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return (int) msg.wParam;
}

////Method used for the 32 bit pipe listening thread
void pipeListener() {
	char buffer[1024];
	DWORD dwRead;
	HANDLE hPipe32;

	//Create Named Pipe to Communicate with 32 Bit Process
	hPipe32 = CreateNamedPipe(TEXT("\\\\.\\pipe\\Pipe"), PIPE_ACCESS_DUPLEX | PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
		PIPE_WAIT,
		1,
		1024 * 16,
		1024 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);

	while (hPipe32 != INVALID_HANDLE_VALUE && running)
	{
		if (ConnectNamedPipe(hPipe32, NULL) != FALSE)   // wait for someone to connect to the pipe
		{
			while (ReadFile(hPipe32, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
			{
				/* add terminating zero */
				buffer[dwRead] = '\0';

				/* do something with data in buffer */
				printf("%s", buffer);
				if (!running)break;
			}
		}
		DisconnectNamedPipe(hPipe32);
	}
	
}

//Method used for the DLL pipe listening thread
void pipeListenerDLL() {
	char buffer[10000];
	char time[256];
	char program[5000];
	char eventType[256];
	int key = 0;
	DWORD dwRead;
	HANDLE hPipe32;
	//sqlite3 *database;

	//Create Named Pipe to Communicate with 32 Bit Process
	hPipe32 = CreateNamedPipe(TEXT("\\\\.\\pipe\\PipeDLL"), PIPE_ACCESS_DUPLEX | PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE,
		PIPE_WAIT,
		1,
		10000 * 16,
		10000 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);

	while (hPipe32 != INVALID_HANDLE_VALUE && running)
	{
		if (ConnectNamedPipe(hPipe32, NULL) != FALSE)   // wait for someone to connect to the pipe
		{
			while (ReadFile(hPipe32, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
			{
				/* add terminating zero */
				buffer[dwRead] = '\0';

				int currentBuffer = 0;
				int bufferInd = 0;
				char* curBuffer =  time;
				for (int i = 0; i < dwRead; i++) {		
					if (buffer[i] != '-') {
						curBuffer[bufferInd] = buffer[i];
						if (buffer[i] == '\0')curBuffer[bufferInd] = '\0';
						bufferInd++;
					}
					else {
						currentBuffer++;
						curBuffer[bufferInd] = '\0';
						if (currentBuffer == 1)curBuffer = program;
						if (currentBuffer == 2)curBuffer = eventType;
						bufferInd = 0;
					}
					
				}
				mutex.lock();
				//sqlite3_open("Database.sqlite", &database);
				const char* sql = "INSERT INTO PROGRAM_EVENTS VALUES(?, ?, ?, 0)";
				sqlite3_stmt *statement;
				sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
				sqlite3_bind_text(statement, 1, time, -1, SQLITE_STATIC);
				sqlite3_bind_text(statement, 2, program, -1, SQLITE_STATIC);
				sqlite3_bind_text(statement, 3, eventType, -1, SQLITE_STATIC);
				int result = sqlite3_step(statement);
				key++;
				if (debuggingProgramHook) {
					char sBuffer[10000];
					sprintf_s(sBuffer, buffer);
					OutputDebugStringA(sBuffer);
					OutputDebugString(L"\n");
				}
				//sqlite3_close(database);
				mutex.unlock();
				if (!running)break;
			}
		}

		DisconnectNamedPipe(hPipe32);
		if (!running)break;
	}

}

//Method to inject the program monitoring hook
int injectHook() {
	//Inject Hook
	lib = LoadLibrary(L"D:\\Tom\\Documents\\Bio-Metric-Logger\\hookDLL\\x64\\Debug\\hookDll.dll");
	if (lib) {
		HOOKPROC procedure = (HOOKPROC)GetProcAddress(lib, "procedure"); //Get Procdeure address

		if (procedure) {
			hook = SetWindowsHookEx(WH_CALLWNDPROC, procedure, lib, 0); //Set up the hook
			DWORD test = GetLastError();
			test = test;
		}
		else {
			printf("Can't find function in dll!\n"); //Error if the DLL doesn't contain the addressed procedure
			return -1;
		}
	}
	else {
		printf("Can't find dll!\n"); //Error if the DLL is missing
		return -1;
	}
	if (hook) {
		printf("Hook installed properly!\n\n");
		HookInstalled = true;
	}
	//End Inject Hook
	HookInstalled = true;
	return 0;
}

//Method to start the 32Bit logging software
int startLog32() {
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Start the child process. 
	if (!CreateProcess(L"D:\\Tom\\Documents\\Visual Studio 2015\\Projects\\BioLog32\\Debug\\BioLog32.exe",   // No module name (use command line)
		NULL,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return -1;
	}
}

//Callback method for the URL hook
void CALLBACK WinEventProc(HWINEVENTHOOK hWinEventHook,
	DWORD event,
	HWND hwnd,
	LONG idObject,
	LONG idChild,
	DWORD dwEventThread,
	DWORD dwmsEventTime)
{
	IAccessible* pAcc = NULL;
	VARIANT varChild;
	HRESULT hr = AccessibleObjectFromEvent(hwnd, idObject, idChild, &pAcc, &varChild);
	long *children = new long();

	if ((hr == S_OK) && (pAcc != NULL))
	{
		BSTR bstrName, bstrValue;
		pAcc->get_accValue(varChild, &bstrValue);
		pAcc->get_accChildCount(children);
		pAcc->get_accName(varChild, &bstrName);

		TCHAR className[50];
		GetClassName(hwnd, className, 50);

		if (bstrName) {
			if ((_tcscmp(className, TEXT("Chrome_WidgetWin_1")) == 0) /*&& (wcscmp(bstrName, L"Address and search bar") == 0)*/)
			{
				mutex.lock();
				OutputDebugString(bstrValue);
				OutputDebugString(L"\n");
				const char* sql = "INSERT INTO URLS VALUES(?)";
				sqlite3_stmt *statement;
				sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
				USES_CONVERSION;
				sqlite3_bind_text(statement, 1, OLE2A(bstrValue), -1, SQLITE_STATIC);
				int result = sqlite3_step(statement);
				mutex.unlock();
			}
		}
		if (bstrName) {
			if ((_tcscmp(className, TEXT("Windows.UI.Core.CoreWindow")) == 0) && (wcscmp(bstrName, L"Search or enter web address") == 0))
			{
				mutex.lock();
				OutputDebugString(bstrValue);
				OutputDebugString(className);
				OutputDebugString(L"\n");
				const char* sql = "INSERT INTO URLS VALUES(?)";
				sqlite3_stmt *statement;
				sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
				USES_CONVERSION;
				sqlite3_bind_text(statement, 1, OLE2A(bstrValue), -1, SQLITE_STATIC);
				int result = sqlite3_step(statement);
				mutex.unlock();
			}
		}
		if (bstrName) {
			if (/*(_tcscmp(className, TEXT("Windows.UI.Core.CoreWindow")) == 0) &&*/ (wcscmp(bstrName, L"Search or enter address") == 0))
			{
				mutex.lock();
				OutputDebugString(bstrValue);
				OutputDebugString(className);
				OutputDebugString(L"\n");
				const char* sql = "INSERT INTO URLS VALUES(?)";
				sqlite3_stmt *statement;
				sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
				USES_CONVERSION;
				sqlite3_bind_text(statement, 1, OLE2A(bstrValue), -1, SQLITE_STATIC);
				int result = sqlite3_step(statement);
				mutex.unlock();
			}
		}
		pAcc->Release();
	}
}

//Method to set up the URL logging hook
void Hook()
{
	if (LHook != 0)
		return;

	CoInitialize(NULL);
	LHook = SetWinEventHook(EVENT_OBJECT_FOCUS, EVENT_OBJECT_VALUECHANGE, 0, WinEventProc, 0, 0, WINEVENT_SKIPOWNPROCESS);
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_BIOMETRICLOGGER));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_BIOMETRICLOGGER);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   //Set up Tray Icon
   nid.cbSize = sizeof(nid);
   nid.hWnd = hWnd;
   nid.uFlags = NIF_ICON | NIF_TIP | NIF_GUID;
   static const GUID myGUID = { 0x23977b55, 0x10e0, 0x4041,{ 0xb8, 0x62, 0xb1, 0x95, 0x41, 0x96, 0x36, 0x69 } };
   nid.guidItem = myGUID;
   StringCchCopy(nid.szTip, ARRAYSIZE(nid.szTip), L"Test application");
   LoadIconMetric(hInst, MAKEINTRESOURCE(IDI_SMALL), LIM_SMALL, &(nid.hIcon));
   Shell_NotifyIcon(NIM_ADD, &nid) ? S_OK : E_FAIL;
   //End Set up Tray Icon

   //Update and Show the Window
   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);
   return TRUE;
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
	DWORD exitCode = 0;
	DWORD exitCodeThread = 0;
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
			if (HookInstalled == true) {
				TextOut(hdc, 0 /* X */, 0 /* Y */, L"Hook Installed Correctly", 24 /* Number of chars */);
			}
			else {
				TextOut(hdc, 0 /* X */, 0 /* Y */, L"Hook Not Installed", 18 /* Number of chars */);
			}
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
		//Remove Tray Icon
		Shell_NotifyIcon(NIM_DELETE, &nid) ? S_OK : E_FAIL;
		//Remove Hook
		sqlite3_close(database);
		FreeLibrary(lib);
		UnhookWindowsHookEx(hook);
		//GetExitCodeProcess(pi.hProcess, &exitCode);
		//TerminateThread(pi.hThread, exitCodeThread);
		//TerminateProcess(pi.hProcess, (UINT)exitCode);
		//CloseHandle(pi.hProcess);
		//CloseHandle(pi.hThread);
		running = false;
		pipeThreadDLL.join();
		//End Remove Hook
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
