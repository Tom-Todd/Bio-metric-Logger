#include "stdafx.h"
#include "BiometricLogger.h"
#include <Shellapi.h>
#include <Windows.h>
#include <Winuser.h>
#include <Strsafe.h>
#include "sqlite3.h"
#include <thread>
#include <atomic>
#include <vector>
#include <CommCtrl.h>
#include <oleacc.h>
#include <stdio.h>
#include <tchar.h>
#include <conio.h>
#include <mutex>
#include <urlmon.h>
#include <AtlConv.h>
#include "HelperMethods.h"
//#include "dll.h"
#include "cryptlib.h"
#include "hex.h"
#include "cryptlib.h"
#include "filters.h"    // StringSink
#include "osrng.h"      // AutoSeededRandomPool
#include "hex.h"        // HexEncoder
#include "sha.h"
#include "md5.h"
#include "base64.h"


#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"urlmon.lib")
#pragma comment (lib, "cryptlib.lib")

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
//The Handle of the hook used for applications
HHOOK hook;
//The DLL used for application hooking
HMODULE lib;
//The window handle
HWND hWnd;
//Information on the 32 bit thread
STARTUPINFO si;
PROCESS_INFORMATION pi;
//Hook for the URL logging
HWINEVENTHOOK LHook = 0;
//Start the threads for listening to pipes from the other process and DLLs
std::thread pipeThread32;
std::thread pipeThreadDLL;
std::thread databaseOut;
//Is the program running, if not end the threads
bool running = true;
//Did the hook install correctly?
bool HookInstalled = false;
//If debugging the hook make true for console output
bool debuggingProgramHook = false;
//Database connection
sqlite3 *database;
//Mutex for the database
std::mutex mutex;
//Mutex for the program data vector
std::mutex DBStmt_lock;
//Boolean idicating if the program is running under 64 bit windows.
BOOL is64;
std::string previousURLEdge = "";
std::string previousURLChrome = "";
std::string previousURLFirefox = "";


// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
//void pipeListener();
void pipeListenerDLL(); //Method for the pipe listening thread
void databaseOutput(); //Method for the database Output thread
int injectHook(); //Method to inject the program hook
int startLog64(); //Method to start the 64bit process
void Hook(); //Method to hook for URL fetching
struct programData; //Structure to hold returned data from the DLL
void push_statement(programData line); //Method to push 
bool try_pop_statement(programData &out);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow){
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_BIOMETRICLOGGER, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

	IsWow64Process(GetCurrentProcess(), &is64);
    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }
	//Inject the hook and check for error
	if (injectHook() == -1)return -1;
	//Start a new thread to listen for messages from the hooks
	pipeThreadDLL = std::thread(pipeListenerDLL);
	//Start a new thread to handle database output
	databaseOut = std::thread(databaseOutput);
	//Start the 64 bit process and check for error
	if (is64) { //Check if this is 64 bit windows
		if (startLog64() == -1)return -1;
	}
	//Lock the mutex for the database
	mutex.lock();
	CreateDirectory(L"C:\\BiometricLoggerDatabase", NULL);
	sqlite3_open("C:\\BiometricLoggerDatabase\\Database.sqlite", &database);
	const char* sql = "CREATE TABLE PROGRAM_EVENTS("
		"ID INTEGER PRIMARY        KEY      NOT NULL,"
		/*"TIME				   TEXT     NOT NULL,"*/
		"HOUR				   INT     NOT NULL,"
		"MINUTE				   INT     NOT NULL,"
		"SECOND				   INT     NOT NULL,"
		"PROGRAM_NAME          TEXT     NOT NULL,"
		"EVENT				   TEXT     NOT NULL);";

	const char* sql2 = "CREATE TABLE URLS("
		"ID INTEGER PRIMARY        KEY      NOT NULL,"
		/*"TIME				   TEXT     NOT NULL,"*/
		"HOUR				   INT     NOT NULL,"
		"MINUTE				   INT     NOT NULL,"
		"SECOND				   INT     NOT NULL,"
		"URL				   TEXT     NOT NULL);";

	/* Execute SQL statement */
	int rc = sqlite3_exec(database, sql, NULL, NULL, NULL);
	int rc2 = sqlite3_exec(database, sql2, NULL, NULL, NULL);
	//Unlock, statements done.
	mutex.unlock();
	
	//Hook browsers for URL tracking
	Hook();

	//Window message loop
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


//Vector containing data the DLL has sent back
//This is used to output to the database
std::vector<programData> programDataLines;

//Access methods for the programDataLines vector
void push_statement(programData line) {
	std::lock_guard<std::mutex> lock(DBStmt_lock);
	programDataLines.push_back(line);
}

//Access methods for the programDataLines vector
bool try_pop_statement(programData &out) {
	if (programDataLines.size() > 0) {
		std::lock_guard<std::mutex> lock(DBStmt_lock);
		out = programDataLines.back();
		programDataLines.pop_back();
		return true;
	}
	return false;
}


//Database output thread
//Continuously loops checking if there is data to be output in the
//programDataLines vector
void databaseOutput() {
	//int key = 0;
	while (running) {
		programData data;
			while(try_pop_statement(data)){
				int ind = 0;
				int indBuf = 0;
				int part = 0;
				int hour = 0;
				int min = 0;
				int sec = 0;
				char* buffer = new char[256];
				while (ind < 256) {
					buffer[indBuf] = data.time[ind];
					if (buffer[indBuf] == ':') {
						buffer[indBuf] = '\0';
						if (part == 0)hour = atoi(buffer);
						if (part == 1)min = atoi(buffer);
						if (part == 2)sec = atoi(buffer);
						part++;
						buffer = new char[256];
						indBuf = 0;
					}
					else if (buffer[indBuf] == '\0') {
						if (part == 2)sec = atoi(buffer);
						break;
					}
					else {
						indBuf++;
					}
					ind++;
				}
				
				std::lock_guard<std::mutex> lock(mutex);
				const char* sql = "INSERT INTO PROGRAM_EVENTS VALUES(NULL, ?, ?, ?, ?, ?)";
				sqlite3_stmt *statement;
				sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
				/*sqlite3_bind_text(statement, 1, data.time, -1, SQLITE_STATIC);
				sqlite3_bind_text(statement, 2, data.program, -1, SQLITE_STATIC);
				sqlite3_bind_text(statement, 3, data.eventType, -1, SQLITE_STATIC);*/
				sqlite3_bind_int(statement, 1, hour);
				sqlite3_bind_int(statement, 2, min);
				sqlite3_bind_int(statement, 3, sec);
				sqlite3_bind_text(statement, 4, data.program, -1, SQLITE_STATIC);
				sqlite3_bind_text(statement, 5, data.eventType, -1, SQLITE_STATIC);
				OutputDebugStringA(data.time);
				OutputDebugStringA(data.program);
				OutputDebugStringA(data.eventType);
				OutputDebugString(L"\n");
				int result = sqlite3_step(statement);
				int test = result;
				delete(buffer);
			}
			Sleep(500);		
	}
}


//Method used for the DLL pipe listening thread
void pipeListenerDLL() {
	char buffer[1000];
	programData data;
	DWORD dwRead;
	HANDLE hPipe32;

	//Create Named Pipe to Communicate with DLL hook
	hPipe32 = CreateNamedPipe(TEXT("\\\\.\\pipe\\PipeDLL"), PIPE_ACCESS_DUPLEX | PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE,
		PIPE_WAIT,
		1,
		300 * 16,
		300 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);

	while (hPipe32 != INVALID_HANDLE_VALUE && running)
	{
		if (ConnectNamedPipe(hPipe32, NULL) != FALSE && running)   // wait for someone to connect to the pipe
		{
			while ((ReadFile(hPipe32, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE) && running)
			{
				/* add terminating zero */
				buffer[dwRead] = '\0';

				int currentBuffer = 0;
				int bufferInd = 0;
				char* curBuffer =  data.time;
				for (int i = 0; i < dwRead; i++) {		
					if (buffer[i] != ',') {
						curBuffer[bufferInd] = buffer[i];
						if (buffer[i] == '\0')curBuffer[bufferInd] = '\0';
						if (buffer[i] == ';') {
							curBuffer[bufferInd] = '\0';
							break;
						}
						bufferInd++;
					}else {
						currentBuffer++;
						curBuffer[bufferInd] = '\0';
						if (currentBuffer == 1)curBuffer = data.program;
						if (currentBuffer == 2)curBuffer = data.eventType;
						bufferInd = 0;
					}
				}
				if (strcmp(data.program, "combase.dll") != 0) {
					push_statement(data);
				}
				if (debuggingProgramHook) {
					char sBuffer[10000];
					sprintf_s(sBuffer, buffer);
					OutputDebugStringA("RAW: ");
					OutputDebugStringA(sBuffer);
					OutputDebugString(L"\n");
				}
				if (!running) {
					return;
				}
			}
			if (!running) {
				return;
			}
		}
		DisconnectNamedPipe(hPipe32);
		if (!running) {
			return;
		}
	}
}

//Method to inject the program monitoring hook
int injectHook() {
	wchar_t curDir[1000];
	GetCurrentDirectory(1000, curDir);
	std::wstring dir(curDir);
	dir += std::wstring(TEXT("\\bin\\hookDll.dll"));
	//Inject Hook
	lib = LoadLibrary(/*L"D:\\Tom\\Documents\\Bio-Metric-Logger\\hookDLL\\Debug\\hookDll.dll"*/dir.c_str()); //Load DLL
	if (lib) {
		HOOKPROC procedure = (HOOKPROC)GetProcAddress(lib, "_procedure@12"); //Get Procdeure address

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

//Method to start the 64Bit logging software
int startLog64() {
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	
	wchar_t curDir[1000];
	GetCurrentDirectory(1000, curDir);
	std::wstring dir(curDir);
	dir += std::wstring(TEXT("\\BioLog64\\BioLog64.exe"));

	// Start the child process. 
	if (!CreateProcess(dir.c_str(),   // No module name (use command line)
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
	auto timeNow = time(0);
	struct tm* now = localtime(&timeNow);
	char cHour[256];
	char cMin[256];
	char cSec[256];
	char* punc = ":";
	_itoa(now->tm_hour, cHour, 10);
	_itoa(now->tm_min, cMin, 10);
	_itoa(now->tm_sec, cSec, 10);
	char* time = cHour;
	strncat(time, punc, 1);
	strncat(time, cMin, 2);
	strncat(time, punc, 1);
	strncat(time, cSec, 2);
	CryptoPP::SHA256 hashN;

	if ((hr == S_OK) && (pAcc != NULL))
	{
		BSTR bstrName, bstrValue, bstrDescription;
		pAcc->get_accValue(varChild, &bstrValue);
		pAcc->get_accChildCount(children);
		pAcc->get_accName(varChild, &bstrName);
		pAcc->get_accDescription(varChild, &bstrDescription);

		TCHAR className[50];
		GetClassName(hwnd, className, 50);

		if (bstrName) {
			if ((_tcscmp(className, TEXT("Chrome_WidgetWin_1")) == 0) && (wcscmp(bstrName, L"Address and search bar") == 0) && bstrValue != NULL)
			{
				USES_CONVERSION;
				if (wcsstr(bstrValue, L"https://") == NULL && !(wcsstr(bstrValue, L".") == NULL)) {
					char tmpStr[300] = "http://";
					strncat(tmpStr, OLE2A(bstrValue), 256);
					bstrValue = A2OLE(tmpStr);
					
				}
				if (IsValidURL(NULL, bstrValue, 0) == S_OK) {
					std::string url = parse_url(OLE2A(bstrValue));
					if (url.substr(0, 4).compare("www.") == 0) {
						url = url.substr(4, std::string::npos);
					}
					if (previousURLChrome.compare("") == 0 || previousURLChrome.compare(url) != 0) {
						std::lock_guard<std::mutex> lock(mutex);
						const char* sql = "INSERT INTO URLS VALUES(NULL, ?, ?, ?, ?)";
						sqlite3_stmt *statement;
						sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
						if (strcmp("chrome-extension", url.c_str()) != 0) {
							std::string digest;
							CryptoPP::StringSource foo(url, true, new CryptoPP::HashFilter(hashN, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(digest))));
							OutputDebugStringA(digest.c_str());
							OutputDebugString(L"\n");
							sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
							//sqlite3_bind_text(statement, 1, time, -1, SQLITE_STATIC);
							sqlite3_bind_int(statement, 1, now->tm_hour);
							sqlite3_bind_int(statement, 2, now->tm_min);
							sqlite3_bind_int(statement, 3, now->tm_sec);
							sqlite3_bind_text(statement, 4, digest.c_str(), -1, SQLITE_STATIC);
						}
						int result = sqlite3_step(statement);
						previousURLChrome = url;
					}
				}
			}
		}
		if (bstrName) {
			if ((_tcscmp(className, TEXT("Windows.UI.Core.CoreWindow")) == 0) && (wcscmp(bstrName, L"Search or enter web address") == 0) && bstrValue != NULL)
			{
				USES_CONVERSION;
				if (wcsstr(bstrValue, L"https://") == NULL && !(wcsstr(bstrValue, L".") == NULL)) {
					char tmpStr[300] = "http://";
					strncat(tmpStr, OLE2A(bstrValue), 256);
					bstrValue = A2OLE(tmpStr);

				}
				if (IsValidURL(NULL, bstrValue, 0) == S_OK) {
					std::string url = parse_url(OLE2A(bstrValue));
					if (url.substr(0, 4).compare("www.") == 0) {
						url = url.substr(4, std::string::npos);
					}
					if (previousURLEdge.compare("") == 0 || previousURLEdge.compare(url) != 0) {
						std::lock_guard<std::mutex> lock(mutex);
						const char* sql = "INSERT INTO URLS VALUES(NULL, ?, ?, ?, ?)";
						sqlite3_stmt *statement;
						sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
						std::string digest;
						CryptoPP::StringSource foo(url, true, new CryptoPP::HashFilter(hashN, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(digest))));
						OutputDebugStringA(digest.c_str());
						OutputDebugString(L"\n");
						sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
						sqlite3_bind_int(statement, 1, now->tm_hour);
						sqlite3_bind_int(statement, 2, now->tm_min);
						sqlite3_bind_int(statement, 3, now->tm_sec);
						sqlite3_bind_text(statement, 4, digest.c_str(), -1, SQLITE_STATIC);
						int result = sqlite3_step(statement);
						previousURLEdge = url;
					}
				}
			}
		}
		if (bstrName) {
			if ((_tcscmp(className, TEXT("MozillaWindowClass")) == 0) && (wcscmp(bstrName, L"Search or enter address") == 0) && bstrValue != NULL)
			{
				USES_CONVERSION;
				if (wcsstr(bstrValue, L"https://") == NULL && !(wcsstr(bstrValue, L".") == NULL)) {
					char tmpStr[300] = "http://";
					strncat(tmpStr, OLE2A(bstrValue), 256);
					bstrValue = A2OLE(tmpStr);
				}
				if (IsValidURL(NULL, bstrValue, 0) == S_OK) {
					std::string url = parse_url(OLE2A(bstrValue));
					if (url.substr(0, 4).compare("www.") == 0) {
						url = url.substr(4, std::string::npos);
					}
					if (previousURLFirefox.compare("") == 0 || previousURLFirefox.compare(url) != 0) {
						std::lock_guard<std::mutex> lock(mutex);
						const char* sql = "INSERT INTO URLS VALUES(NULL, ?, ?, ?, ?)";
						sqlite3_stmt *statement;
						std::string digest;
						CryptoPP::StringSource foo(url, true, new CryptoPP::HashFilter(hashN, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(digest))));
						OutputDebugStringA(digest.c_str());
						OutputDebugString(L"\n");
						sqlite3_prepare_v2(database, sql, strlen(sql), &statement, NULL);
						sqlite3_bind_int(statement, 1, now->tm_hour);
						sqlite3_bind_int(statement, 2, now->tm_min);
						sqlite3_bind_int(statement, 3, now->tm_sec);
						sqlite3_bind_text(statement, 4, digest.c_str(), -1, SQLITE_STATIC);
						int result = sqlite3_step(statement);
						previousURLFirefox = url;
					}
				}
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

void Unhook()
{
	if (LHook == 0)
		return;

	UnhookWinEvent(LHook);
	CoUninitialize();
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
   //Update and Show the Window
   //ShowWindow(hWnd, nCmdShow);
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
		//Remove Hook
		running = false;
		if (is64) {
			GetExitCodeProcess(pi.hProcess, &exitCode);
			TerminateThread(pi.hThread, exitCodeThread);
			TerminateProcess(pi.hProcess, (UINT)exitCode);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}		
		pipeThreadDLL.join();
		databaseOut.join();
		Unhook();
		UnhookWindowsHookEx(hook);
		sqlite3_close(database);
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
