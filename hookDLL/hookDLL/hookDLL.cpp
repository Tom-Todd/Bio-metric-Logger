#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>

HHOOK global;

void dll_write_func(const char* extract, char* eventType, int hour, int min, int sec) {
	HANDLE hPipe;
	DWORD dwWritten = 0;
	char cHour[256];
	char cMin[256];
	char cSec[256];
	char* punc = ":";
	char* punc2 = ",";
	char* punc3 = ";";
	_itoa(hour, cHour, 10);
	_itoa(min, cMin, 10);
	_itoa(sec, cSec, 10);

	char* outPut = cHour; 
	strncat(outPut, punc, 1);
	strncat(outPut, cMin, 2);
	strncat(outPut, punc, 1);
	strncat(outPut, cSec, 2);
	strncat(outPut, punc2, 1);
	strncat(outPut, extract, 256);
	strncat(outPut, punc2, 1);
	strncat(outPut, eventType, 10);
	strncat(outPut, punc3, 1);

		hPipe = CreateFile(TEXT("\\\\.\\pipe\\PipeDLL"),
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (hPipe != INVALID_HANDLE_VALUE)
	{
		WriteFile(hPipe,
			outPut,
			279,   // = length of string + terminating '\0' !!!
			NULL,
			NULL);
		CloseHandle(hPipe);
	}
}


extern "C" __declspec(dllexport) LRESULT WINAPI procedure(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION) {
		//lets extract the data
		auto* data = reinterpret_cast<CWPSTRUCT*>(lParam);
		auto timeNow = time(0);
		struct tm* now = localtime(&timeNow);
		if (data->message == WM_QUIT || data->message == WM_CLOSE || data->message == WM_DESTROY || data->message == WM_CREATE || data->message == WM_SETFOCUS || data->message == WM_KILLFOCUS) {
			//lets get the name of the program closed
			char name[256];
			GetWindowModuleFileNameA(data->hwnd, name, 256);

			if (strcmp( name, "C:\\WINDOWS\\SYSTEM32\\urlmon.dll") != 0 && strlen(name) != 0) {
				//LPWSTR className =  new wchar_t[260];
				char className[256];

				//TCHAR className[260];
				std::string sName(name);
				std::string sName2 = sName.substr(sName.find_last_of("\\")+1, std::string::npos);
				const char* test = sName.c_str();
				if (sName2.length() == 0)test = name;
				
				//if (strcmp(name, "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe") == 0) {
				//	MessageBox(0, L"And text here", L"MessageBox caption", MB_OK);
				//}

				GetClassNameA(data->hwnd, className, 260);
				if (data->message == WM_QUIT)dll_write_func(sName2.c_str(), "quit", now->tm_hour, now->tm_min, now->tm_sec);
				if (data->message == WM_CLOSE)dll_write_func(sName2.c_str(), "close", now->tm_hour, now->tm_min, now->tm_sec);
				if (data->message == WM_DESTROY)dll_write_func(sName2.c_str(), "destroy", now->tm_hour, now->tm_min, now->tm_sec);
				if (data->message == WM_CREATE)dll_write_func(sName2.c_str(), "create", now->tm_hour, now->tm_min, now->tm_sec);
				if (data->message == WM_SETFOCUS)dll_write_func(sName2.c_str(), "focus", now->tm_hour, now->tm_min, now->tm_sec);
				if (data->message == WM_KILLFOCUS)dll_write_func(sName2.c_str(), "lose focus", now->tm_hour, now->tm_min, now->tm_sec);
			}
		}
	}
	return CallNextHookEx(global, nCode, wParam, lParam);
}