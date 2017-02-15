#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <mutex>
#include <iostream>
#include <fstream>
#include <string>

HHOOK global;

struct Mutex {
	Mutex() {
		h = ::CreateMutex(nullptr, false, L"{any-GUID-1247965802375274724957}");
	}

	~Mutex() {
		::CloseHandle(h);
	}

	HANDLE h;
};

Mutex mutex;

void dll_write_func(char* extract, char* eventType, int hour, int min, int sec, TCHAR className) {
	HANDLE hPipe;
	DWORD dwWritten = 0;
	char cHour[256];
	char cMin[256];
	char cSec[256];
	char* punc = ":";
	char* punc2 = "-";
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
			278,   // = length of string + terminating '\0' !!!
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
				//LPWSTR className = new TCHAR[260];
				TCHAR className[260];
				GetClassName(data->hwnd, className, 260);
				if (data->message == WM_QUIT)dll_write_func(name, "quit", now->tm_hour, now->tm_min, now->tm_sec, *className);
				if (data->message == WM_CLOSE)dll_write_func(name, "close", now->tm_hour, now->tm_min, now->tm_sec, *className);
				if (data->message == WM_DESTROY)dll_write_func(name, "destroy", now->tm_hour, now->tm_min, now->tm_sec, *className);
				if (data->message == WM_CREATE)dll_write_func(name, "create", now->tm_hour, now->tm_min, now->tm_sec, *className);
				if (data->message == WM_SETFOCUS)dll_write_func(name, "focus", now->tm_hour, now->tm_min, now->tm_sec, *className);
				if (data->message == WM_KILLFOCUS)dll_write_func(name, "lose focus", now->tm_hour, now->tm_min, now->tm_sec, *className);
			}
		}
	}
	return CallNextHookEx(global, nCode, wParam, lParam);
}
