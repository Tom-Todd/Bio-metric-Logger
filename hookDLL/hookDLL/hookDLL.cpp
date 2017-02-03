#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <mutex>
#include <iostream>
#include <fstream>

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
	::WaitForSingleObject(mutex.h, INFINITE);
	std::ofstream f("D:\\Tom\\Desktop\\output.txt", std::ios_base::app | std::ios_base::out);
	f << hour << ":" << min << ":" << sec << " - " << extract << " - " << eventType << " - " << className << std::endl;
	::ReleaseMutex(mutex.h);
}


extern "C" __declspec(dllexport) LRESULT WINAPI procedure(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HC_ACTION) {
		
		//lets extract the data
		auto* data = reinterpret_cast<CWPSTRUCT*>(lParam);
		auto timeNow = time(0);
		struct tm* now = localtime(&timeNow);
		if (data->message == WM_QUIT || data->message == WM_CLOSE || data->message == WM_DESTROY || data->message == WM_CREATE || data->message == WM_SETFOCUS || data->message == WM_KILLFOCUS) {
			//lets get the name of the program closed
			char name[260];
			GetWindowModuleFileNameA(data->hwnd, name, 260);
			//extract only the exe from the path
			//char* extract = (char *)((DWORD)name + lstrlenA(name) - 1);
			//while (extract != '\\')
			//	extract--;
			//extract++;

			//LPWSTR className = new TCHAR[260];
			TCHAR className[260];
			GetClassName(data->hwnd, className, 260);


			//MessageBoxA(0, "A program has been closed", extract, 0);
			if (data->message == WM_QUIT)dll_write_func(name, "quit", now->tm_hour, now->tm_min, now->tm_sec, *className);
			if (data->message == WM_CLOSE)dll_write_func(name, "close", now->tm_hour, now->tm_min, now->tm_sec, *className);
			if (data->message == WM_DESTROY)dll_write_func(name, "destroy", now->tm_hour, now->tm_min, now->tm_sec, *className);
			if (data->message == WM_CREATE)dll_write_func(name, "create", now->tm_hour, now->tm_min, now->tm_sec, *className);
			if (data->message == WM_SETFOCUS)dll_write_func(name, "focus", now->tm_hour, now->tm_min, now->tm_sec, *className);
			if (data->message == WM_KILLFOCUS)dll_write_func(name, "lose focus", now->tm_hour, now->tm_min, now->tm_sec, *className);
		}
		/*if (data->message == WM_SETFOCUS || data->message == WM_KILLFOCUS) {
			char name[260];
			GetWindowModuleFileNameA(data->hwnd, name, 260);
			//extract only the exe from the path
			auto* extract = reinterpret_cast<char *>((reinterpret_cast<DWORD>(name) + lstrlenA(name) - 1));
			while (*extract != '\\')
				extract--;
			extract++;

			//LPWSTR className = new TCHAR[260];
			TCHAR className[260];
			GetClassName(data->hwnd, className, 260);

			//MessageBoxA(0, "A program has been closed", extract, 0);
			if (data->message == WM_SETFOCUS)dll_write_func(extract, "focus", now->tm_hour, now->tm_min, now->tm_sec, *className);
			if (data->message == WM_KILLFOCUS)dll_write_func(extract, "lose focus", now->tm_hour, now->tm_min, now->tm_sec, *className);
		
		}*/
	}
	return CallNextHookEx(global, nCode, wParam, lParam);
}
