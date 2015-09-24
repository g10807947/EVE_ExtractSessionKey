// ExtractSessionKeyInject.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <io.h>
#include <strsafe.h>

#define ErrorExit(x) { ErrorExit_(x); return; }

void ErrorExit_(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	//ExitProcess(dw);
}

#include <TlHelp32.h>

DWORD FindProcessId(const wchar_t *processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap)
		return(result);

	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

										  // Retrieve information about the first process,
										  // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		printf("!!! Failed to gather information on system processes! \n");
		return(NULL);
	}

	do
	{
		printf("Checking process %ls\n", pe32.szExeFile);
		if (0 == wcscmp(processname, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}

void main()
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, FindProcessId(TEXT("exefile.exe")));
	if (hProcess == NULL)
		ErrorExit(TEXT("OpenProcess"));
	HMODULE hKernel32 = GetModuleHandle(TEXT("Kernel32"));
	if (hKernel32 == NULL)
		ErrorExit(TEXT("GetModuleHandle"));

	char szLibPath[] = "ExtractSessionKeyDLL.dll";
	void *pLibRemote = VirtualAllocEx(hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE);
	if (pLibRemote == NULL)
		ErrorExit(TEXT("VirtualAllocEx"));
	if (!WriteProcessMemory(hProcess, pLibRemote, (void *)szLibPath, sizeof(szLibPath), NULL))
		ErrorExit(TEXT("WriteProcessMemory (Load)"));


	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0, NULL);
	if (hThread == NULL)
		ErrorExit(TEXT("CreateRemoteThread (Load)"));
	if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0)
		ErrorExit(TEXT("WaitForSingleObject (Load)"));


	DWORD   hLibModule;
	if (!GetExitCodeThread(hThread, &hLibModule))
		ErrorExit(TEXT("GetExitCodeThread (Load)"));
	if (hLibModule == NULL)
		ErrorExit(TEXT("LoadLibrary (Remote)"));

	if (!CloseHandle(hThread))
		ErrorExit(TEXT("CloseHandle (Load)"));
	if (!VirtualFreeEx(hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE))
		; // ErrorExit(TEXT("VirtualFreeEx"));

	BYTE b[1];
	_read(0, b, sizeof(b));

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32, "FreeLibrary"), (void *)hLibModule, 0, NULL);
	if (hThread == NULL)
		ErrorExit(TEXT("CreateRemoteThread (Unload)"));
	if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0)
		ErrorExit(TEXT("WaitForSingleObject (Unload)"));

	if (!GetExitCodeThread(hThread, &hLibModule))
		ErrorExit(TEXT("GetExitCodeThread (Unload)"));
	if (!hLibModule)
		ErrorExit(TEXT("FreeLibrary (Remote)"));

	if (!CloseHandle(hThread))
		ErrorExit(TEXT("CloseHandle (Unload)"));

    return;
}

