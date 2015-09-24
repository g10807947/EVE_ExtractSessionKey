// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include <windows.h>
#include <wincrypt.h>
#include <strsafe.h>

#define ErrorExit(x) { ErrorExit_(x); return retValue; }

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


typedef BOOL (WINAPI *pCryptGenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *);
BOOL WINAPI MyCryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *);

void BeginRedirect();
void StopRedirect();

#define SIZE 6

pCryptGenKey pOrig = NULL;
BYTE origBytes[SIZE] = { 0 };
BYTE jumpBytes[SIZE] = { 0 };
DWORD origProtect, myProtect = PAGE_EXECUTE_READWRITE;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		pOrig = (pCryptGenKey) GetProcAddress(GetModuleHandle(TEXT("advapi32.dll")), "CryptGenKey");
		if (pOrig != NULL)
		{
			VirtualProtect((LPVOID)pOrig, SIZE, PAGE_EXECUTE_READWRITE, &origProtect);
			memcpy(origBytes, pOrig, SIZE);
			VirtualProtect((LPVOID)pOrig, SIZE, origProtect, NULL);

			jumpBytes[0] = 0xE9;
			*((DWORD *)(&jumpBytes[1])) = ((DWORD)MyCryptGenKey - (DWORD)pOrig - 5);
			jumpBytes[5] = 0xC3;

			BeginRedirect();
		}
		break;
	case DLL_PROCESS_DETACH:
		if (pOrig != NULL)
			StopRedirect();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

void BeginRedirect()
{
	VirtualProtect((LPVOID)pOrig, SIZE, PAGE_EXECUTE_READWRITE, &origProtect);
	memcpy(pOrig, jumpBytes, SIZE);
	VirtualProtect((LPVOID)pOrig, SIZE, origProtect, NULL);
}

void StopRedirect()
{
	VirtualProtect((LPVOID)pOrig, SIZE, PAGE_EXECUTE_READWRITE, &origProtect);
	memcpy(pOrig, origBytes, SIZE);
	VirtualProtect((LPVOID)pOrig, SIZE, origProtect, NULL);
}

BOOL WINAPI MyCryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey)
{
	StopRedirect();
	BOOL retValue = CryptGenKey(hProv, Algid, dwFlags, phKey);

	if (!(Algid == 0x6603 && dwFlags == 0xc00001))
	{
		BeginRedirect();
		return retValue;
	}

	HCRYPTKEY exckey = 0;
	if (!CryptGenKey(hProv, AT_KEYEXCHANGE, 0, &exckey))
		ErrorExit(TEXT("CryptGenKey"));

	DWORD size;
	if (!CryptExportKey(*phKey, exckey, SIMPLEBLOB, 0, NULL, &size))
		ErrorExit(TEXT("CryptExportKey"));

	typedef struct {
		BLOBHEADER hdr;
		DWORD      size;
		BYTE       data[1];
	} PLAINTEXTKEYSTRUCT;
	PLAINTEXTKEYSTRUCT *key = (PLAINTEXTKEYSTRUCT *)LocalAlloc(LMEM_FIXED, size);
	if (key == NULL)
		ErrorExit(TEXT("LocalAlloc"));
	if (!CryptExportKey(*phKey, exckey, SIMPLEBLOB, 0, (BYTE *)key, &size))
		ErrorExit(TEXT("CryptExportKey"));

	key->hdr.bType = PLAINTEXTKEYBLOB;
	key->size = size - sizeof(BLOBHEADER) - sizeof(DWORD);

	if (!CryptDecrypt(exckey, 0, TRUE, 0, &(key->data[0]), &(key->size)))
		ErrorExit(TEXT("CryptDecrypt"));

	if (!CryptDestroyKey(exckey))
		ErrorExit(TEXT("CryptExportKey"));

	HANDLE hFile = CreateFile(TEXT("C:\\Users\\User\\Desktop\\eve.key"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		ErrorExit(TEXT("CreateFile"));
	if (!WriteFile(hFile, key, key->size + sizeof(BLOBHEADER) + sizeof(DWORD), &size, NULL))
		ErrorExit(TEXT("WriteFile"));
	if (key->size + sizeof(BLOBHEADER) + sizeof(DWORD) != size)
		ErrorExit(TEXT("Short write"));
	if (!CloseHandle(hFile))
		ErrorExit(TEXT("CloseHandle"));

	LocalFree(key);

	return retValue;
}