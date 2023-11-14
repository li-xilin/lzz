#include "lzz.h"
#include <windows.h>
#include <stdio.h>

#define TOKEN_FILE 0
#define TOKEN_DIR_BEGIN 1
#define TOKEN_DIR_END 2

#define STATUS_SUCCESS 0x00
#define STATUS_BUFFER_ALL_ZEROS 0x117

#define COMPRESSED_BUF_SIZE 0x1000
#define UNCOMPRESSED_BUF_SIZE COMPRESSED_BUF_SIZE - 2

DWORD (WINAPI *_RtlCompressBuffer)(
		ULONG CompressionFormat,
		PVOID SourceBuffer,
		ULONG SourceBufferLength,
		PVOID DestinationBuffer,
		ULONG DestinationBufferLength,
		ULONG TrunkSize,
		PULONG pDestinationSize,
		PVOID WorkspaceBuffer);

DWORD (WINAPI *_RtlDecompressBuffer)(
		ULONG CompressionFormat,
		PVOID DestinationBuffer,
		ULONG DestinationBufferLength,
		PVOID SourceBuffer,
		ULONG SourceBufferLength,
		PULONG pDestinationSize);

DWORD (WINAPI *_RtlGetCompressionWorkSpaceSize)(
		ULONG CompressionFormat,
		PULONG pNeededBufferSize,
		PULONG pUnknown);

LPVOID g_pWorkBuffer = NULL;

static LPWSTR Utf8ToUtf16(LPCSTR pszStr) {
        INT cBuf = MultiByteToWideChar(CP_UTF8, 0, pszStr, -1, NULL, 0);
        if (cBuf == 0)
                return NULL;
        LPWSTR buf = HeapAlloc(GetProcessHeap(), 0, cBuf * sizeof(WCHAR));
        if (!buf)
                return NULL;
        if (cBuf != MultiByteToWideChar(CP_UTF8, 0, pszStr, -1, buf, cBuf)) {
                HeapFree(GetProcessHeap(), 0, buf);
                return NULL;
        }
        return buf;
}

static LPSTR Utf16ToUtf8(LPWSTR pszStr) {
        INT cBuf = WideCharToMultiByte(CP_UTF8, 0, pszStr, -1, NULL, 0, NULL, NULL);
        if (cBuf < 1)
                return NULL;
        LPSTR buf = HeapAlloc(GetProcessHeap(), 0, cBuf);
        if (!buf)
                return NULL;
        if (cBuf != WideCharToMultiByte(CP_UTF8, 0, pszStr, -1, buf, cBuf, NULL, NULL)) {
                HeapFree(GetProcessHeap(), 0, buf);
                return NULL;
        }
        return buf;
}

BOOL LZZ_Init(void)
{
        HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
        _RtlCompressBuffer = (void *)GetProcAddress(hNtdll, "RtlCompressBuffer");
        _RtlDecompressBuffer = (void *)GetProcAddress(hNtdll, "RtlDecompressBuffer");
        _RtlGetCompressionWorkSpaceSize = (void *)GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");

	ULONG uNeedSize, uFragSize;
        _RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &uNeedSize, &uFragSize);
	g_pWorkBuffer = HeapAlloc(GetProcessHeap(), 0, uNeedSize);
	if (!g_pWorkBuffer) {
		FreeLibrary(hNtdll);
		return FALSE;
	}
	return TRUE;
}

VOID LZZ_Exit(void)
{
	HANDLE hNtdll = GetModuleHandleW(L"ntdll.dll");
	FreeLibrary(hNtdll);
	HeapFree(GetProcessHeap(), 0, g_pWorkBuffer);
}

static BOOL WriteFileEntry(LPWIN32_FIND_DATAW pFindData, HANDLE hDestFile)
{
	BOOL bRet = FALSE;
	LPSTR pNameUtf8 = NULL;
	BYTE byNameLen;
	DWORD dwTime = 0;

	BYTE byToken = (pFindData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		? TOKEN_DIR_BEGIN
		: TOKEN_FILE;

	if (!(pNameUtf8 = Utf16ToUtf8(pFindData->cFileName)))
		goto FINISH;


	if (!WriteFile(hDestFile, &byToken, sizeof byToken, NULL, NULL))
		goto FINISH;
	
	ULARGE_INTEGER uiTime = {
		.LowPart = pFindData->ftCreationTime.dwLowDateTime,
		.HighPart = pFindData->ftCreationTime.dwHighDateTime };

	dwTime =  ((LONGLONG)(uiTime.QuadPart - 116444736000000000) / 10000000);

	if (!WriteFile(hDestFile, &dwTime, sizeof dwTime, NULL, NULL))
		goto FINISH;
	
	byNameLen = lstrlenA(pNameUtf8);

	if (!WriteFile(hDestFile, &byNameLen, sizeof byNameLen, NULL, NULL))
		goto FINISH;
	
	if (!WriteFile(hDestFile, pNameUtf8, byNameLen, NULL, NULL))
		goto FINISH;

	bRet = TRUE;
FINISH:
	if (pNameUtf8)
		HeapFree(GetProcessHeap(), 0, pNameUtf8);
	return bRet;
}

static BOOL PackFile(LPWSTR pPath, DWORD dwPathLen, LPWIN32_FIND_DATAW pFindData, HANDLE hDestFile)
{
	BOOL bRetVal = FALSE;

	wprintf(L"%S\n", pPath);

	if (!(pFindData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		HANDLE hSourceFile = CreateFileW(pPath, GENERIC_READ, 0, NULL,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hSourceFile == INVALID_HANDLE_VALUE)
			return TRUE;
		DWORD dwFileSizeHigh, dwFileSize = GetFileSize(hSourceFile, &dwFileSizeHigh);
		if (dwFileSize == INVALID_FILE_SIZE || dwFileSizeHigh != 0) {
			bRetVal = TRUE;
			goto CLOSE_FILE;
		}

		if (!WriteFileEntry(pFindData, hDestFile))
			goto CLOSE_FILE;

		BYTE baBuffer[UNCOMPRESSED_BUF_SIZE];
		DWORD dwBytesRead;
		while (ReadFile(hSourceFile, baBuffer, sizeof baBuffer, &dwBytesRead, NULL)) {
			if (dwBytesRead == 0)
				break;
			BYTE baCompressedBuffer[0x1002];
			DWORD dwCompressedSize;
			DWORD dwCompResult = _RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1, baBuffer, dwBytesRead,
						baCompressedBuffer, sizeof baCompressedBuffer,
						4096, &dwCompressedSize, g_pWorkBuffer);
			if (dwCompResult != STATUS_SUCCESS && dwCompResult != STATUS_BUFFER_ALL_ZEROS) {
				goto CLOSE_FILE;
			}
			WORD wCompressedSize = dwCompressedSize;
			if (!WriteFile(hDestFile, &wCompressedSize, sizeof wCompressedSize, NULL, NULL))
				goto CLOSE_FILE;
			if (!WriteFile(hDestFile, baCompressedBuffer, wCompressedSize, NULL, NULL))
				goto CLOSE_FILE;
		}
		WORD wCompressedSize = 0;
		if (!WriteFile(hDestFile, &wCompressedSize, sizeof wCompressedSize, NULL, NULL))
			goto CLOSE_FILE;

		bRetVal = TRUE;
CLOSE_FILE:
		CloseHandle(hSourceFile);

		return bRetVal;
	}
	else {

		HANDLE hFind;
		WIN32_FIND_DATAW find;

		lstrcatW(pPath + dwPathLen, L"\\*.*");
		hFind = FindFirstFileW(pPath, &find);
		if (hFind == INVALID_HANDLE_VALUE)
			return TRUE;

		if (!WriteFileEntry(pFindData, hDestFile))
			goto CLOSE_FIND;

		do {
			if (lstrcmpW(find.cFileName, L".") == 0 || lstrcmpW(find.cFileName, L"..") == 0)
				continue;

			lstrcpyW(pPath + dwPathLen, L"\\");
			lstrcpyW(pPath + dwPathLen + 1, find.cFileName);

			DWORD dwNameLen = lstrlenW(find.cFileName);
			if (!PackFile(pPath, dwPathLen + 1 + dwNameLen, &find, hDestFile))
				goto CLOSE_FIND;

		} while (FindNextFileW(hFind, &find));

		BYTE byToken = TOKEN_DIR_END;
		if (!WriteFile(hDestFile, &byToken, sizeof byToken, NULL, NULL))
			goto CLOSE_FIND;

		bRetVal = TRUE;
CLOSE_FIND:
		FindClose(hFind);
	}
	return bRetVal;
}

BOOL LZZ_Pack(LPCWSTR pwzSourceList[], LPCWSTR pwzDestFile)
{
	HANDLE hDestFile = CreateFileW(pwzDestFile, GENERIC_WRITE, 0, NULL,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDestFile == INVALID_HANDLE_VALUE)
		return FALSE;
	
	CHAR szMagic[2] = { 'l', 'z' };
	if (!WriteFile(hDestFile, szMagic, sizeof szMagic, NULL, NULL))
		goto FAILED;

	WCHAR wzFileName[MAX_PATH];

	for (int i = 0; pwzSourceList[i]; i++) {
		DWORD dwPathLen = GetFullPathNameW(pwzSourceList[i], sizeof wzFileName / sizeof(WCHAR), wzFileName, NULL);
		if (!dwPathLen)
			continue;

		HANDLE hFind;
		WIN32_FIND_DATAW find;
		hFind = FindFirstFileW(wzFileName, &find);
		if (hFind == INVALID_HANDLE_VALUE)
			continue;

		if (!PackFile(wzFileName, dwPathLen, &find, hDestFile)) {
			FindClose(hFind);
			goto FAILED;
		}
		FindClose(hFind);
	}
	CloseHandle(hDestFile);
	return TRUE;
FAILED:
	CloseHandle(hDestFile);
	DeleteFileW(pwzDestFile);
	return FALSE;
}

static BOOL ReadFileEntry(HANDLE hSourceFile, LPWSTR pName, LPDWORD pCreationTime)
{
	BOOL bRet = FALSE;
	DWORD dwBytesRead;
	CHAR caNameBuf[0x101];
	BYTE byNameLen;
	LPWSTR pNameUtf16 = NULL;

	if (!ReadFile(hSourceFile, pCreationTime, sizeof *pCreationTime, &dwBytesRead, NULL))
		goto FINISH;
	if (dwBytesRead != sizeof *pCreationTime)
		goto FINISH;

	if (!ReadFile(hSourceFile, &byNameLen, sizeof byNameLen, &dwBytesRead, NULL))
		goto FINISH;
	if (dwBytesRead != sizeof byNameLen)
		goto FINISH;

	if (!ReadFile(hSourceFile, caNameBuf, byNameLen, &dwBytesRead, NULL))
		goto FINISH;
	if (dwBytesRead != byNameLen)
		goto FINISH;
	caNameBuf[byNameLen] = '\0';

	if (!(pNameUtf16 = Utf8ToUtf16(caNameBuf)))
		goto FINISH;

	lstrcpyW(pName, pNameUtf16);

	bRet = TRUE;
FINISH:
	if (pNameUtf16)
		HeapFree(GetProcessHeap(), 0, pNameUtf16);
	return bRet;
}

static BOOL CreateDestFile(HANDLE hSourceFile, LPWSTR pwzDestName, DWORD dwCreationTime)
{
	BOOL bRetVal = FALSE;
	DWORD dwBytesRead;
	BYTE baReadBuffer[COMPRESSED_BUF_SIZE];
	BYTE baUncompressedBuffer[UNCOMPRESSED_BUF_SIZE];
	WORD wCompressedSize;
	BOOL bWriteFailed = FALSE;

	wprintf(L"%S\n", pwzDestName);

	HANDLE hDestFile = CreateFileW(pwzDestName, GENERIC_WRITE, 0, NULL,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	while (1) {
		if (!ReadFile(hSourceFile, &wCompressedSize, sizeof wCompressedSize, &dwBytesRead, NULL))
			goto FINISH;
		if (dwBytesRead != sizeof wCompressedSize)
			goto FINISH;

		if (wCompressedSize == 0)
			break;

		if (!ReadFile(hSourceFile, baReadBuffer, wCompressedSize, &dwBytesRead, NULL))
			goto FINISH;
		if (dwBytesRead != wCompressedSize)
			goto FINISH;

		if (hDestFile == INVALID_HANDLE_VALUE)
			continue;

		ULONG ulUncompressedSize;
		if (_RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, baUncompressedBuffer,
					sizeof baUncompressedBuffer,
					baReadBuffer, wCompressedSize, &ulUncompressedSize) == STATUS_SUCCESS) {
			if (!WriteFile(hDestFile, baUncompressedBuffer, ulUncompressedSize, NULL, NULL))
				bWriteFailed = TRUE;
		}
		else
			bWriteFailed = TRUE;

	}
	if (hDestFile != INVALID_HANDLE_VALUE) {
		ULARGE_INTEGER uiTime =  {
			.QuadPart = (LONGLONG)dwCreationTime * 10000000 + 116444736000000000
		};
		FILETIME ft = { .dwHighDateTime = uiTime.HighPart, .dwLowDateTime = uiTime.LowPart };
		SetFileTime(hDestFile, &ft, &ft, &ft);
	}
	bRetVal = TRUE;
FINISH:
	if (hDestFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hDestFile);
		if (bWriteFailed)
			DeleteFileW(pwzDestName);
	}
	
	return bRetVal;
}

static BOOL UnpackFile(HANDLE hSourceFile, LPWSTR pPath, DWORD dwPathLen)
{
	BOOL bRetVal = FALSE;
	DWORD dwBytesRead;
	BYTE byToken;

	while (1) {
		if (!ReadFile(hSourceFile, &byToken, sizeof byToken, &dwBytesRead, NULL))
			goto FINISH;
		if (dwBytesRead != sizeof (byToken))
			goto FINISH;

		WCHAR wzName[MAX_PATH];
		DWORD dwCreationTime;

		if (byToken == TOKEN_DIR_END)
			break;

		if (!ReadFileEntry(hSourceFile, wzName, &dwCreationTime))
			goto FINISH;

		lstrcpyW(pPath + dwPathLen, L"\\");
		lstrcatW(pPath + dwPathLen, wzName);

		if (byToken == TOKEN_FILE) {
			if (!CreateDestFile(hSourceFile, pPath, dwCreationTime))
				goto FINISH;
		}
		else if (byToken == TOKEN_DIR_BEGIN) {
			if (!CreateDirectoryW(pPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
				goto FINISH;
			DWORD dwNameLen = lstrlenW(wzName);
			if (!UnpackFile(hSourceFile, pPath, dwPathLen + dwNameLen + 1))
				goto FINISH;
		}
		else {
			SetLastError(ERROR_BAD_FORMAT);
			goto FINISH;
		}
	}

	bRetVal = TRUE;
FINISH:
	return bRetVal;
}

BOOL LZZ_Unpack(LPCWSTR pwzSourceFile, LPCWSTR pwzDestPath)
{
	BOOL bRetVal = FALSE;
	HANDLE hSourceFile = CreateFileW(pwzSourceFile, GENERIC_READ, 0, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSourceFile == INVALID_HANDLE_VALUE)
		return bRetVal;
	
	BYTE baMagic[2];
	DWORD dwBytesRead;
	if (!ReadFile(hSourceFile, baMagic, sizeof baMagic, &dwBytesRead, NULL))
		goto FINISH;

	if (dwBytesRead != sizeof baMagic)
		goto FINISH;

	if (baMagic[0] != 'l' || baMagic[1] != 'z')
		goto FINISH;

	WCHAR wzFileName[MAX_PATH];
	DWORD dwPathLen = GetFullPathNameW(pwzDestPath, sizeof wzFileName / sizeof(WCHAR), wzFileName, NULL);
	if (!dwPathLen)
		goto FINISH;
	
	bRetVal = UnpackFile(hSourceFile, wzFileName, dwPathLen);
FINISH:
	CloseHandle(hSourceFile);
	return bRetVal;
}

