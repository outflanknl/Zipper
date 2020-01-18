#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE
#define USEWIN32IOAPI

#include <Windows.h>
#include <shlwapi.h>
#include "minizip\zip.h"
#include "minizip\unzip.h"
#include "minizip\iowin32.h"
#include "ReflectiveLoader.h"
#include "zipper.h"

#define ARG_MAX 8191
#define BUF_SIZE 4 * 2048 * 1024
#define ZIP64 1

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "zlib.lib")

BOOL bIsUNCPath = FALSE;
DWORD dwFilesCompressed = 0;
DWORD dwFoldersCompressed = 0;

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;


LPSTR Utf16ToUtf8(LPWSTR lpwWideString) {
	INT strLen = WideCharToMultiByte(CP_UTF8, 0, lpwWideString, -1, NULL, 0, NULL, NULL);
	if (!strLen) {
		return NULL;
	}
	LPSTR lpMultiByteString = (LPSTR)calloc(1, strLen + 1);
	if (!lpMultiByteString) {
		return NULL;
	}
	WideCharToMultiByte(CP_UTF8, 0, lpwWideString, -1, lpMultiByteString, strLen, NULL, NULL);

	return lpMultiByteString;
}

void GenRandomStringW(LPWSTR lpFileName, INT len) {
	static const wchar_t AlphaNum[] =
		L"0123456789"
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz";
	srand(GetTickCount());
	for (INT i = 0; i < len; ++i) {
		lpFileName[i] = AlphaNum[rand() % (_countof(AlphaNum) - 1)];
	}
	lpFileName[len] = 0;
}

BOOL InfoZip(LPWSTR lpwZipName) {
	zlib_filefunc64_def ffunc;
	fill_win32_filefunc64W(&ffunc);

	unzFile uzFile = unzOpen2_64(lpwZipName, &ffunc);
	if (uzFile == NULL) {
		return FALSE;
	}

	unz_file_info64 uzFinfo;
	INT Result = unzGetCurrentFileInfo64(uzFile, &uzFinfo, NULL, 0, NULL, 0, NULL, 0);
	if (Result != UNZ_OK) {
		unzClose(uzFile);
		return FALSE;
	}

	wprintf(L"[+] Uncompressed file size:\t %llu Bytes\n", uzFinfo.uncompressed_size);
	wprintf(L"[+] Compressed file size:\t\t %llu Bytes\n", uzFinfo.compressed_size);

	unzClose(uzFile);

	return TRUE;
}

zipFile CreateZip(LPWSTR lpwZipName) {
	zlib_filefunc64_def ffunc;
	fill_win32_filefunc64W(&ffunc);

	zipFile zFile = zipOpen2_64(lpwZipName, APPEND_STATUS_CREATE, NULL, &ffunc);

	return zFile;
}

BOOL AddFile(zipFile zFile, LPWSTR lpwFilename, BOOL bIgnoreFilePath) {
	BOOL Success;
	LARGE_INTEGER FileSize;
	DWORD dwInputFileSize;
	LPSTR lpFullFilePath = NULL;
	LPSTR lpFileName = NULL;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == NULL) {
		return FALSE;
	}

	_NtFreeVirtualMemory NtFreeVirtualMemory = (_NtFreeVirtualMemory)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtFreeVirtualMemory");
	if (NtFreeVirtualMemory == NULL) {
		exit(FALSE);
	}

	_NtCreateFile NtCreateFile = (_NtCreateFile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
	if (NtCreateFile == NULL) {
		return FALSE;
	}

	_NtReadFile NtReadFile = (_NtReadFile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadFile");
	if (NtReadFile == NULL) {
		return FALSE;
	}

	WCHAR chFileName[ARG_MAX] = { 0 };
	if (bIsUNCPath) {
		lstrcat(chFileName, L"\\??\\UNC");
		wcscat_s(chFileName, _countof(chFileName), lpwFilename + 1);
	}
	else {
		lstrcat(chFileName, L"\\??\\");
		wcscat_s(chFileName, _countof(chFileName), lpwFilename);
	}

	UNICODE_STRING uFileName;
	RtlInitUnicodeString(&uFileName, chFileName);

	HANDLE hSrcFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS Status = NtCreateFile(&hSrcFile, (GENERIC_READ | SYNCHRONIZE), &FileObjectAttributes, &IoStatusBlock, 0,
		0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

	if (hSrcFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	Success = GetFileSizeEx(hSrcFile, &FileSize);
	if ((!Success) || (FileSize.QuadPart > 0xFFFFFFFF))
	{
		return FALSE;
	}
	dwInputFileSize = FileSize.LowPart;

	FILETIME ft;
	GetFileTime(hSrcFile, NULL, NULL, &ft);

	zip_fileinfo zfi = { 0 };
	FileTimeToDosDateTime(&ft, ((LPWORD)&zfi.dosDate) + 1, ((LPWORD)&zfi.dosDate) + 0);

	zfi.internal_fa = 0;
	zfi.external_fa = GetFileAttributes(lpwFilename);

	LPSTR lpFilePathA = Utf16ToUtf8(lpwFilename);
	if (!lpFilePathA) {
		CloseHandle(hSrcFile);
		return FALSE;
	}

	if (bIgnoreFilePath) {
		lpFileName = PathFindFileNameA(lpFilePathA);
	}
	else {
		lpFullFilePath = lpFilePathA;
		lpFileName = PathSkipRootA(lpFullFilePath);
	}

	INT Result = zipOpenNewFileInZip64(zFile, lpFileName, &zfi, NULL, 0, NULL, 0, NULL,
		Z_DEFLATED, Z_DEFAULT_COMPRESSION, ZIP64);
	if (Result != ZIP_OK) {
		CloseHandle(hSrcFile);
		return FALSE;
	}

	PVOID lpBuffer = NULL;
	SIZE_T uSize = BUF_SIZE;
	Status = NtAllocateVirtualMemory(NtCurrentProcess(), &lpBuffer, 0, &uSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (Status != 0) {
		zipCloseFileInZip(zFile);
		CloseHandle(hSrcFile);
		return FALSE;
	}

	ULONG uBytesRead = 0;
	ULONG uBytesWritten = 0;

	while (Result == ZIP_OK && uBytesWritten < dwInputFileSize) {
		Status = NtReadFile(hSrcFile, 0, NULL, NULL, &IoStatusBlock, lpBuffer, BUF_SIZE, 0, NULL);
		uBytesRead = IoStatusBlock.Information;
		if (Status != 0) {
			CloseHandle(hSrcFile);
			return FALSE;
		}

		uBytesWritten += uBytesRead;

		if (uBytesRead)
			Result = zipWriteInFileInZip(zFile, lpBuffer, uBytesRead);
		else
			break;
	}

	Status = NtFreeVirtualMemory(NtCurrentProcess(), &lpBuffer, &uSize, MEM_RELEASE);

	zipCloseFileInZip(zFile);
	CloseHandle(hSrcFile);

	dwFilesCompressed++;

	return TRUE;
}

BOOL AddFolder(zipFile zFile, LPWSTR lpwFoldername) {
	LPSTR lpFolderName = NULL;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	_NtCreateFile NtCreateFile = (_NtCreateFile)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
	if (NtCreateFile == NULL) {
		return FALSE;
	}

	PathAddBackslash(lpwFoldername);

	LPWSTR lpDotPath = StrStr(lpwFoldername, L"\\.\\");
	LPWSTR lpDotDotPath = StrStr(lpwFoldername, L"\\..\\");
	if (lpDotPath || lpDotDotPath) {
		return TRUE;
	}

	WCHAR chFolderName[ARG_MAX] = { 0 };
	if (bIsUNCPath) {
		lstrcat(chFolderName, L"\\??\\UNC");
		wcscat_s(chFolderName, _countof(chFolderName), lpwFoldername + 1);
	}
	else {
		lstrcat(chFolderName, L"\\??\\");
		wcscat_s(chFolderName, _countof(chFolderName), lpwFoldername);
	}

	UNICODE_STRING uFolderName;
	RtlInitUnicodeString(&uFolderName, chFolderName);

	HANDLE hSrcFolder = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &uFolderName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS Status = NtCreateFile(&hSrcFolder, (GENERIC_READ | SYNCHRONIZE), &FileObjectAttributes, &IoStatusBlock, 0,
		0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, NULL, 0);

	if (hSrcFolder == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	FILETIME ft;
	GetFileTime(hSrcFolder, NULL, NULL, &ft);

	zip_fileinfo zfi = { 0 };
	FileTimeToDosDateTime(&ft, ((LPWORD)&zfi.dosDate) + 1, ((LPWORD)&zfi.dosDate) + 0);

	zfi.internal_fa = 0;
	zfi.external_fa = GetFileAttributes(lpwFoldername);

	LPSTR lpFolderNameA = Utf16ToUtf8(lpwFoldername);
	if (!lpFolderNameA) {
		return FALSE;
	}

	lpFolderName = PathSkipRootA(lpFolderNameA);

	if (lpFolderName != NULL) {
		INT Result = zipOpenNewFileInZip64(zFile, lpFolderName, &zfi, NULL, 0, NULL, 0, NULL,
			Z_DEFLATED, Z_DEFAULT_COMPRESSION, ZIP64);
		if (Result != ZIP_OK) {
			CloseHandle(hSrcFolder);
			return FALSE;
		}
	}

	zipCloseFileInZip(zFile);
	CloseHandle(hSrcFolder);

	dwFoldersCompressed++;

	WCHAR wcWildCard[ARG_MAX] = { 0 };
	lstrcpy(wcWildCard, lpwFoldername);
	lstrcat(wcWildCard, L"*");

	WIN32_FIND_DATA findData;
	HANDLE hFindFile = FindFirstFile(wcWildCard, &findData);
	if (hFindFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	do
	{
		WCHAR wcFullPath[ARG_MAX] = { 0 };
		lstrcpy(wcFullPath, lpwFoldername);
		lstrcat(wcFullPath, findData.cFileName);

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			AddFolder(zFile, wcFullPath);
		}
		else {
			AddFile(zFile, wcFullPath, FALSE);
		}
	} while (FindNextFile(hFindFile, &findData));

	return TRUE;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	LPWSTR pwszParams = (LPWSTR)calloc(strlen((LPSTR)lpReserved) + 1, sizeof(WCHAR));
	size_t convertedChars = 0;
	size_t newsize = strlen((LPSTR)lpReserved) + 1;

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		if (lpReserved != NULL) {

			// Handle the command line arguments.
			mbstowcs_s(&convertedChars, pwszParams, newsize, (LPSTR)lpReserved, _TRUNCATE);

			BOOL IsDirectory = FALSE;
			BOOL bIgnoreFullPath = TRUE;

			if (!PathFileExists(pwszParams)) {
				wprintf(L"[!] Path does not exist.\n\n");
				fflush(stdout);
				ExitProcess(0);
			}

			wprintf(L" __________.__                                   \n");
			wprintf(L" \\____    /|__|_____ ______   ___________       \n");
			wprintf(L"   /     / |  \\____ \\\\____ \\_/ __ \\_  __ \\ \n");
			wprintf(L"  /     /_ |  |  |_> >  |_> >  ___/|  | \\/      \n");
			wprintf(L" /_______ \\|__|   __/|   __/ \\___  >__|        \n");
			wprintf(L"         \\/   |__|   |__|        \\/            \n");
			wprintf(L"                         Outflank Zipper        \n");
			wprintf(L"                    By Cneeliz @Outflank 2020   \n\n");

			if (PathIsDirectory(pwszParams)) {
				IsDirectory = TRUE;
			}

			if (PathIsUNC(pwszParams)) {
				bIsUNCPath = TRUE;
			}

			WCHAR wcZipContent[ARG_MAX] = { 0 };
			lstrcat(wcZipContent, pwszParams);

			WCHAR chZipPath[MAX_PATH];
			DWORD dwRetVal = GetTempPath(MAX_PATH, chZipPath);
			if (dwRetVal == 0) {
				fflush(stdout);
				ExitProcess(0);
			}

			WCHAR chFileName[MAX_PATH] = { 0 };
			GenRandomStringW(chFileName, 12);
			lstrcat(chZipPath, chFileName);
			lstrcat(chZipPath, L".zip");

			zipFile zFile = CreateZip(chZipPath);
			if (zFile == NULL) {
				fflush(stdout);
				ExitProcess(0);
			}

			if (IsDirectory == FALSE) {
				if (!AddFile(zFile, wcZipContent, bIgnoreFullPath)) {
					wprintf(L"[!] Failed to compress %ls\n\n", wcZipContent);
					zipClose(zFile, NULL);
					fflush(stdout);
					ExitProcess(0);
				}
			}
			else {
				if (!AddFolder(zFile, wcZipContent)) {
					wprintf(L"[!] Failed to compress %ls\n\n", wcZipContent);
					zipClose(zFile, NULL);
					fflush(stdout);
					ExitProcess(0);
				}
			}

			zipClose(zFile, NULL);

			wprintf(L"[+] Zipfile saved as:\t\t %ls\n", chZipPath);
			if (IsDirectory == FALSE) {
				InfoZip(chZipPath);
			}

			wprintf(L"[+] Total files compressed:\t %d\n", dwFilesCompressed);
			wprintf(L"[+] Total folders compressed:\t %d\n", dwFoldersCompressed);	
		}

		// Flush STDOUT
		fflush(stdout);

		// We're done, so let's exit
		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
