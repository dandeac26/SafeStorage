#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "Commands.h"

#define BUFSIZE 1024
#define MD5LEN  16
#define HASH_SIZE (MD5LEN * 2 + 1)

BOOL SanitizeFilePath_Normalization(
	_In_ const TCHAR* filepath,
	_In_ size_t length,
	_In_ const TCHAR* basePath);


BOOL SanitizeFilePath_UserDir(
	_In_ const TCHAR* filepath,
	_In_ size_t length);

DWORD EncryptPassword(
	_In_ const BYTE* password,
	_In_ DWORD length,
	_Out_opt_ char* hash,
	_Out_opt_ DWORD* hashlen);

DWORD VerifyPassword(
	_In_ const BYTE* password,
	_In_ DWORD length,
	_In_ char* hash,
	_In_ DWORD hashlen);

void InsertUser(
	_In_ const char* Username,
	_In_ const char* hash);

BOOL ValidCredentials(
	_In_ const char* Username,
	_In_ uint16_t UsernameLength,
	_In_ const char* Password,
	_In_ uint16_t PasswordLength);

BOOL RetrieveHash(
	_In_ const char* Username,
	_Out_opt_ char* retrievedHash,
	_Out_opt_ DWORD* retrievedHashLen);

BOOL createUsersDirectory(VOID);

void displayExitMSG(VOID);

BOOL createUsersDatabase(VOID);

BOOL createNewUserDirectory(
	_In_ const char* Username,
	_In_ uint16_t UsernameLength);

_Success_(return) BOOL buildUserPathAndCheckIfExists(
	_In_ const char* Username,
	_In_ uint16_t UsernameLength,
	_Out_ TCHAR* UserDirPath);


#endif // !_UTILS_H_