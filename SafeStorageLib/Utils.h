#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "Commands.h"

#define BUFSIZE 1024
#define MD5LEN  16
#define HASH_SIZE (MD5LEN * 2 + 1)

int SanitizeFilePath2(const TCHAR* filepath, size_t length);

int SanitizeFilePath(const char* filepath, size_t length, LPCSTR appdir);

DWORD EncryptPassword(const BYTE* password, DWORD length, char* hash, DWORD* hashlen);

DWORD VerifyPassword(const BYTE* password, DWORD length, char* hash, DWORD hashlen);

void InsertUser(const char* Username, const char* hash);

int ValidCredentials(const char* Username, uint16_t UsernameLength, const char* Password, uint16_t PasswordLength);

int RetrieveHash(const char* Username, char* retrievedHash, DWORD* retrievedHashLen);

int createUsersDirectory(VOID);
void displayExitMSG(VOID);
int createUsersDatabase(VOID);

int createNewUserDirectory(const char* Username, uint16_t UsernameLength);

int buildUserPathAndCheckIfExists(const char* Username, uint16_t UsernameLength, TCHAR* UserDirPath);
#endif // !_UTILS_H_