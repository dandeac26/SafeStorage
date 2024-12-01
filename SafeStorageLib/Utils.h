#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "Commands.h"

#define BUFSIZE 1024
#define MD5LEN  16
#define HASH_SIZE (MD5LEN * 2 + 1)

BOOL SanitizeFilePath_Normalization(const TCHAR* filepath, size_t length, const TCHAR* basePath);

BOOL SanitizeFilePath_UserDir(const TCHAR* filepath, size_t length);


DWORD EncryptPassword(const BYTE* password, DWORD length, char* hash, DWORD* hashlen);

DWORD VerifyPassword(const BYTE* password, DWORD length, char* hash, DWORD hashlen);

void InsertUser(const char* Username, const char* hash);

BOOL ValidCredentials(const char* Username, uint16_t UsernameLength, const char* Password, uint16_t PasswordLength);

BOOL RetrieveHash(const char* Username, char* retrievedHash, DWORD* retrievedHashLen);

BOOL createUsersDirectory(VOID);

void displayExitMSG(VOID);

BOOL createUsersDatabase(VOID);

BOOL createNewUserDirectory(const char* Username, uint16_t UsernameLength);

BOOL buildUserPathAndCheckIfExists(const char* Username, uint16_t UsernameLength, TCHAR* UserDirPath);


#endif // !_UTILS_H_