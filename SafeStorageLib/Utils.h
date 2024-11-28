#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "Commands.h"

#define BUFSIZE 1024
#define MD5LEN  16
#define HASH_SIZE (MD5LEN * 2 + 1)

// Function to sanitize username
//int SanitizedUsername(const char* username, uint16_t length);
//
//// Function to sanitize password
//int SanitizedPassword(const char* password, uint16_t length);

// Function to sanitize file path
int SanitizeFilePath(const char* filepath, uint16_t length, LPCSTR appdir);

// Function for Encryption
DWORD EncryptPassword(const BYTE* password, DWORD length, char* hash, DWORD* hashlen);

// Function for Decryption

DWORD VerifyPassword(const BYTE* password, DWORD length, char* hash, DWORD hashlen);

void InsertUser(const char* Username, const char* hash);

int ValidCredentials(const char* Username, uint16_t UsernameLength, const char* Password, uint16_t PasswordLength);

int RetrieveHash(const char* Username, char* retrievedHash, DWORD* retrievedHashLen);




#endif // !_UTILS_H_