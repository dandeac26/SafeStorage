#include "Utils.h"


BOOL createUsersDatabase(VOID)
{
    const TCHAR* fileName = _T("users.txt");

    // check if file exists
    DWORD fileAttributes = GetFileAttributes(fileName);
    if (fileAttributes != INVALID_FILE_ATTRIBUTES &&
        !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        return SUCCESS;
    }

    // if doesn't exist, create it
    HANDLE hFileUsersDB = CreateFile(
        fileName,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFileUsersDB == INVALID_HANDLE_VALUE) {
        printf_s("Error creating file: (%d)", GetLastError());
        return FAIL;
    }

    CloseHandle(hFileUsersDB);

    return SUCCESS;
}


void displayExitMSG(VOID)
{
    printf("\nPress Enter to exit...");
    //getchar();
}

BOOL createUsersDirectory(VOID)
{
    TCHAR dirPath[MAX_PATH];
    _tcscpy_s(dirPath, MAX_PATH, g_AppDir);

    if (PathAppend(dirPath, _T("users")) == 0)
    {
        printf("Error: failed to append users dir to APPDIR.\n");
        return FAIL;
    }

    DWORD attributes = GetFileAttributes(dirPath);

    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        if (!CreateDirectory((LPCWSTR)dirPath, NULL))
        {
            printf_s("CreateDirectory failed (%d)\n", GetLastError());
            return FAIL;
        }
        else return SUCCESS;
    }

    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        printf("Directory exists.\n");
        return SUCCESS;
    }

    printf("Path exists, but it's not a directory.\n");
    return FAIL;
}


BOOL createNewUserDirectory(_In_ const char* Username, _In_ uint16_t UsernameLength)
{
    TCHAR dirPath[MAX_PATH];
    _tcscpy_s(dirPath, MAX_PATH, g_AppDir);

    if (PathAppend(dirPath, _T("users")) == 0)
    {
        printf("Error: failed to append users dir to APPDIR.\n");
        return FAIL;
    }

    TCHAR usr[12];
    uint16_t i;
    for (i = 0; i < UsernameLength; i++)
    {
        usr[i] = Username[i];
    }
    usr[i] = '\0';

    if (PathAppend(dirPath, usr) == 0)
    {
        printf_s("Error: failed to append %s dir to APPDIR.\n", Username);
        return FAIL;
    }

    if (!SanitizeFilePath_UserDir(dirPath, _tcslen(dirPath)))
    {
        printf("sanitize fail\n");
        return FAIL;
    }

    DWORD attributes = GetFileAttributes(dirPath);

    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        if (!CreateDirectory((LPCWSTR)dirPath, NULL))
        {
            printf_s("CreateDirectory failed (%d)\n", GetLastError());
            return FAIL;
        }
        else
        {
            return SUCCESS;
        }
    }

    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        printf("Directory exists.\n");

        // This means that path already exists, which should not during registration, so
        // actually should return fail..
        return FAIL;
    }

    printf("Path exists, but it's not a directory.\n");
    return FAIL;
}

/// disable warning 6386 because it is checked above the line _tcsncpy_s(UserDirPath, MAX_PATH, dirPath, _tcslen(dirPath)) but tool doesn't see it
#pragma warning( push )
#pragma warning( disable : 6386)

_Success_(return) BOOL buildUserPathAndCheckIfExists(_In_ const char* Username, _In_ uint16_t UsernameLength, _Out_ TCHAR* UserDirPath)
{
    if (UserDirPath == NULL) {
        printf("Error: UserDirPath is NULL!\n");
        return FAIL;
    }

    TCHAR dirPath[MAX_PATH];
    _tcscpy_s(dirPath, MAX_PATH, g_AppDir);

    if (PathAppend(dirPath, _T("users")) == 0)
    {
        printf("Error: failed to append users dir to APPDIR.\n");
        return FAIL;
    }

    TCHAR usr[12];
    uint16_t i;
    for (i = 0; i < UsernameLength; i++)
    {
        usr[i] = Username[i];
    }
    usr[i] = '\0';

    if (PathAppend(dirPath, usr) == 0)
    {
        printf_s("Error: failed to append %s dir to APPDIR.\n", Username);
        return FAIL;
    }

    if (!SanitizeFilePath_UserDir(dirPath, _tcslen(dirPath)))
    {
        printf("sanitize fail\n");
        return FAIL;
    }

    DWORD attributes = GetFileAttributes(dirPath);

    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        printf("Directory doesn't exist!\n");
        return FAIL;
    }

    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        printf("Path exists, but its not a directory!\n");
        // If dir doesn't exist already, return fail!
        return FAIL;
    }

    if (_tcslen(dirPath) >= MAX_PATH)
    {
        printf("Resulting file path too long!\n");
        return FAIL;
    }
    if (_tcsncpy_s(UserDirPath, MAX_PATH, dirPath, _tcslen(dirPath)) != 0) { // generates warning but checked above:
        return FAIL;
    }

    return SUCCESS;
}
#pragma warning( pop )

int IsSpecialCharacter(_In_ char ch)
{
    const char* specialChars = "!@#$%^&";
    return strchr(specialChars, ch) != NULL;
}


int SanitizedUsername(_In_ const char* username, _In_ uint16_t length)
{

    if (length < 5 || length > 10)
    {
        return FALSE;
    }

    for (uint16_t i = 0; i < length; i++)
    {
        if (!isalpha((unsigned char)username[i])) {
            return FALSE;
        }
    }

    return TRUE;
}


int SanitizedPassword(_In_ const char* password, _In_ uint16_t length)
{
    if (length < 5 || length > 25) // upper limit - Could cause tests to fail as it is not in the requirements
    {
        return FALSE;
    }

    int hasDigit = FALSE;
    int hasLower = FALSE;
    int hasUpper = FALSE;
    int hasSpecial = FALSE;

    for (uint16_t i = 0; i < length; i++)
    {
        char ch = password[i];
        if (isdigit((unsigned char)ch))
        {
            hasDigit = TRUE;
        }
        else if (islower((unsigned char)ch))
        {
            hasLower = TRUE;
        }
        else if (isupper((unsigned char)ch))
        {
            hasUpper = TRUE;
        }
        else if (IsSpecialCharacter(ch))
        {
            hasSpecial = TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    return hasDigit && hasLower && hasUpper && hasSpecial;
}


BOOL SanitizeFilePath_UserDir(_In_ const TCHAR* filepath, _In_ size_t length)
{
    if (length == 0 || filepath == NULL)
    {
        return FALSE;
    }

    TCHAR resolvedPath[MAX_PATH];

    if (GetFullPathName((LPCWSTR)filepath, MAX_PATH, (LPWSTR)resolvedPath, NULL) == 0)
    {
        return FALSE;
    }

    // checks if its %appdir%/users/username
    if (_tcsncmp(filepath, resolvedPath, _tcslen(filepath)) != 0)
    {
        return FALSE;
    }



    // make sure same base path
    TCHAR resolvedBasePath[MAX_PATH];

    if (GetFullPathName((LPCWSTR)g_AppDir, MAX_PATH, (LPWSTR)resolvedBasePath, NULL) == 0)
    {
        printf("Error Sanitization\n");
        return FALSE;
    }

    if (_tcsncmp(filepath, resolvedBasePath, _tcslen(resolvedBasePath)) != 0)
    {
        printf("Failed base path check\n");
        return FALSE;
    }

    

    for (size_t i = 0; i < length; i++)
    {
        if (filepath[i] == '\0' || filepath[i] == '*' || filepath[i] == '|')
        {
            return FALSE;
        }
    }

    return TRUE;
}


BOOL SanitizeFilePath_Normalization(_In_ const TCHAR* filepath, _In_ size_t length, _In_ const TCHAR* basePath) // with normalization
{
    if (length == 0 || filepath == NULL || basePath == NULL)
    {
        return FALSE;
    }

    TCHAR resolvedFilePath[MAX_PATH];

    if (GetFullPathName((LPCWSTR)filepath, MAX_PATH, (LPWSTR)resolvedFilePath, NULL) == 0)
    {
        return FALSE;
    }

    if (_tcsncmp(resolvedFilePath, basePath, _tcslen(basePath)) != 0)
    {
        printf("Sanitization failed! Directory out of bounds!\n");
        return FALSE;
    }

    for (size_t i = 0; i < length; i++)
    {
        if (filepath[i] == '\0' || filepath[i] == '*' || filepath[i] == '|')
        {
            return FALSE;
        }
    }

    return TRUE;
}

DWORD EncryptPassword(_In_ const BYTE* password, _In_ DWORD length, _Out_opt_ char* hash, _Out_opt_ DWORD* hashlen)
{
    DWORD dwStatus = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    hashlen = malloc(sizeof(DWORD));  // Allocate memory for hashlen
    if (hashlen == NULL) {
        // Handle allocation failure
        printf("Memory allocation failed.\n");
        dwStatus = GetLastError();
        return dwStatus; // or appropriate error handling
    }

    *hashlen = 0;


    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf_s("CryptAcquireContext failed: %d\n", dwStatus);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf_s("CryptCreateHash failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }


    if (!CryptHashData(hHash, password, length, 0))
    {
        dwStatus = GetLastError();
        printf_s("CryptHashData failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return dwStatus;
    }


    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        DWORD j = 0;
        for (DWORD i = 0; i < cbHash; i++)
        {
            hash[j++] = rgbDigits[rgbHash[i] >> 4];
            hash[j++] = rgbDigits[rgbHash[i] & 0xf];
        }
        hash[j] = '\0';
        *hashlen = j + 1;
    }
    else
    {
        *hashlen = 0;
        hash = NULL;
        dwStatus = GetLastError();
        printf_s("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return dwStatus;
}


DWORD VerifyPassword(_In_ const BYTE* password, _In_ DWORD length, _In_ char* hash, _In_ DWORD hashlen)
{
    if (password == NULL || hash == NULL || hashlen != (HASH_SIZE - 1))
    {
        return FALSE;
    }

    
    char generatedHash[HASH_SIZE];
    DWORD generatedHashlen = sizeof(hash);
    if (EncryptPassword(password, length, generatedHash, &generatedHashlen) != 0) {
        return FALSE;
    }

    if (strncmp(generatedHash, hash, hashlen) == 0)
    {
        return TRUE;  // Passwords match
    }

    return FALSE;
}


void InsertUser(_In_ const char* Username, _In_ const char* hash)
{

    HANDLE FileUsersDB = CreateFile(
        _T("users.txt"),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );


    if (FileUsersDB == INVALID_HANDLE_VALUE) {
        printf_s("Failed to open users.txt: %d\n", GetLastError());
        return;
    }


    char lineBuffer[512];
    memset(lineBuffer, 0, sizeof(lineBuffer));
    snprintf(lineBuffer, sizeof(lineBuffer) - 1, "\n%s:%s", Username, hash);


    DWORD bytesWritten;
    BOOL writeSuccess = WriteFile(
        FileUsersDB,
        lineBuffer,
        strlen(lineBuffer),
        &bytesWritten,
        NULL
    );


    if (!writeSuccess || bytesWritten != strlen(lineBuffer)) {
        printf("Failed to write to users.txt: %d\n", GetLastError());
    }
    else {
        printf("User '%s' added successfully.\n", Username);
    }


    CloseHandle(FileUsersDB);
}



BOOL ValidCredentials(_In_ const char* Username, _In_ uint16_t UsernameLength, _In_ const char* Password, _In_ uint16_t PasswordLength)
{
    if (!SanitizedUsername(Username, UsernameLength))
    {
        printf("%s", "Username should contain only English alphabet letters (a - zA - Z) and be between 5 and 10 characters long\n");
        return FALSE;
    }

    if (!SanitizedPassword(Password, PasswordLength))
    {
        printf("%s", "Password must have at least 5 and no more than 25 characters and contain at least one digit, one lowercase letter, one uppercase letter, and at least one special symbol(!@#$%^&)\n");
        return FALSE;
    }

    return TRUE;
}


BOOL RetrieveHash(_In_ const char* Username, _Out_opt_ char* retrievedHash, _Out_opt_ DWORD* retrievedHashLen)
{
    int result = FAIL;

    *retrievedHashLen = (DWORD)malloc(sizeof(DWORD)); 
    if (retrievedHashLen == NULL)
    {
        printf("Memory allocation failed.\n");
        return result;
    }

    *retrievedHashLen = 0;

    HANDLE FileUsersDB = CreateFile(
        _T("users.txt"),
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );


    if (FileUsersDB == INVALID_HANDLE_VALUE)
    {
        return result;
    }

    SetFilePointer(FileUsersDB, 0, NULL, FILE_BEGIN);

    char buffer[256];
    DWORD bytesRead;
    char lineBuffer[512];
    memset(lineBuffer, 0, sizeof(lineBuffer));
    lineBuffer[511] = '\0';
    char* lineEnd = NULL;
    char* Context;

    while (TRUE)
    {
        if (!ReadFile(FileUsersDB, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            printf_s("ReadFile failed: %d\n", GetLastError());
            CloseHandle(FileUsersDB);
            return result;
        }

        if (bytesRead == 0) {
            break;
        }

        buffer[bytesRead] = '\0';

        strncat_s(lineBuffer, sizeof(lineBuffer), buffer, sizeof(lineBuffer) - strlen(lineBuffer) - 1);

        while ((lineEnd = strchr(lineBuffer, '\n')) != NULL) {
            *lineEnd = '\0';

            char* fileUser = strtok_s(lineBuffer, ":", &Context);
            char* encryptedPassword = strtok_s(NULL, ":", &Context);

            if (fileUser && encryptedPassword && strcmp(fileUser, Username) == 0) {
                result = SUCCESS;

                strncpy_s(retrievedHash, HASH_SIZE, encryptedPassword, HASH_SIZE - 1);
                *retrievedHashLen = strlen(encryptedPassword);
                break;
            }

            memmove(lineBuffer, lineEnd + 1, strlen(lineEnd + 1) + 1);
        }

        if (result == SUCCESS) {
            break;
        }
    }


    if (strlen(lineBuffer) > 0 && result != SUCCESS) {
        char* fileUser = strtok_s(lineBuffer, ":", &Context);
        char* encryptedPassword = strtok_s(NULL, ":", &Context);

        if (fileUser && encryptedPassword && strcmp(fileUser, Username) == 0) {
            result = SUCCESS;
            strncpy_s(retrievedHash, HASH_SIZE, encryptedPassword, HASH_SIZE - 1);
            *retrievedHashLen = strlen(encryptedPassword);
        }
    }

    CloseHandle(FileUsersDB);
    
    return result;
}



