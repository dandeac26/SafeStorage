#include "Utils.h"


int createUsersDatabase(VOID)
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
    g_hFileUsersDB = CreateFile(
        fileName,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    // Check if the file was created successfully
    if (g_hFileUsersDB == INVALID_HANDLE_VALUE) {
        printf("Error creating file: (%d)", GetLastError());
        return FAIL;
    }
    return SUCCESS;
}


void displayExitMSG(VOID)
{
    printf("\nPress Enter to exit...");
    //getchar();
}

int createUsersDirectory(VOID)
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
            printf("CreateDirectory failed (%d)\n", GetLastError());
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


int createNewUserDirectory(const char* Username, uint16_t UsernameLength)
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
        printf("Error: failed to append %s dir to APPDIR.\n", Username);
        return FAIL;
    }

    if (!SanitizeFilePath2(dirPath, _tcslen(dirPath)))
    {
        //_tprintf(TEXT("Bad path: %s"), dirPath);
        printf("sanitize fail\n");
        return FAIL;
    }

    DWORD attributes = GetFileAttributes(dirPath);

    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        if (!CreateDirectory((LPCWSTR)dirPath, NULL))
        {
            printf("CreateDirectory failed (%d)\n", GetLastError());
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


int buildUserPathAndCheckIfExists(const char* Username, uint16_t UsernameLength, TCHAR* UserDirPath)
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
        printf("Error: failed to append %s dir to APPDIR.\n", Username);
        return FAIL;
    }

    if (!SanitizeFilePath2(dirPath, _tcslen(dirPath)))
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

    if (_tcsncpy_s(UserDirPath, MAX_PATH, dirPath, _tcslen(dirPath)) != 0) {
        return FAIL;
    }
    // need to check if a file named as directory exists maybe? but i hope file atrib directory handles this
    return SUCCESS;
}


int IsSpecialCharacter(char ch)
{
    const char* specialChars = "!@#$%^&";
    return strchr(specialChars, ch) != NULL;
}


int SanitizedUsername(const char* username, uint16_t length)
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


int SanitizedPassword(const char* password, uint16_t length)
{
    if (length < 5 || length > 25)
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


int SanitizeFilePath(const char* filepath, size_t length, LPCSTR appdir)
{
    if (length == 0 || filepath == NULL)
    {
        return FALSE;
    }


    char normalizedPath[MAX_PATH] = { 0 };
    char resolvedBasePath[MAX_PATH] = { 0 };


    // Normalization strategy
    if (GetFullPathNameA(filepath, MAX_PATH, normalizedPath, NULL) == 0)
    {
        return FALSE;
    }


    if (GetFullPathNameA(appdir, MAX_PATH, resolvedBasePath, NULL) == 0)
    {
        return FALSE;
    }


    if (strncmp(normalizedPath, resolvedBasePath, strlen(resolvedBasePath)) != 0)
    {
        return FALSE;
    }


    for (size_t i = 0; i < length; i++)
    {
        if (filepath[i] == '\0')
        {
            return FALSE;
        }
        if (i < length - 1 && filepath[i] == '.' && filepath[i + 1] == '.')
        {
            return FALSE;
        }
    }


    return TRUE;
}


int SanitizeFilePath2(const TCHAR* filepath, size_t length) // with normalization
{
    if (length == 0 || filepath == NULL)
    {
        return FALSE;
    }

    TCHAR resolvedBasePath[MAX_PATH];

    if (GetFullPathName((LPCWSTR)filepath, MAX_PATH, (LPWSTR)resolvedBasePath, NULL) == 0)
    {
        return FALSE;
    }

    if (_tcsncmp((const TCHAR*)filepath, (const TCHAR*)resolvedBasePath, _tcslen((const TCHAR*)filepath)) != 0)
    {
        return FALSE;
    }

    for (size_t i = 0; i < length; i++)
    {
        if (filepath[i] == '\0')
        {
            return FALSE;
        }
    }

    return TRUE;
}




int SanitizeFilePath3(const TCHAR* filepath, size_t length, const TCHAR* basePath) // with normalization
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

    if (_tcsnicmp((const TCHAR*)resolvedFilePath, basePath, _tcslen(basePath)) != 0)
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

DWORD EncryptPassword(const BYTE* password, DWORD length, char* hash, DWORD* hashlen)
{
    DWORD dwStatus = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";


    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        printf("CryptAcquireContext failed: %d\n", dwStatus);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        printf("CryptCreateHash failed: %d\n", dwStatus);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }


    if (!CryptHashData(hHash, password, length, 0))
    {
        dwStatus = GetLastError();
        printf("CryptHashData failed: %d\n", dwStatus);
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
        printf("CryptGetHashParam failed: %d\n", dwStatus);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return dwStatus;
}


DWORD VerifyPassword(const BYTE* password, DWORD length, char* hash, DWORD hashlen)
{
    if (password == NULL || hash == NULL || hashlen != (HASH_SIZE - 1))
    {
        // Invalid parameters
        return FALSE;
    }

    /// obtain hash of password
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


void InsertUser(const char* Username, const char* hash)
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
        printf("Failed to open users.txt: %d\n", GetLastError());
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



int ValidCredentials(const char* Username, uint16_t UsernameLength, const char* Password, uint16_t PasswordLength)
{
    if (!SanitizedUsername(Username, UsernameLength))
    {
        printf("%s", "Username should contain only English alphabet letters (a - zA - Z) and be between 5 and 10 characters long\n");
        return FALSE;
    }

    if (!SanitizedPassword(Password, PasswordLength))
    {
        printf("%s", "Password must have at least 5 and less than 25 characters and contain at least one digit, one lowercase letter, one uppercase letter, and at least one special symbol(!@#$%^&)\n");
        return FALSE;
    }

    return TRUE;
}


int RetrieveHash(const char* Username, char* retrievedHash, DWORD* retrievedHashLen)
{
    int result = FAIL;

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
            printf("ReadFile failed: %d\n", GetLastError());
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



