#include "Utils.h"

int IsSpecialCharacter(char ch) 
{
    const char* specialChars = "!@#$%^&";
    return strchr(specialChars, ch) != NULL;
}


int SanitizedUsername(const char* username, uint16_t length) 
{
    
    if (length < 5 || length > 10) 
    {
        return false;
    }

    for (uint16_t i = 0; i < length; i++) 
    {
        if (!isalpha((unsigned char)username[i])) {
            return false;
        }
    }

    return true;
}


int SanitizedPassword(const char* password, uint16_t length) 
{
    if (length < 5 || length > 25) 
    {
        return false;
    }

    int hasDigit = false;
    int hasLower = false;
    int hasUpper = false;
    int hasSpecial = false;

    for (uint16_t i = 0; i < length; i++) 
    {
        char ch = password[i];
        if (isdigit((unsigned char)ch)) 
        {
            hasDigit = true;
        }
        else if (islower((unsigned char)ch)) 
        {
            hasLower = true;
        }
        else if (isupper((unsigned char)ch)) 
        {
            hasUpper = true;
        }
        else if (IsSpecialCharacter(ch)) 
        {
            hasSpecial = true;
        }
        else 
        {
            return false;
        }
    }

    return hasDigit && hasLower && hasUpper && hasSpecial;
}


int SanitizeFilePath(const char* filepath, uint16_t length, LPCSTR appdir)
{
    if (length == 0 || filepath == NULL) 
    {
        return false;
    }


    char normalizedPath[MAX_PATH] = { 0 };
    char resolvedBasePath[MAX_PATH] = { 0 };
    

    // Normalization strategy
    if (GetFullPathNameA(filepath, MAX_PATH, normalizedPath, NULL) == 0) 
    {
        return false;
    }

   
    if (GetFullPathNameA(appdir, MAX_PATH, resolvedBasePath, NULL) == 0)
    {
        return false;
    }

   
    if (strncmp(normalizedPath, resolvedBasePath, strlen(resolvedBasePath)) != 0) 
    { 
        return false;
    }

    
    for (uint16_t i = 0; i < length; i++) 
    {
        if (filepath[i] == '\0')
        {
            return false;
        }
        if (i < length-1 && filepath[i] == '.' && filepath[i + 1] == '.')
        {
            return false;
        }
    }

    
    return true;
}


DWORD EncryptPassword(const BYTE* password, DWORD length, char* hash, DWORD* hashlen)
{
    DWORD dwStatus = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
   

    // Get handle to the crypto provider
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
        hash[j] = '\0';  // Null-terminate the string
        *hashlen = j+1;
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
    //printf("Given hash : %s\n", hash);
    if (password == NULL || hash == NULL || hashlen != (HASH_SIZE-1))
    {
        // Invalid parameters
        return false;
    }

    /// obtain hash of password
    char generatedHash[HASH_SIZE];
    DWORD generatedHashlen = sizeof(hash);
    if (EncryptPassword(password, length, generatedHash, &generatedHashlen) != 0) {
        return false;
    }
    //printf("Generated hash : %s\nGiven hash : %s\n", generatedHash, hash); 
    if (strncmp(generatedHash, hash, hashlen) == 0)
    {
       return true;  // Passwords match
    }
    
    return false;
}


void InsertUser(const char* Username, const char* hash)
{
    // Open the users.txt file in append mode
    HANDLE FileUsersDB = CreateFile(
        _T("users.txt"),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    // Check if the file was opened successfully
    if (FileUsersDB == INVALID_HANDLE_VALUE) {
        printf("Failed to open users.txt: %d\n", GetLastError());
        return;
    }

    // Create the line to append: "username:hash\n"
    char lineBuffer[512];
    memset(lineBuffer, 0, sizeof(lineBuffer));
    snprintf(lineBuffer, sizeof(lineBuffer) - 1, "\n%s:%s", Username, hash);

    // Write the line to the file
    DWORD bytesWritten;
    BOOL writeSuccess = WriteFile(
        FileUsersDB,
        lineBuffer,
        strlen(lineBuffer),
        &bytesWritten,
        NULL
    );

    // Check if writing succeeded
    if (!writeSuccess || bytesWritten != strlen(lineBuffer)) {
        printf("Failed to write to users.txt: %d\n", GetLastError());
    }
    else {
        printf("User '%s' added successfully.\n", Username);
    }

    // Close the file handle
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


//int RetrieveHash(const char* Username, char* retrievedHash, DWORD* retrievedHashLen)
//{
//    HANDLE FileUsersDB = CreateFile(
//        _T("users.txt"),
//        GENERIC_READ,
//        0,
//        NULL,
//        OPEN_EXISTING,
//        FILE_ATTRIBUTE_NORMAL,
//        NULL
//    );
//
//    // Check if the file was opened successfully
//    if (FileUsersDB == INVALID_HANDLE_VALUE) {
//        printf("Failed to open users.txt: %d\n", GetLastError());
//        return;
//    }
//
//    // return the hash coinciding to username
//    
//
//    // Close the file handle
//    CloseHandle(FileUsersDB);
//}

//int RetrieveHash(const char* Username, char* retrievedHash, DWORD* retrievedHashLen)
//{
//    int result = FAIL;
//
//    HANDLE FileUsersDB = CreateFile(
//        _T("users.txt"),
//        GENERIC_READ,
//        0,
//        NULL,
//        OPEN_EXISTING,
//        FILE_ATTRIBUTE_NORMAL,
//        NULL
//    );
//
//    // Check if users.txt file is open 
//    if (FileUsersDB == INVALID_HANDLE_VALUE) 
//    {
//        return result;
//    }
//
//    SetFilePointer(FileUsersDB, 0, NULL, FILE_BEGIN);
//
//    char buffer[256];
//    DWORD bytesRead;
//    char lineBuffer[512];
//    memset(lineBuffer, 0, 512);
//    lineBuffer[511] = '\0';
//    char* lineEnd = NULL;
//    char* Context;
//
//    while (TRUE)
//    {
//        if (!ReadFile(FileUsersDB, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
//            printf("ReadFile failed: %d\n", GetLastError());
//            return result;
//        }
//
//        if (bytesRead == 0) {
//            break;
//        }
//
//        buffer[bytesRead] = '\0';
//
//        strncat_s(lineBuffer, sizeof(lineBuffer), buffer, sizeof(lineBuffer) - strlen(lineBuffer) - 1);
//
//        while ((lineEnd = strchr(lineBuffer, '\n')) != NULL) {
//            *lineEnd = '\0';
//
//            char* fileUser = strtok_s(lineBuffer, ":", &Context);
//            char* encryptedPassword = strtok_s(NULL, ":", &Context);
//
//            if (fileUser && encryptedPassword && strcmp(fileUser, Username) == 0) {
//                result = SUCCESS;
//                strncpy_s(retrievedHash, strlen(encryptedPassword), encryptedPassword, HASH_SIZE);
//                *retrievedHashLen = strlen(encryptedPassword);
//                break;
//            }
//
//            memmove(lineBuffer, lineEnd + 1, strlen(lineEnd + 1) + 1);
//        }
//    }
//
//    if (strlen(lineBuffer) > 0 && result != SUCCESS) {
//
//        char* fileUser = strtok_s(lineBuffer, ":", &Context);
//        char* encryptedPassword = strtok_s(NULL, ":", &Context);
//
//        if (fileUser && encryptedPassword && strcmp(fileUser, Username) == 0) {
//            result = SUCCESS;
//            strncpy_s(retrievedHash, strlen(encryptedPassword), encryptedPassword, HASH_SIZE);
//            *retrievedHashLen = strlen(encryptedPassword);
//        }
//    }
//
//    if (FileUsersDB != INVALID_HANDLE_VALUE) {
//        CloseHandle(FileUsersDB);  // Close the handle to the file
//        FileUsersDB = INVALID_HANDLE_VALUE; // Set handle to an invalid value after closing
//    }
//
//    return result;
//}


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

    // Check if users.txt file is open 
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

        // Safely concatenate the contents of the buffer to lineBuffer
        strncat_s(lineBuffer, sizeof(lineBuffer), buffer, sizeof(lineBuffer) - strlen(lineBuffer) - 1);

        while ((lineEnd = strchr(lineBuffer, '\n')) != NULL) {
            *lineEnd = '\0';  // Null-terminate at the newline

            // Tokenize the line
            char* fileUser = strtok_s(lineBuffer, ":", &Context);
            char* encryptedPassword = strtok_s(NULL, ":", &Context);

            // Check if the user matches
            if (fileUser && encryptedPassword && strcmp(fileUser, Username) == 0) {
                result = SUCCESS;
                // Copy the encrypted password to retrievedHash safely
                strncpy_s(retrievedHash, HASH_SIZE, encryptedPassword, HASH_SIZE - 1); // Always leave space for null-termination
                *retrievedHashLen = strlen(encryptedPassword);
                break;
            }

            // Move the remaining part of the buffer
            memmove(lineBuffer, lineEnd + 1, strlen(lineEnd + 1) + 1);
        }

        // If a user was found during the loop, break out
        if (result == SUCCESS) {
            break;
        }
    }

    // Handle the case where the last line does not end with a newline
    if (strlen(lineBuffer) > 0 && result != SUCCESS) {
        char* fileUser = strtok_s(lineBuffer, ":", &Context);
        char* encryptedPassword = strtok_s(NULL, ":", &Context);

        if (fileUser && encryptedPassword && strcmp(fileUser, Username) == 0) {
            result = SUCCESS;
            strncpy_s(retrievedHash, HASH_SIZE, encryptedPassword, HASH_SIZE - 1);  // Safely copy the hash
            *retrievedHashLen = strlen(encryptedPassword);
        }
    }

    // Clean up and close the file handle
    CloseHandle(FileUsersDB);
    return result;
}
