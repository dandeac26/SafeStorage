#include "Commands.h"

TCHAR g_AppDir[MAX_PATH];
DWORD g_AppDirBuffSize;
HANDLE g_hFileUsersDB;

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
        //printf("Directory exists.\n");
        return SUCCESS;
    }

    printf("Path exists, but it's not a directory.\n");
    return FAIL;
}


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
        printf("Error creating file: (%d)",GetLastError());
        return FAIL;
    }
    return SUCCESS;
}


void displayExitMSG(VOID) 
{
    printf("\nPress Enter to exit...");
    getchar();
}

NTSTATUS WINAPI SafeStorageInit(VOID)
{
    // find %APPDIR%
    g_AppDirBuffSize = GetCurrentDirectory(MAX_PATH, g_AppDir);
    if (g_AppDirBuffSize == FAIL)
    {
        printf("Error finding current directory (%d)\n", GetLastError());
        displayExitMSG();
        return STATUS_UNSUCCESSFUL;
    }

    // check if /users subdir exists, if not create it
    if (createUsersDirectory()== FAIL)
    {
        displayExitMSG();
        return STATUS_UNSUCCESSFUL;
    }

    // check if /users.txt database exists, if not create it
    if (createUsersDatabase() == FAIL) {
        displayExitMSG();
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


VOID WINAPI SafeStorageDeinit(VOID)
{

    if (g_hFileUsersDB != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hFileUsersDB);  // Close the handle to the file
        g_hFileUsersDB = INVALID_HANDLE_VALUE; // Set handle to an invalid value after closing
    }
    /* The function is not implemented. It is your responsibility. */
    /* Here you can clean up any global objects you have created earlier. */

    return;
}


int usernameExists(const char* username)
{
    g_hFileUsersDB = CreateFile(
        _T("users.txt"),
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    // Check if users.txt file is open 
    if (g_hFileUsersDB == INVALID_HANDLE_VALUE) {
        if (createUsersDatabase() == FAIL) {
            displayExitMSG();
            return STATUS_UNSUCCESSFUL;
        }
    }

    SetFilePointer(g_hFileUsersDB, 0, NULL, FILE_BEGIN);

    char buffer[256];
    DWORD bytesRead;
    char lineBuffer[512];
    memset(lineBuffer, 0, 512);
    lineBuffer[511] = '\0';
    char* lineEnd = NULL;

    while (TRUE) 
    {
        if (!ReadFile(g_hFileUsersDB, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            printf("ReadFile failed: %d\n", GetLastError());
            return FAIL;
        }

        if (bytesRead == 0) {
            break;
        }

        buffer[bytesRead] = '\0';

        strncat(lineBuffer, buffer, sizeof(lineBuffer) - strlen(lineBuffer) - 1);

        while ((lineEnd = strchr(lineBuffer, '\n')) != NULL) {
            *lineEnd = '\0'; 

            char* fileUser = strtok(lineBuffer, ":");
            char* encryptedPassword = strtok(NULL, ":");

            if (fileUser && encryptedPassword && strcmp(fileUser, username) == 0) {
                return SUCCESS; 
            }

            memmove(lineBuffer, lineEnd + 1, strlen(lineEnd + 1) + 1);
        }
    }

    if (strlen(lineBuffer) > 0) {
        
        char* fileUser = strtok(lineBuffer, ":");
        char* encryptedPassword = strtok(NULL, ":");

        if (fileUser && encryptedPassword && strcmp(fileUser, username) == 0) {
            return SUCCESS; 
        }
    }

    return FAIL;
}

NTSTATUS WINAPI 
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    if (!SanitizedUsername(Username, UsernameLength)) 
    {
        printf("%s", "Username should contain only English alphabet letters (a - zA - Z) and be between 5 and 10 characters long\n");
        return STATUS_UNSUCCESSFUL;
    }
        
    if(!SanitizedPassword(Password, PasswordLength))
    {
        printf("%s", "Password must have at least 5 characters and contain at least one digit, one lowercase letter, one uppercase letter, and at least one special symbol(!@#$%^&)\n");
        return STATUS_UNSUCCESSFUL;
    }

    // check if user exists:
    if (usernameExists(Username)) 
    {
        printf("Username already exists!\n");
        return STATUS_UNSUCCESSFUL;
    }
   

    /// INPUT is good and Username doesn't exist

    /// Hash password 
    char hash[MD5LEN * 2 + 1];  // Buffer for hex hash + null terminator
    DWORD hashlen = sizeof(hash);
    if (EncryptPassword((const BYTE*)Password, (DWORD)PasswordLength, hash, &hashlen) != 0) 
    {
        return STATUS_UNSUCCESSFUL;
    }
    printf("Pass hash: %s\n", hash);
    
    char testhash[] = "7d151bc844f266a1e6c70fee1a52e360";
    //                 7d151bc844f266a1e6c70fee1a52e360
   /* if (VerifyPassword((const BYTE*)Password, (DWORD)PasswordLength, hash, hashlen))
    {*/
        printf("%d\n", VerifyPassword((const BYTE*)Password, (DWORD)PasswordLength, testhash, strlen(testhash)));
    //}


    // close file
    if (g_hFileUsersDB != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hFileUsersDB);  // Close the handle to the file
        g_hFileUsersDB = INVALID_HANDLE_VALUE; // Set handle to an invalid value after closing
    }


    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLength);

    return STATUS_SUCCESS;
}


NTSTATUS WINAPI 
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */
    
    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    /* The function is not implemented. It is your responsibility. */

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(SourceFilePath);
    UNREFERENCED_PARAMETER(SourceFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    /* The function is not implemented. It is your responsibility. */
    /* After you implement the function, you can remove UNREFERENCED_PARAMETER(x). */
    /* This is just to prevent a compilation warning that the parameter is unused. */

    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(DestinationFilePath);
    UNREFERENCED_PARAMETER(DestinationFilePathLength);

    return STATUS_NOT_IMPLEMENTED;
}
