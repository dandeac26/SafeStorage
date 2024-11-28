#include "Commands.h"

TCHAR g_AppDir[MAX_PATH];
DWORD g_AppDirBuffSize;
HANDLE g_hFileUsersDB;

static char* LoggedUser = NULL;

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
    if (FileUsersDB == INVALID_HANDLE_VALUE) {
        if (createUsersDatabase() == FAIL) {
            displayExitMSG();
            return result;
        }
    }

    SetFilePointer(FileUsersDB, 0, NULL, FILE_BEGIN);

    char buffer[256];
    DWORD bytesRead;
    char lineBuffer[512];
    memset(lineBuffer, 0, 512);
    lineBuffer[511] = '\0';
    char* lineEnd = NULL;

    while (TRUE) 
    {
        if (!ReadFile(FileUsersDB, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            printf("ReadFile failed: %d\n", GetLastError());
            return result;
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
                result = SUCCESS;
                break;
            }

            memmove(lineBuffer, lineEnd + 1, strlen(lineEnd + 1) + 1);
        }
    }

    if (strlen(lineBuffer) > 0 && result != SUCCESS) {

        char* fileUser = strtok(lineBuffer, ":");
        char* encryptedPassword = strtok(NULL, ":");

        if (fileUser && encryptedPassword && strcmp(fileUser, username) == 0) {
            result = SUCCESS;
        }
    }

    if (FileUsersDB != INVALID_HANDLE_VALUE) {
        CloseHandle(FileUsersDB);  // Close the handle to the file
        FileUsersDB = INVALID_HANDLE_VALUE; // Set handle to an invalid value after closing
    }

    return result;
}



NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{

    if (!ValidCredentials(Username, UsernameLength, Password, PasswordLength))
    {
        return STATUS_UNSUCCESSFUL;
    }

    // check if user exists:
    if (usernameExists(Username))
    {
        printf("Username already exists!\n");
        return STATUS_UNSUCCESSFUL;
    }

    /// INPUT is good and Username doesn't already exist:

    char hash[HASH_SIZE];
    DWORD hashlen = sizeof(hash);

    /// Hash password 
    if (EncryptPassword((const BYTE*)Password, (DWORD)PasswordLength, hash, &hashlen) != 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    InsertUser(Username, hash);

    return STATUS_SUCCESS;
}

NTSTATUS WINAPI LoginUser(const char* Username, uint16_t UsernameLength)
{


    LoggedUser = calloc(sizeof(char), (UsernameLength + 1));
    strncpy_s(LoggedUser, UsernameLength + 1, Username, UsernameLength);


    /*UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
*/
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{

    if (!(ValidCredentials(Username, UsernameLength, Password, PasswordLength) && usernameExists(Username)))
    {
        printf("Invalid Credentials!\n");
        return STATUS_UNSUCCESSFUL;
    }

    char retrievedHash[HASH_SIZE];
    DWORD retrievedHashLen = sizeof(retrievedHash);

    if (RetrieveHash(Username, retrievedHash, &retrievedHashLen) == FAIL)
    {
        printf("Corresponding Hash could not be retrieved!\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (VerifyPassword((const BYTE*)Password, (DWORD)PasswordLength, retrievedHash, retrievedHashLen))
    {
        printf("SUCCESS!!\n");
        if (LoginUser(Username, UsernameLength) == FAIL)
        {
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        printf("FAILED!!\n");
    }
   
    printf("%s\n",  LoggedUser);

    return STATUS_SUCCESS;
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
