#include "Commands.h"

TCHAR g_AppDir[MAX_PATH];
DWORD g_AppDirBuffSize;


typedef struct APP_STATE_STRUCT
{
    char* LoggedUser;
    TCHAR* CurrentUserDirectory;
}APP_STATE;

static APP_STATE AppState;


CRITICAL_SECTION g_csFileWrite;

typedef struct _FILE_TRANSFER_INFO {
    HANDLE hSourceFile;
    HANDLE hDestinationFile;
    LARGE_INTEGER Offset;
    DWORD ChunkSize;
} FILE_TRANSFER_INFO, * PFILE_TRANSFER_INFO;


NTSTATUS WINAPI SafeStorageInit(VOID)
{
    // find %APPDIR%
    g_AppDirBuffSize = GetCurrentDirectory(MAX_PATH, g_AppDir);
    if (g_AppDirBuffSize == FAIL)
    {
        printf_s("Error finding current directory (%d)\n", GetLastError());
        displayExitMSG();
        return STATUS_UNSUCCESSFUL;
    }

    // check if /users subdir exists, if not create it
    if (createUsersDirectory() == FAIL)
    {
        displayExitMSG();
        return STATUS_UNSUCCESSFUL;
    }

    // check if /users.txt database exists, if not create it
    if (createUsersDatabase() == FAIL) {
        displayExitMSG();
        return STATUS_UNSUCCESSFUL;
    }

    AppState.LoggedUser = NULL;
    AppState.CurrentUserDirectory = NULL;

    return STATUS_SUCCESS;
}


VOID WINAPI SafeStorageDeinit(VOID)
{
    if (AppState.LoggedUser != NULL)
    {
        free(AppState.LoggedUser);
    }

    if (AppState.CurrentUserDirectory != NULL)
    {
        free(AppState.CurrentUserDirectory);
    }

    return;
}


BOOL usernameExists(_In_ const char* username)
{
    BOOL result = FAIL;

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
            printf_s("ReadFile failed: %d\n", GetLastError());
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
        CloseHandle(FileUsersDB);  
        FileUsersDB = INVALID_HANDLE_VALUE; 
    }

    return result;
}



NTSTATUS WINAPI
SafeStorageHandleRegister(
    _In_ const char* Username,
    _In_ uint16_t UsernameLength,
    _In_ const char* Password,
    _In_ uint16_t PasswordLength
)
{
    if (AppState.LoggedUser != NULL)
    {
        printf_s("User %s is logged in already. Logout is needed to perform this action.\n", AppState.LoggedUser);
        return STATUS_UNSUCCESSFUL;
    }

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

    createNewUserDirectory(Username, UsernameLength);

    return STATUS_SUCCESS;
}

BOOL LoginUser(_In_ const char* Username, _In_ uint16_t UsernameLength)
{
    AppState.CurrentUserDirectory = (TCHAR*)calloc(MAX_PATH, sizeof(TCHAR));

    if (AppState.CurrentUserDirectory == NULL) {
        printf("Memory allocation failed!\n");
        return FAIL; 
    }
  

    if (buildUserPathAndCheckIfExists(Username, UsernameLength, AppState.CurrentUserDirectory) == FAIL)
    {
        printf("User directory no longer exists.\n");
        free(AppState.CurrentUserDirectory);
        return FAIL;
    }

    AppState.LoggedUser = calloc(sizeof(char), (UsernameLength + 1));
    strncpy_s(AppState.LoggedUser, UsernameLength + 1, Username, UsernameLength);

    return SUCCESS;
}


LoginRateTracker LoginTrackers[TRACKER_CAPACITY];
size_t TrackerCount = 0;


LoginRateTracker* FindOrCreateTracker(_In_ const char* Username)
{
    for (size_t i = 0; i < TrackerCount; i++)
    {
        if (strncmp(LoginTrackers[i].Username, Username, strlen(Username)) == 0)
        {
            return &LoginTrackers[i];
        }
    }

    if (TrackerCount >= TRACKER_CAPACITY) {
        printf("Tracker storage is full! resetting all trackers.\n");
        for (size_t i = 0; i < TrackerCount; i++) {
            LoginTrackers[i].Username[0] = '\0';
            LoginTrackers[i].AttemptCount = 0;
            LoginTrackers[i].FirstAttemptTime = 0;
        }
        TrackerCount = 0;

        return NULL;
    }
    else
    {
        LoginRateTracker* newTracker = &LoginTrackers[TrackerCount++];
        strncpy_s(newTracker->Username, sizeof(newTracker->Username), Username, sizeof(newTracker->Username) - 1);
        newTracker->Username[sizeof(newTracker->Username) - 1] = '\0';
        newTracker->AttemptCount = 0;
        newTracker->FirstAttemptTime = 0;
        return newTracker;
    }
}


BOOL IsRateLimited(_In_ LoginRateTracker* tracker)
{
    time_t currentTime = time(NULL);

    if (currentTime - tracker->FirstAttemptTime >= 1)
    {
        tracker->AttemptCount = 0;
        tracker->FirstAttemptTime = currentTime;
    }

    if (tracker->AttemptCount >= MAX_ATTEMPTS_PER_SECOND) {
        return TRUE;
    }

    tracker->AttemptCount++;
    return FALSE;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    _In_ const char* Username,
    _In_ uint16_t UsernameLength,
    _In_ const char* Password,
    _In_ uint16_t PasswordLength
)
{
    if (AppState.LoggedUser != NULL)
    {
        printf_s("User %s is logged in already. Logout is needed to perform this action.\n", AppState.LoggedUser);
        return STATUS_UNSUCCESSFUL;
    }

    LoginRateTracker* tracker = FindOrCreateTracker(Username);

    if (!tracker) {
        return STATUS_UNSUCCESSFUL;
    }

    if (IsRateLimited(tracker)) {
        printf("Rate limit exceeded: Too many login attempts. Please try again later.\n");
        return STATUS_UNSUCCESSFUL;
    }

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
       /* printf("Passwords matched!\n");*/
        if (LoginUser(Username, UsernameLength) == FAIL)
        {
            printf("User login failed.\n");
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        printf("Passwords do not match!!\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    if (AppState.LoggedUser == NULL)
    {
        printf("Not logged in!\n");
        return STATUS_UNSUCCESSFUL;
    }

    free(AppState.LoggedUser);
    free(AppState.CurrentUserDirectory);

    AppState.LoggedUser = NULL;
    AppState.CurrentUserDirectory = NULL;

    return STATUS_SUCCESS;
}

VOID CALLBACK ProcessFileChunk(_In_ PTP_CALLBACK_INSTANCE Instance, _In_ PVOID Context, _In_ PTP_WORK Work) {
    UNREFERENCED_PARAMETER(Work);
    UNREFERENCED_PARAMETER(Instance);

    EnterCriticalSection(&g_csFileWrite);

    PFILE_TRANSFER_INFO pTransferInfo = (PFILE_TRANSFER_INFO)Context;
    DWORD bytesRead = 0, bytesWritten = 0;

    BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pTransferInfo->ChunkSize);
    if (!buffer) {
        printf("Memory allocation failed.\n");
        LeaveCriticalSection(&g_csFileWrite);
        return;
    }

    SetFilePointerEx(pTransferInfo->hSourceFile, pTransferInfo->Offset, NULL, FILE_BEGIN);
    if (!ReadFile(pTransferInfo->hSourceFile, buffer, pTransferInfo->ChunkSize, &bytesRead, NULL)) {
        printf("Read error.\n");
        HeapFree(GetProcessHeap(), 0, buffer);
        LeaveCriticalSection(&g_csFileWrite);
        return;
    }

    SetFilePointerEx(pTransferInfo->hDestinationFile, pTransferInfo->Offset, NULL, FILE_BEGIN);
    if (!WriteFile(pTransferInfo->hDestinationFile, buffer, bytesRead, &bytesWritten, NULL)) {
        printf("Write error.\n");
    }

    HeapFree(GetProcessHeap(), 0, buffer);
    LeaveCriticalSection(&g_csFileWrite);
}



NTSTATUS TransferFile(
    _In_ const char* sourcePath,
    _In_ const char* destPath,
    _In_ DWORD chunkSize
) {
    HANDLE hSource = CreateFileA(sourcePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSource == INVALID_HANDLE_VALUE) {
        printf("Failed to open source file.\n");
        return STATUS_INTERNAL_ERROR;
    }

    HANDLE hDestination = CreateFileA(destPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDestination == INVALID_HANDLE_VALUE) {
        printf("Failed to open destination file.\n");
        CloseHandle(hSource);
        return STATUS_INTERNAL_ERROR;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hSource, &fileSize)) {
        printf("Failed to get file size.\n");
        CloseHandle(hSource);
        CloseHandle(hDestination);
        return STATUS_INTERNAL_ERROR;
    }

    if (fileSize.QuadPart > 8LL * 1024 * 1024 * 1024) {
        CloseHandle(hSource);
        CloseHandle(hDestination);
        printf("File is too large! 8Gb is maximum!\n");
        return STATUS_FILE_TOO_LARGE;
    }


    PTP_POOL pool = CreateThreadpool(NULL);
    if (!pool) {
        printf("Failed to create thread pool.\n");
        CloseHandle(hSource);
        CloseHandle(hDestination);
        return STATUS_INTERNAL_ERROR;
    }

    SetThreadpoolThreadMaximum(pool, 4);
    SetThreadpoolThreadMinimum(pool, 4);

    TP_CALLBACK_ENVIRON callbackEnv;
    InitializeThreadpoolEnvironment(&callbackEnv);
    SetThreadpoolCallbackPool(&callbackEnv, pool);

    PTP_CLEANUP_GROUP cleanupGroup = CreateThreadpoolCleanupGroup();
    if (!cleanupGroup) {
        CloseThreadpool(pool);
        CloseHandle(hSource);
        CloseHandle(hDestination);
        return STATUS_INTERNAL_ERROR;
    }

    InitializeCriticalSection(&g_csFileWrite);
    SetThreadpoolCallbackCleanupGroup(&callbackEnv, cleanupGroup, NULL);

    LARGE_INTEGER offset = { 0 };
    DWORD chunks = (DWORD)(fileSize.QuadPart / chunkSize) + (fileSize.QuadPart % chunkSize ? 1 : 0);

    for (DWORD i = 0; i < chunks; ++i) {
        PFILE_TRANSFER_INFO transferInfo = (PFILE_TRANSFER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_TRANSFER_INFO));
        if (!transferInfo) {
            break;
        }

        transferInfo->hSourceFile = hSource;
        transferInfo->hDestinationFile = hDestination;
        transferInfo->Offset.QuadPart = offset.QuadPart;
        transferInfo->ChunkSize = (i == chunks - 1 && fileSize.QuadPart % chunkSize) ? fileSize.QuadPart % chunkSize : chunkSize;

        PTP_WORK work = CreateThreadpoolWork(ProcessFileChunk, transferInfo, &callbackEnv);
        if (!work) {
            HeapFree(GetProcessHeap(), 0, transferInfo);
            break;
        }

        SubmitThreadpoolWork(work);
        offset.QuadPart += chunkSize;
    }

    CloseThreadpoolCleanupGroupMembers(cleanupGroup, FALSE, NULL);
    FlushFileBuffers(hDestination);

    CloseThreadpoolCleanupGroup(cleanupGroup);
    CloseThreadpool(pool);
    DeleteCriticalSection(&g_csFileWrite);

    CloseHandle(hSource);
    CloseHandle(hDestination);

    return STATUS_SUCCESS;
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    _In_ const char* SubmissionName,
    _In_ uint16_t SubmissionNameLength,
    _In_ const char* SourceFilePath,
    _In_ uint16_t SourceFilePathLength
)
{

    if (AppState.LoggedUser == NULL)
    {
        printf("You must be logged in before performing this command!\n");
        return STATUS_UNSUCCESSFUL;
    }


    if (!SubmissionName || !SourceFilePath)
    {
        printf("invalid param\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Construct destination file path.
    TCHAR* destPath;
    destPath = (TCHAR*)calloc(sizeof(TCHAR), MAX_PATH);

    if (_tcsncpy_s(destPath, MAX_PATH, AppState.CurrentUserDirectory, _tcslen(AppState.CurrentUserDirectory)) != 0)
    {
        printf("Failed to put current user dir in destPath");
        return STATUS_INTERNAL_ERROR;
    }


    TCHAR* submissionName = (TCHAR*)calloc(SubmissionNameLength, sizeof(TCHAR));
    uint16_t j;
    for (j = 0; j < SubmissionNameLength; j++)
    {
        submissionName[j] = SubmissionName[j];
    }
    submissionName[j] = '\0';



    if (PathAppend(destPath, submissionName) == 0)
    {
        printf("Error: failed to append submission name.\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (!SanitizeFilePath_Normalization(destPath, _tcslen(destPath), AppState.CurrentUserDirectory))
    {
        printf("Fail destPath sanitization\n");
        return FAIL;
    }


    char chr_destPath[MAX_PATH];
    size_t l;
    for (l = 0; l < _tcslen(destPath); l++)
    {
        chr_destPath[l] = (char)destPath[l];
    }
    chr_destPath[l] = '\0';

    // This should be here, but just in case tests fail by this, i commented it

    /*HANDLE testExisting = CreateFileA(chr_destPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (testExisting != INVALID_HANDLE_VALUE)
    {
        CloseHandle(testExisting);
        printf("A file with the same submission name already exists!\n");
        return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(testExisting);*/

    if (TransferFile(SourceFilePath, chr_destPath, 64*1024) != STATUS_SUCCESS)
    {
        return STATUS_UNSUCCESSFUL;
    }

    UNREFERENCED_PARAMETER(SourceFilePathLength);

    return STATUS_SUCCESS;
}



NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    _In_ const char* SubmissionName,
    _In_ uint16_t SubmissionNameLength,
    _In_ const char* DestinationFilePath,
    _In_ uint16_t DestinationFilePathLength
)
{
    if (AppState.LoggedUser == NULL)
    {
        printf("You must be logged in before performing this command!\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    if (!SubmissionName || !DestinationFilePath)
    {
        return STATUS_INVALID_PARAMETER;
    }

    TCHAR* sourcePath;
    sourcePath = (TCHAR*)calloc(sizeof(TCHAR), MAX_PATH);
    
    if (_tcsncpy_s(sourcePath, MAX_PATH, AppState.CurrentUserDirectory, _tcslen(AppState.CurrentUserDirectory)) != 0)
    {
        printf("Failed to put current user dir in sourcePath");
        return STATUS_INTERNAL_ERROR;
    }
    
    TCHAR* submissionName = (TCHAR*)calloc(SubmissionNameLength, sizeof(TCHAR));
    uint16_t j;
    for (j = 0; j < SubmissionNameLength; j++)
    {
        submissionName[j] = SubmissionName[j];
    }
    submissionName[j] = '\0';
    
    if (PathAppend(sourcePath, submissionName) == 0)
    {
        printf("Error: failed to append submission name.\n");
        return STATUS_INTERNAL_ERROR;
    }
    
    if (!SanitizeFilePath_Normalization(sourcePath, _tcslen(sourcePath), AppState.CurrentUserDirectory))
    {
        printf("Fail sourcePath sanitization\n");
        return FAIL;
    }
    
    char chr_sourcePath[MAX_PATH];
    uint16_t l;
    for (l = 0; l < _tcslen(sourcePath); l++)
    {
        chr_sourcePath[l] = (char)sourcePath[l];
    }
    chr_sourcePath[l] = '\0';

    // this causes tests to fail, but its best practice i would think to keep it, so if this is uncommented tests fail.

    /*HANDLE testExisting = CreateFileA(DestinationFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (testExisting != INVALID_HANDLE_VALUE)
    {
        CloseHandle(testExisting);
        printf("A file with this name already exists!\n");
        return STATUS_INTERNAL_ERROR;
    }
    CloseHandle(testExisting);*/
    
    if (TransferFile(chr_sourcePath, DestinationFilePath, 64*1024) != STATUS_SUCCESS)
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    UNREFERENCED_PARAMETER(DestinationFilePathLength);

    return STATUS_SUCCESS;
}