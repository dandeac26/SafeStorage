#include "Commands.h"

TCHAR g_AppDir[MAX_PATH];
DWORD g_AppDirBuffSize;
HANDLE g_hFileUsersDB;

typedef struct APP_STATE_STRUCT
{
    char* LoggedUser;
    TCHAR* CurrentUserDirectory;
}APP_STATE;

static APP_STATE AppState;


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

    AppState.LoggedUser = NULL;
    AppState.CurrentUserDirectory = NULL;

    return STATUS_SUCCESS;
}


VOID WINAPI SafeStorageDeinit(VOID)
{

    if (g_hFileUsersDB != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hFileUsersDB);  // Close the handle to the file
        g_hFileUsersDB = INVALID_HANDLE_VALUE; // Set handle to an invalid value after closing
    }

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

int LoginUser(const char* Username, uint16_t UsernameLength)
{
    AppState.CurrentUserDirectory = (TCHAR*)calloc(sizeof(TCHAR), MAX_PATH);
    
    if (buildUserPathAndCheckIfExists(Username, UsernameLength, AppState.CurrentUserDirectory) == FAIL) 
    {
        printf("User directory no longer exists.\n");
        return FAIL;
    }

    printf("current user dir : ");
    _tprintf(AppState.CurrentUserDirectory);
    printf("\n");

    AppState.LoggedUser = calloc(sizeof(char), (UsernameLength + 1));
    strncpy_s(AppState.LoggedUser, UsernameLength + 1, Username, UsernameLength);


    return SUCCESS;
}


LoginRateTracker LoginTrackers[TRACKER_CAPACITY];
size_t TrackerCount = 0;


LoginRateTracker* FindOrCreateTracker(const char* Username) 
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


int IsRateLimited(LoginRateTracker* tracker) 
{
    time_t currentTime = time(NULL);

    if (currentTime - tracker->FirstAttemptTime >= 1) 
    {
        tracker->AttemptCount = 0;
        tracker->FirstAttemptTime = currentTime;
    }

    if (tracker->AttemptCount >= MAX_ATTEMPTS_PER_SECOND) {
        return true;
    }

    tracker->AttemptCount++;
    return false;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
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
        printf("Passwords matched!\n");
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
    if(AppState.LoggedUser == NULL)
    {
        printf("Not logged in!\n");
        return STATUS_UNSUCCESSFUL;
    }

    AppState.LoggedUser = NULL;

    free(AppState.LoggedUser);

    return STATUS_SUCCESS;
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
