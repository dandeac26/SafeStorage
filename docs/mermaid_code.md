# SafeStorage — Mermaid Diagram Source Code

> **Usage:** Copy each code block into [Mermaid Live](https://mermaid.live), render, and save the PNG into `docs/` using the filename indicated under each title.
>
> All diagrams reflect actual function calls and data flows from the source code.

---

## 1. System Architecture

**Save as:** `docs/architecture.png`

```mermaid
graph TB
    subgraph CLI ["SafeStorage — CLI Application"]
        main["main.c\nCommand Parser\nPrintHelp · scanf loop"]
    end

    subgraph Lib ["SafeStorageLib — Security Library (primary author contribution)"]
        Commands["Commands.c\nSafeStorageHandleRegister\nSafeStorageHandleLogin · Logout\nSafeStorageHandleStore · Retrieve\nLoginRateTracker · TransferFile\nProcessFileChunk"]
        Utils["Utils.c\nValidCredentials · SanitizeFilePath3\nEncryptPassword · VerifyPassword\nInsertUser · RetrieveHash\ncreateNewUserDirectory"]
    end

    subgraph WinAPI ["Windows APIs"]
        Crypto["CryptoAPI\nCryptAcquireContext\nCryptCreateHash MD5\nCryptHashData · CryptGetHashParam"]
        FileIO["Win32 File I/O\nCreateFileA · ReadFile\nWriteFile · GetFileSizeEx"]
        TP["Windows Thread Pool\nCreateThreadpoolWork\n4 worker threads min/max"]
        PathAPI["Path APIs\nGetFullPathName\nPathAppend · GetCurrentDirectory"]
    end

    subgraph Storage ["Persistent Storage"]
        DB[("users.txt\nusername:md5hash\none entry per line")]
        UserDirs["users/\n├── UserA/\n└── UserB/\n    └── Homework"]
    end

    subgraph Tests ["SafeStorageUnitTests"]
        UTest["SafeStorageUnitTests.cpp\nMicrosoft CppUnitTest Framework\nUserRegisterLoginLogout\nFileTransfer"]
    end

    main --> Commands
    Commands --> Utils
    Utils --> Crypto
    Utils --> FileIO
    Utils --> PathAPI
    Commands --> FileIO
    Commands --> TP
    Commands --> DB
    Commands --> UserDirs
    UTest --> Commands
    UTest --> Utils
```

---

## 2. User Authentication Flow

**Save as:** `docs/authentication_flow.png`

```mermaid
sequenceDiagram
    actor User
    participant CLI as main.c
    participant CMD as SafeStorageHandleLogin()
    participant RL as IsRateLimited()
    participant VAL as ValidCredentials()
    participant DB as RetrieveHash() / usernameExists()
    participant CRYPTO as VerifyPassword()
    participant STATE as AppState

    User->>CLI: login username password
    CLI->>CMD: SafeStorageHandleLogin(username, password)

    CMD->>CMD: Check AppState.LoggedUser == NULL
    alt Already logged in
        CMD-->>CLI: STATUS_FAIL
        CLI-->>User: Error — already logged in
    end

    CMD->>RL: FindOrCreateTracker(username)
    CMD->>RL: IsRateLimited(tracker)
    alt Rate limited — more than 1 attempt per second
        RL-->>CMD: TRUE
        CMD-->>CLI: STATUS_FAIL
        CLI-->>User: Error — too many login attempts
    end
    RL-->>CMD: FALSE — attempt allowed

    CMD->>VAL: ValidCredentials(username, password)
    Note over VAL: Username: 5–10 alpha chars<br/>Password: 5–25 chars, requires digit +<br/>uppercase + lowercase + special (!@#$%^&)
    alt Invalid format
        VAL-->>CMD: FAIL
        CMD-->>CLI: STATUS_FAIL
        CLI-->>User: Error — invalid credentials format
    end
    VAL-->>CMD: SUCCESS

    CMD->>DB: usernameExists(username)
    alt Username not found in users.txt
        DB-->>CMD: FAIL
        CMD-->>CLI: STATUS_FAIL
        CLI-->>User: Error — invalid username or password
    end
    DB-->>CMD: SUCCESS

    CMD->>DB: RetrieveHash(username, storedHash)
    DB-->>CMD: 32-char MD5 hex string

    CMD->>CRYPTO: VerifyPassword(inputPassword, storedHash)
    Note over CRYPTO: EncryptPassword(input) → compare<br/>with stored hash via strncmp
    alt Hash mismatch
        CRYPTO-->>CMD: FALSE
        CMD-->>CLI: STATUS_FAIL
        CLI-->>User: Error — invalid username or password
    end
    CRYPTO-->>CMD: TRUE

    CMD->>STATE: LoginUser(username) — set AppState.LoggedUser<br/>build CurrentUserDirectory path
    STATE-->>CMD: SUCCESS
    CMD-->>CLI: STATUS_SUCCESS
    CLI-->>User: Login successful
```

---

## 3. User Registration Flow

**Save as:** `docs/registration_flow.png`

```mermaid
sequenceDiagram
    actor User
    participant CLI as main.c
    participant CMD as SafeStorageHandleRegister()
    participant VAL as ValidCredentials()
    participant DB as usernameExists() / InsertUser()
    participant CRYPTO as EncryptPassword()
    participant FS as createNewUserDirectory()

    User->>CLI: register username password
    CLI->>CMD: SafeStorageHandleRegister(username, password)

    CMD->>CMD: Check AppState.LoggedUser == NULL
    alt Already logged in
        CMD-->>CLI: STATUS_FAIL
        CLI-->>User: Error — must be logged out to register
    end

    CMD->>VAL: ValidCredentials(username, password)
    Note over VAL: Username: 5–10 alpha chars only<br/>Password complexity enforced:<br/>digit · uppercase · lowercase · special from !@#$%^&
    alt Invalid format
        VAL-->>CMD: FAIL
        CMD-->>CLI: STATUS_FAIL
        CLI-->>User: Error — invalid credentials format
    end
    VAL-->>CMD: SUCCESS

    CMD->>DB: usernameExists(username)
    alt Username already taken
        DB-->>CMD: SUCCESS
        CMD-->>CLI: STATUS_FAIL
        CLI-->>User: Error — username already exists
    end
    DB-->>CMD: FAIL — username is available

    CMD->>CRYPTO: EncryptPassword(password, hashBuffer)
    Note over CRYPTO: CryptAcquireContext → CryptCreateHash(CALG_MD5)<br/>CryptHashData → CryptGetHashParam<br/>Converts 16-byte digest to 32-char hex string
    CRYPTO-->>CMD: MD5 hash (32-char hex)

    CMD->>DB: InsertUser(username, hash)
    Note over DB: Opens users.txt with FILE_APPEND_DATA<br/>Writes "\nusername:hash" line
    DB-->>CMD: SUCCESS

    CMD->>FS: createNewUserDirectory(username)
    Note over FS: Builds path: AppDir\users\username<br/>SanitizeFilePath2() validates path first<br/>CreateDirectory() creates the folder
    FS-->>CMD: SUCCESS

    CMD-->>CLI: STATUS_SUCCESS
    CLI-->>User: Registration successful
```

---

## 4. File Transfer — Store and Retrieve

**Save as:** `docs/file_transfer.png`

```mermaid
flowchart TD
    A(["User: store src_file submission\nor retrieve submission dest"]) --> B

    B["Check: AppState.LoggedUser != NULL"] --> C{Logged in?}
    C -- No --> Z1(["Return STATUS_FAIL"])

    C -- Yes --> D["Build full path:\nCurrentUserDirectory + submission name\nvia PathAppend"]

    D --> E["SanitizeFilePath3:\n① GetFullPathName — normalize to absolute\n② _tcsnicmp — verify base path prefix\n③ Scan for '..' sequences\n④ Block dangerous chars: * | null-byte"]

    E --> F{Path safe?}
    F -- No --> Z2(["Return STATUS_FAIL\nPath traversal blocked"])

    F -- Yes --> G["TransferFile:\nCreateFileA source — GENERIC_READ\nCreateFileA dest — GENERIC_WRITE, CREATE_ALWAYS\nGetFileSizeEx — read file size"]

    G --> H{File size > 8 GB?}
    H -- Yes --> Z3(["Return STATUS_FAIL\nFile too large"])

    H -- No --> I["Calculate chunk count\nChunk size: 64 KB\nCreate Windows Thread Pool\nMin threads: 4 · Max threads: 4"]

    I --> J["Submit TP work item per chunk offset\nCreateThreadpoolWork + SubmitThreadpoolWork"]

    J --> K["ProcessFileChunk callback:\nEnterCriticalSection g_csFileWrite\nHeapAlloc — allocate chunk buffer\nSetFilePointerEx — seek to chunk offset\nReadFile — read chunk from source\nWriteFile — write chunk to destination\nHeapFree — release buffer\nLeaveCriticalSection"]

    K --> L{All chunks\ncomplete?}
    L -- No --> K

    L -- Yes --> M["WaitForThreadpoolWorkCallbacks\nCloseThreadpoolWork\nDeleteCriticalSection\nCloseHandle source and dest"]

    M --> N(["Return STATUS_SUCCESS"])
```

---

## 5. Path Traversal Prevention — SanitizeFilePath3

**Save as:** `docs/path_traversal_prevention.png`

```mermaid
flowchart TD
    A(["Input: filePath + basePath"]) --> B

    B["GetFullPathName filePath\n→ normalizedPath\nResolves ., .., symlinks to absolute form"]

    B --> C["GetFullPathName basePath\n→ normalizedBase\nNormalizes the allowed storage root"]

    C --> D{"_tcsnicmp:\nnormalizedPath starts\nwith normalizedBase?\n(case-insensitive)"}

    D -- No --> F1(["REJECT\nPath escapes storage directory\ne.g. C:\\users\\admin\\secret.txt"])

    D -- Yes --> E{"Original path\ncontains '..'?"}

    E -- Yes --> F2(["REJECT\nDirectory traversal attempt\ne.g. ..\\..\\Windows\\system.ini"])

    E -- No --> G{"Path contains\ndangerous characters?\n* pipe null-byte"}

    G -- Yes --> F3(["REJECT\nDangerous character\ne.g. wildcard or ADS separator"])

    G -- No --> H(["ACCEPT\nPath is within allowed directory\nand contains no traversal sequences"])

    style F1 fill:#c0392b,color:#fff
    style F2 fill:#c0392b,color:#fff
    style F3 fill:#c0392b,color:#fff
    style H fill:#27ae60,color:#fff
```

---

## 6. Rate Limiting — Login Brute Force Protection

**Save as:** `docs/rate_limiting.png`

```mermaid
flowchart TD
    A(["Login attempt for username"]) --> B

    B["FindOrCreateTracker username\nSearch LoginTrackers array\n— capacity: 100 entries"]

    B --> C{Tracker exists\nfor this username?}

    C -- No --> D{TrackerCount < 100?}
    D -- No --> ALLOW1(["ALLOW\nArray full — fail open\nCannot track, do not block"])
    D -- Yes --> E["Create new tracker:\nUsername = input\nAttemptCount = 1\nFirstAttemptTime = time_now"]
    E --> ALLOW2(["ALLOW\nFirst attempt for this user"])

    C -- Yes --> F["IsRateLimited:\nfetch current time via time()"]
    F --> G{"time_now − FirstAttemptTime\n> 1 second?"}

    G -- Yes --> H["Reset tracker:\nAttemptCount = 1\nFirstAttemptTime = time_now"]
    H --> ALLOW3(["ALLOW\nTime window expired — counter reset"])

    G -- No --> I{"AttemptCount >=\nMAX_ATTEMPTS_PER_SECOND\n(1 attempt per second)"}

    I -- No --> J["Increment AttemptCount"]
    J --> ALLOW4(["ALLOW\nWithin rate limit"])

    I -- Yes --> DENY(["DENY\nReturn STATUS_FAIL\nToo many login attempts"])

    style DENY fill:#c0392b,color:#fff
    style ALLOW1 fill:#27ae60,color:#fff
    style ALLOW2 fill:#27ae60,color:#fff
    style ALLOW3 fill:#27ae60,color:#fff
    style ALLOW4 fill:#27ae60,color:#fff
```
