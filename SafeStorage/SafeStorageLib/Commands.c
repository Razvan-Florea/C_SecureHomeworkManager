#include "Commands.h"

#include "winnt.h"
#include "sddl.h"

static char* g_AppDir = NULL;
static char* g_UsersDir = NULL;
static char* g_UsersDbPath = NULL;

static char g_CurrentUsername[11] = { 0 };
static DWORD g_LastFailedLoginTime = 0;
static int g_FailedLoginCount = 0;
#define MAX_LOGIN_ATTEMPTS 5
#define LOCKOUT_DURATION_MS 1000

#define CHUNK_SIZE (64 * 1024) // 64KB chunks (Allowed: 512B - 64KB)
#define THREAD_COUNT 4

// Context struct for thread pool
typedef struct _COPY_CONTEXT {
    HANDLE hSource;
    HANDLE hDest;
    LARGE_INTEGER FileSize;
    volatile LONG64 CurrentOffset; // Shared atomic counter
    volatile LONG Status;          // Shared error state (0 = Success, <0 = Error)
} COPY_CONTEXT, * PCOPY_CONTEXT;

static BOOL GenerateSalt(PBYTE pbSalt, DWORD cbSalt)
{
    // Use CryptGenRandom for a cryptographically secure random number generator
    HCRYPTPROV hCryptProv = 0;
    if (!CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }

    if (!CryptGenRandom(hCryptProv, cbSalt, pbSalt)) {
        CryptReleaseContext(hCryptProv, 0);
        return FALSE;
    }

    CryptReleaseContext(hCryptProv, 0);
    return TRUE;
}

static BOOL IsReparsePoint(const char* path)
{
    // Check for symlink
    DWORD attributes = GetFileAttributesA(path);
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        return TRUE;
    }
    return FALSE;
}

static BOOL IsHandleReparsePoint(HANDLE hFile)
{
    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (!GetFileInformationByHandle(hFile, &fileInfo)) {
        return TRUE; // Assume unsafe if we can't read info
    }
    return (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? TRUE : FALSE;
}

static BOOL IsValidUsername(const char* username, uint16_t length)
{
    if (length < 5 || length > 10) return FALSE;

    for (uint16_t i = 0; i < length; i++)
    {
        if (!((username[i] >= 'a' && username[i] <= 'z') ||
            (username[i] >= 'A' && username[i] <= 'Z')))
        {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL IsValidPassword(const char* password, uint16_t length)
{
    if (length < 5) return FALSE;

    BOOL hasDigit = FALSE;
    BOOL hasLower = FALSE;
    BOOL hasUpper = FALSE;
    BOOL hasSpecial = FALSE;
    BOOL hasInvalid = FALSE;
    const char* specialChars = "!@#$%^&";

    for (uint16_t i = 0; i < length; i++)
    {
        char c = password[i];
        if (c >= '0' && c <= '9') hasDigit = TRUE;
        else if (c >= 'a' && c <= 'z') hasLower = TRUE;
        else if (c >= 'A' && c <= 'Z') hasUpper = TRUE;
        else if (strchr(specialChars, c)) hasSpecial = TRUE;
        else hasInvalid = TRUE;
    }

    return hasDigit && hasLower && hasUpper && hasSpecial && !hasInvalid;
}

static NTSTATUS ComputeSecureHash(const char* input, uint16_t length, const char* saltHex, char* outputHex)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;
    PBYTE pbSalt = NULL;
    PBYTE pbInputWithSalt = NULL;
    DWORD cbSalt = 16; // 16 bytes for salt
    DWORD cbInputWithSalt;

    // Convert salt from hex back to bytes
    pbSalt = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSalt);
    if (!pbSalt) goto Cleanup;
    for (DWORD i = 0; i < cbSalt; i++) {
        // Simple hex to byte conversion (assuming input salt is 32 chars)
        sscanf_s(saltHex + (i * 2), "%2hhX", &pbSalt[i]);
    }

    // Prepare data to hash (salt + password)
    cbInputWithSalt = cbSalt + length;
    pbInputWithSalt = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbInputWithSalt);
    if (!pbInputWithSalt) goto Cleanup;

    // Copy salt, then copy password data
    memcpy(pbInputWithSalt, pbSalt, cbSalt);
    memcpy(pbInputWithSalt + cbSalt, input, length);

    // Open algorithm provider
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto Cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) goto Cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) goto Cleanup;

    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (!pbHashObject || !pbHash) goto Cleanup;

    // Create and compute hash
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) goto Cleanup;
    if (!NT_SUCCESS(BCryptHashData(hHash, pbInputWithSalt, cbInputWithSalt, 0))) goto Cleanup;
    if (!NT_SUCCESS(BCryptFinishHash(hHash, pbHash, cbHash, 0))) goto Cleanup;

    // Convert hash to hex string
    for (DWORD i = 0; i < cbHash; i++) {
        sprintf_s(outputHex + (i * 2), 3, "%02X", pbHash[i]);
    }
    status = STATUS_SUCCESS;

Cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
    if (pbSalt) HeapFree(GetProcessHeap(), 0, pbSalt);
    if (pbInputWithSalt) HeapFree(GetProcessHeap(), 0, pbInputWithSalt);

    return status;
}

static NTSTATUS SaveUserToDb(const char* username, const char* password, uint16_t passwordLength)
{
    DWORD bytesWritten = 0;
    char entryBuffer[256];
    char passwordHash[65]; // SHA256 is 32 bytes -> 64 hex chars + 1 for NULL
    char saltHex[33] = { 0 };      // 16 bytes -> 32 hex chars + 1 for NULL
    BYTE saltBytes[16];    // 16 bytes salt
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    // Generate salt
    if (!GenerateSalt(saltBytes, sizeof(saltBytes))) {
        printf("[Register] Error: Failed to generate salt.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Convert salt bytes to hex string for storage
    for (int i = 0; i < 16; i++) {
        sprintf_s(saltHex + (i * 2), 3, "%02X", saltBytes[i]);
    }

    // Compute hash
    if (!NT_SUCCESS(ComputeSecureHash(password, passwordLength, saltHex, passwordHash))) {
        printf("[Register] Error: Failed to compute hash.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Open the db file (append mode)
    hFile = CreateFileA(
        g_UsersDbPath,
        FILE_APPEND_DATA,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[Register] Error: Failed to open DB file. LE: %d\n", GetLastError());
        return STATUS_UNSUCCESSFUL;
    }

    // Verify the handle we just opened is not a symlink
    if (IsHandleReparsePoint(hFile)) {
        printf("[Register] Security Error: users.txt is a symlink/trap!\n");
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    // Prepare data (username + salt + hash)
    // <username> <salt> <hash>\r\n
    if (FAILED(StringCchPrintfA(entryBuffer, 256, "%s %s %s\r\n", username, saltHex, passwordHash))) {
        status = STATUS_BUFFER_OVERFLOW;
        goto Cleanup;
    }

    // Write
    if (!WriteFile(hFile, entryBuffer, (DWORD)strlen(entryBuffer), &bytesWritten, NULL)) {
        printf("[Register] Error: Failed to write to DB. LE: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    status = STATUS_SUCCESS;
    goto Cleanup;

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return status;
}

static BOOL IsValidSubmissionName(const char* name, uint16_t length)
{
    if (length == 0 || length > 255) return FALSE;
    // Ban "." and ".." to avoid relative path tricks
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return FALSE;

    for (uint16_t i = 0; i < length; i++) {
        char c = name[i];
        BOOL isAlpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        BOOL isNum = (c >= '0' && c <= '9');
        BOOL isSafeSpecial = (c == '.' || c == '_' || c == '-');

        if (!isAlpha && !isNum && !isSafeSpecial) return FALSE;
    }
    return TRUE;
}

static VOID CALLBACK CopyWorkerCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_WORK Work
)
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Work);

    PCOPY_CONTEXT pCtx = (PCOPY_CONTEXT)Context;
    BYTE* buffer = (BYTE*)malloc(CHUNK_SIZE);

    if (!buffer) {
        InterlockedExchange(&pCtx->Status, STATUS_NO_MEMORY);
        return;
    }

    // Create async I/O event
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent) {
        free(buffer);
        InterlockedExchange(&pCtx->Status, STATUS_UNSUCCESSFUL);
        return;
    }

    while (TRUE)
    {
        // Fail fast
        if (InterlockedCompareExchange(&pCtx->Status, 0, 0) != 0) break;

        // Grab offset
        LONG64 myEndOffset = InterlockedAdd64(&pCtx->CurrentOffset, CHUNK_SIZE);
        LONG64 myStartOffset = myEndOffset - CHUNK_SIZE;

        if (myStartOffset >= pCtx->FileSize.QuadPart) break;

        DWORD bytesToRead = CHUNK_SIZE;
        if (myEndOffset > pCtx->FileSize.QuadPart) {
            bytesToRead = (DWORD)(pCtx->FileSize.QuadPart - myStartOffset);
        }

        // Prepare overlapped for read
        OVERLAPPED ovRead = { 0 };
        ovRead.Offset = (DWORD)(myStartOffset & 0xFFFFFFFF);
        ovRead.OffsetHigh = (DWORD)(myStartOffset >> 32);
        ovRead.hEvent = hEvent;

        DWORD bytesRead = 0;
        // Async read
        if (!ReadFile(pCtx->hSource, buffer, bytesToRead, &bytesRead, &ovRead)) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                // Wait for it to finish
                if (!GetOverlappedResult(pCtx->hSource, &ovRead, &bytesRead, TRUE)) {
                    InterlockedExchange(&pCtx->Status, STATUS_UNSUCCESSFUL);
                    break;
                }
            }
            else {
                // Real failure
                InterlockedExchange(&pCtx->Status, STATUS_UNSUCCESSFUL);
                break;
            }
        }

        // Prepare overlapped for write
        // We reuse the event, but must reset it or re-create the structure
        OVERLAPPED ovWrite = { 0 };
        ovWrite.Offset = ovRead.Offset;
        ovWrite.OffsetHigh = ovRead.OffsetHigh;
        ovWrite.hEvent = hEvent;
        ResetEvent(hEvent);

        DWORD bytesWritten = 0;
        // Async write
        if (!WriteFile(pCtx->hDest, buffer, bytesRead, &bytesWritten, &ovWrite)) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                if (!GetOverlappedResult(pCtx->hDest, &ovWrite, &bytesWritten, TRUE)) {
                    InterlockedExchange(&pCtx->Status, STATUS_UNSUCCESSFUL);
                    break;
                }
            }
            else {
                InterlockedExchange(&pCtx->Status, STATUS_UNSUCCESSFUL);
                break;
            }
        }
    }

    free(buffer);
    CloseHandle(hEvent);
}

static BOOL IsPathInside(const char* parent, const char* child)
{
    // Simple prefix check
    size_t parentLen = strlen(parent);
    if (_strnicmp(parent, child, parentLen) == 0) {
        // Ensure strictly inside ("C:\User" shouldn't match "C:\UsersFake")
        if (child[parentLen] == '\\' || child[parentLen] == '\0') {
            return TRUE;
        }
    }
    return FALSE;
}

static int SecureCompare(const char* s1, const char* s2, size_t length)
{
    int result = 0;
    volatile const char* v1 = s1;
    volatile const char* v2 = s2;

    for (size_t i = 0; i < length; i++) {
        result |= (v1[i] ^ v2[i]);
    }
    return result;
}

static BOOL CreateSecureSecurityAttributes(SECURITY_ATTRIBUTES* psa, PSECURITY_DESCRIPTOR psd)
{
    if (!InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION))
        return FALSE;

    // "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;CO)"
    // SY = System, BA = Built-in Admins, CO = Creator Owner
    // Everyone else is denied
    // P: only rules defined here apply, OICI: propagates rule to files and subfolders inside, GA: full control
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;CO)",
        SDDL_REVISION_1,
        &(psa->lpSecurityDescriptor),
        NULL))
    {
        return FALSE;
    }

    psa->nLength = sizeof(SECURITY_ATTRIBUTES);
    psa->bInheritHandle = FALSE;
    return TRUE;
}

// If it's on the System Drive (C:), it MUST be inside %USERPROFILE%.
// If it's on any other drive (D:, E:), it is allowed.
// It must not be inside the %AppDir% (Self-protection).
static BOOL IsSafeExternalPath(const char* targetPath)
{
    char systemDrive[MAX_PATH];
    char userProfile[MAX_PATH];

    // Block access to AppDir (forbid overwriting our own DB/Exe)
    // This applies to all drives

    /*if (IsPathInside(g_AppDir, targetPath)) {
        printf("[Security] Blocked: Access to AppDir is forbidden.\n");
        return FALSE;
    }*/

    // Get system env info
    if (GetEnvironmentVariableA("SystemDrive", systemDrive, MAX_PATH) == 0) return FALSE;
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH) == 0) return FALSE;

    // We check if the path starts with "C:" (or whatever SystemDrive is)
    if (_strnicmp(targetPath, systemDrive, strlen(systemDrive)) == 0)
    {
        // If on system drive, must be inside %USERPROFILE%
        if (IsPathInside(userProfile, targetPath)) {
            return TRUE;
        }

        printf("[Security] Blocked: On System Drive, you can only access your User Profile (%s).\n", userProfile);
        return FALSE;
    }

    // It is on a Data Drive (D:, E:, etc.) => ALLOW
    return TRUE;
}


NTSTATUS WINAPI SafeStorageInit(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD length = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    SECURITY_ATTRIBUTES sa = { 0 };
    SECURITY_DESCRIPTOR sd = { 0 };
    BOOL hasSecAttr = FALSE;

    // If fully init, return success immediately.
    if (g_AppDir && g_UsersDir && g_UsersDbPath) {
        return STATUS_SUCCESS;
    }

    // If partially init, free everything and start fresh.
    if (g_AppDir) { free(g_AppDir); g_AppDir = NULL; }
    if (g_UsersDir) { free(g_UsersDir); g_UsersDir = NULL; }
    if (g_UsersDbPath) { free(g_UsersDbPath); g_UsersDbPath = NULL; }

    g_AppDir = (char*)malloc(MAX_PATH);
    if (g_AppDir) memset(g_AppDir, 0, MAX_PATH);
    g_UsersDir = (char*)malloc(MAX_PATH);
    if (g_UsersDir) memset(g_UsersDir, 0, MAX_PATH);
    g_UsersDbPath = (char*)malloc(MAX_PATH);
    if (g_UsersDbPath) memset(g_UsersDbPath, 0, MAX_PATH);

    // If any alloc failed, fail the whole init.
    if (!g_AppDir || !g_UsersDir || !g_UsersDbPath) {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    // Get current dir
    length = GetCurrentDirectoryA(MAX_PATH, g_AppDir);
    if (length == 0 || length > MAX_PATH) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // Construct paths
    if (FAILED(StringCchPrintfA(g_UsersDir, MAX_PATH, "%s\\users", g_AppDir)) ||
        FAILED(StringCchPrintfA(g_UsersDbPath, MAX_PATH, "%s\\users.txt", g_AppDir)))
    {
        printf("[Init] Critical Error: Path buffer overflow. Base path too long.\n");
        status = STATUS_BUFFER_OVERFLOW;
        goto Cleanup;
    }

    // Prepare Secure ACLs (Creator/Owner + System only)
    hasSecAttr = CreateSecureSecurityAttributes(&sa, &sd);

    // Create 'users' dir
    if (!CreateDirectoryA(g_UsersDir, hasSecAttr ? &sa : NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
    }

    // Symlink trap dir
    if (IsReparsePoint(g_UsersDir)) {
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    // Create/Open users.txt
    hFile = CreateFileA(
        g_UsersDbPath,
        GENERIC_READ | GENERIC_WRITE,
        0,                       // Exclusive Access
        hasSecAttr ? &sa : NULL, // Secure ACLs
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[Init] Error: Failed to create/open users.txt. LE: %d\n", GetLastError());
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (!GetFileInformationByHandle(hFile, &fileInfo)) {
        CloseHandle(hFile);
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // Symlink trap file
    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        CloseHandle(hFile);
        status = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }

    CloseHandle(hFile);

    // Free security sescriptor if allocated
    if (hasSecAttr && sa.lpSecurityDescriptor) {
        LocalFree(sa.lpSecurityDescriptor);
    }
    return STATUS_SUCCESS;

Cleanup:
    // Free security sescriptor if allocated
    if (hasSecAttr && sa.lpSecurityDescriptor) {
        LocalFree(sa.lpSecurityDescriptor);
    }

    // Free globals (prevent partial state)
    if (g_AppDir) { free(g_AppDir); g_AppDir = NULL; }
    if (g_UsersDir) { free(g_UsersDir); g_UsersDir = NULL; }
    if (g_UsersDbPath) { free(g_UsersDbPath); g_UsersDbPath = NULL; }

    return status;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    SecureZeroMemory(g_CurrentUsername, sizeof(g_CurrentUsername));

    if (g_AppDir) { free(g_AppDir); g_AppDir = NULL; }
    if (g_UsersDir) { free(g_UsersDir); g_UsersDir = NULL; }
    if (g_UsersDbPath) { free(g_UsersDbPath); g_UsersDbPath = NULL; }
}


NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    if (g_CurrentUsername[0] != '\0')
    {
        printf("[Register] Error: A user is already logged in (%s). Logout first.\n", g_CurrentUsername);
        return STATUS_ACCESS_DENIED;
    }

    char newUserDir[MAX_PATH];
    DWORD dwAttrib = 0;
    NTSTATUS status = STATUS_SUCCESS;

    // Username validation
    if (!IsValidUsername(Username, UsernameLength))
    {
        printf("[Register] Error: Invalid username format (5-10 chars, Alpha only).\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Password validation
    if (!IsValidPassword(Password, PasswordLength)) {
        printf("[Register] Error: Invalid password complexity.\n");
        printf("Must be >= 5 chars, include Digit, Lower, Upper and Special (!@#$%%^&). Other characters are invalid\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Construct specific user dir path
    if (FAILED(StringCchPrintfA(newUserDir, MAX_PATH, "%s\\%s", g_UsersDir, Username)))
    {
        printf("[Register] Error: Path buffer overflow.\n");
        return STATUS_BUFFER_OVERFLOW;
    }

    // Check if dir already exists
    dwAttrib = GetFileAttributesA(newUserDir);
    if (dwAttrib != INVALID_FILE_ATTRIBUTES)
    {
        // Dir exists => user exists (or state is inconsistent)
        printf("[Register] Error: User already exists.\n");
        return STATUS_DUPLICATE_NAME;
    }

    // ACL resources
    SECURITY_ATTRIBUTES sa = { 0 };
    SECURITY_DESCRIPTOR sd = { 0 };
    BOOL hasSecAttr = FALSE;

    // Prepare secure ACLs for the new user dir
    if (CreateSecureSecurityAttributes(&sa, &sd)) {
        hasSecAttr = TRUE;
    }

    // Create the user dir
    if (!CreateDirectoryA(newUserDir, hasSecAttr ? &sa : NULL))
    {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            printf("[Register] Error: Failed to create user directory. LE: %d\n", GetLastError());
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
    }

    // Free security attributes if successfully created
    if (hasSecAttr && sa.lpSecurityDescriptor) {
        LocalFree(sa.lpSecurityDescriptor);
        sa.lpSecurityDescriptor = NULL;
    }

    // Verify not to have created/opened a symlink
    if (IsReparsePoint(newUserDir))
    {
        // If the just created dir is somehow a symlink, delete it and fail
        printf("[Register] Security Alert: User directory is a symlink. Deleting.\n");
        RemoveDirectoryA(newUserDir);
        return STATUS_ACCESS_DENIED;
    }

    // Save to db
    status = SaveUserToDb(Username, Password, PasswordLength);
    if (!NT_SUCCESS(status)) {
        printf("[Register] Error: Failed to update database. Rolling back.\n");
        // Rollback: Delete the just created dir so there is not a zombie user
        RemoveDirectoryA(newUserDir);
        return status;
    }

    printf("[Register] Success: User '%s' registered.\n", Username);
    status = STATUS_SUCCESS;
    goto Cleanup;

Cleanup:
    // Free the descriptor if fail before cleanup.
    if (hasSecAttr && sa.lpSecurityDescriptor) {
        LocalFree(sa.lpSecurityDescriptor);
    }
    return status;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    // Check if a user is already logged in
    if (g_CurrentUsername[0] != '\0')
    {
        printf("[Login] Error: A user is already logged in (%s). Logout first.\n", g_CurrentUsername);
        return STATUS_UNSUCCESSFUL;
    }

    // Count the failed login attempts in the last second
    DWORD currentTime = GetTickCount();
    if (currentTime - g_LastFailedLoginTime < LOCKOUT_DURATION_MS)
    {
        if (g_FailedLoginCount >= MAX_LOGIN_ATTEMPTS)
        {
            printf("[Login] Security Alert: Too many failed attempts. Try again later.\n");
            return STATUS_ACCESS_DENIED;
        }
    }
    else
    {
        // Reset counter if enough time has passed
        g_FailedLoginCount = 0;
    }

    // Username validation
    if (!IsValidUsername(Username, UsernameLength))
    {
        printf("[Login] Error: Invalid username format.\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Open the db
    HANDLE hFile = CreateFileA(
        g_UsersDbPath,
        GENERIC_READ,           // Only read
        FILE_SHARE_READ,        // Allow others to read (but not write)
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, // Needed for potential handle checks
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[Login] Error: Database not found.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Check for symlink db
    if (IsHandleReparsePoint(hFile))
    {
        printf("[Login] Security Alert: Database file is a symlink!\n");
        CloseHandle(hFile);
        return STATUS_ACCESS_DENIED;
    }

    // Read and parse the db
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
    {
        CloseHandle(hFile);
        printf("[Login] Error: Database is empty or invalid.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Allocate buffer for the whole file (relatively small file)
    char* fileBuffer = (char*)malloc(fileSize + 1);
    if (!fileBuffer)
    {
        CloseHandle(hFile);
        return STATUS_NO_MEMORY;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL))
    {
        free(fileBuffer);
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }
    fileBuffer[bytesRead] = '\0';
    CloseHandle(hFile);

    // Verify credentials
    BOOL userFound = FALSE;
    BOOL passwordCorrect = FALSE;

    char targetHash[65] = { 0 };

    // Parse line by line
    char* context = NULL;
    char* line = strtok_s(fileBuffer, "\r\n", &context);

    while (line != NULL)
    {
        char dbUser[MAX_PATH] = { 0 };
        char dbSalt[33] = { 0 };
        char dbHash[65] = { 0 };

        // Expected format: <username> <salt> <hash>
        if (sscanf_s(line, "%s %s %s", dbUser, (unsigned)_countof(dbUser), dbSalt, (unsigned)_countof(dbSalt), dbHash, (unsigned)_countof(dbHash)) == 3)
        {
            if (strcmp(dbUser, Username) == 0)
            {
                userFound = TRUE;
                // Found user, calculate hash with stored salt
                if (NT_SUCCESS(ComputeSecureHash(Password, PasswordLength, dbSalt, targetHash)))
                {
                    // Use SecureCompare for constant-time comparison
                    if (SecureCompare(dbHash, targetHash, 64) == 0)
                    {
                        passwordCorrect = TRUE;
                    }
                }
                // No break to prevent time-based username enumeration
            }
        }
        line = strtok_s(NULL, "\r\n", &context);
    }

    SecureZeroMemory(fileBuffer, fileSize);
    SecureZeroMemory(targetHash, sizeof(targetHash));
    free(fileBuffer);

    // Handle result
    if (userFound && passwordCorrect)
    {
        strcpy_s(g_CurrentUsername, sizeof(g_CurrentUsername), Username);
        g_FailedLoginCount = 0;

        printf("[Login] Success: Welcome, %s!\n", g_CurrentUsername);
        return STATUS_SUCCESS;
    }
    else
    {
        // Update failed counters
        g_LastFailedLoginTime = GetTickCount();
        g_FailedLoginCount++;

        printf("[Login] Error: Invalid credentials or user does not exist.\n");

        return STATUS_UNSUCCESSFUL;
    }
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    // Fail for no logged in user
    if (g_CurrentUsername[0] == '\0')
    {
        printf("[Logout] Error: No user is currently logged in.\n");
        return STATUS_UNSUCCESSFUL;
    }

    printf("[Logout] Goodbye, %s!\n", g_CurrentUsername);

    // Use SecureZeroMemory to ensure the username isn't in RAM
    SecureZeroMemory(g_CurrentUsername, sizeof(g_CurrentUsername));

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
    NTSTATUS status = STATUS_SUCCESS;
    char destPath[MAX_PATH];
    char userDir[MAX_PATH];
    HANDLE hSource = INVALID_HANDLE_VALUE;
    HANDLE hDest = INVALID_HANDLE_VALUE;

    // Thread pool resources
    PTP_POOL pool = NULL;
    PTP_CLEANUP_GROUP cleanupGroup = NULL;
    PTP_WORK work = NULL;
    TP_CALLBACK_ENVIRON callBackEnviron;

    // ACL resources
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd = { 0 };
    BOOL hasSecAttr = FALSE;

    // Login check
    if (g_CurrentUsername[0] == '\0') {
        printf("[Store] Error: No user logged in.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Filename validation
    if (!IsValidSubmissionName(SubmissionName, SubmissionNameLength)) {
        printf("[Store] Error: Invalid submission name (Use a-z, 0-9, . _ -).\n");
        return STATUS_INVALID_PARAMETER;
    }

    char fullSourcePath[MAX_PATH];
    char* filePart;

    // Check path is valid
    if (GetFullPathNameA(SourceFilePath, MAX_PATH, fullSourcePath, &filePart) == 0) {
        printf("[Store] Error: Invalid source path.\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Prevent uploading sensitive system files
    if (!IsSafeExternalPath(fullSourcePath)) {
        return STATUS_ACCESS_DENIED;
    }

    // Open source file
    hSource = CreateFileA(
        SourceFilePath,
        GENERIC_READ,
        FILE_SHARE_READ, // Allow others to read while we copy
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // OVERLAPPED for concurrent reads
        NULL
    );

    if (hSource == INVALID_HANDLE_VALUE) {
        printf("[Store] Error: Source file not found.\n");
        return STATUS_UNSUCCESSFUL;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hSource, &fileSize)) {
        CloseHandle(hSource);
        return STATUS_UNSUCCESSFUL;
    }

    // Prepare destination path & security checks
    if (FAILED(StringCchPrintfA(userDir, MAX_PATH, "%s\\%s", g_UsersDir, g_CurrentUsername))) {
        CloseHandle(hSource);
        return STATUS_BUFFER_OVERFLOW;
    }

    // Check if user dir is a symlink
    if (IsReparsePoint(userDir)) {
        printf("[Store] Security Alert: User directory is a symlink!\n");
        CloseHandle(hSource);
        return STATUS_ACCESS_DENIED;
    }

    if (FAILED(StringCchPrintfA(destPath, MAX_PATH, "%s\\%s", userDir, SubmissionName))) {
        CloseHandle(hSource);
        return STATUS_BUFFER_OVERFLOW;
    }

    // Prepare secure ACLs (destination)
    // Create a security descriptor that allows only:
    // - SYSTEM (full control)
    // - Administrators (full control)
    // - Creator owner (full control)
    if (CreateSecureSecurityAttributes(&sa, &sd)) {
        hasSecAttr = TRUE;
    }
    else {
        printf("[Store] Warning: Failed to create secure ACLs. Using default.\n");
        CloseHandle(hSource);
        return STATUS_ACCESS_DENIED;
    }

    // Open destination file
    hDest = CreateFileA(
        destPath,
        GENERIC_WRITE,
        0, // Exclusive access
        hasSecAttr ? &sa : NULL,
        CREATE_ALWAYS, // Overwrite if exists
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    // Cleanup ACLs immediately after use
    if (hasSecAttr && sa.lpSecurityDescriptor) {
        LocalFree(sa.lpSecurityDescriptor);
    }

    if (hDest == INVALID_HANDLE_VALUE) {
        printf("[Store] Error: Failed to create destination file. LE: %d\n", GetLastError());
        CloseHandle(hSource);
        status = STATUS_UNSUCCESSFUL;
    }

    // Setup private thread pool
    InitializeThreadpoolEnvironment(&callBackEnviron);
    pool = CreateThreadpool(NULL);
    if (!pool) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    SetThreadpoolThreadMaximum(pool, THREAD_COUNT);
    SetThreadpoolThreadMinimum(pool, THREAD_COUNT);

    cleanupGroup = CreateThreadpoolCleanupGroup();
    if (!cleanupGroup) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    SetThreadpoolCallbackPool(&callBackEnviron, pool);
    SetThreadpoolCallbackCleanupGroup(&callBackEnviron, cleanupGroup, NULL);

    // Setup context & submit work
    COPY_CONTEXT ctx = { 0 };
    ctx.hSource = hSource;
    ctx.hDest = hDest;
    ctx.FileSize = fileSize;
    ctx.CurrentOffset = 0;
    ctx.Status = 0;

    work = CreateThreadpoolWork(CopyWorkerCallback, &ctx, &callBackEnviron);
    if (!work) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // Submit the work item 4 times, once for each thread
    for (int i = 0; i < THREAD_COUNT; i++) {
        SubmitThreadpoolWork(work);
    }

    // Wait for completion
    WaitForThreadpoolWorkCallbacks(work, FALSE);

    // Check results
    if (ctx.Status != 0) {
        printf("[Store] Error: Transfer failed mid-stream (Status: 0x%x).\n", ctx.Status);
        status = (NTSTATUS)ctx.Status;
    }
    else {
        printf("[Store] Success: File stored (%lld bytes).\n", fileSize.QuadPart);
        status = STATUS_SUCCESS;
    }
    goto Cleanup;

Cleanup:
    // Close thread pool resources
    if (cleanupGroup) {
        CloseThreadpoolCleanupGroupMembers(cleanupGroup, FALSE, NULL);
        CloseThreadpoolCleanupGroup(cleanupGroup);
    }
    if (pool) {
        CloseThreadpool(pool);
    }

    // Close file handles
    if (hSource != INVALID_HANDLE_VALUE) CloseHandle(hSource);
    if (hDest != INVALID_HANDLE_VALUE) CloseHandle(hDest);

    UNREFERENCED_PARAMETER(SourceFilePathLength);
    return status;
}


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    char sourcePath[MAX_PATH];
    char userDir[MAX_PATH];
    HANDLE hSource = INVALID_HANDLE_VALUE;
    HANDLE hDest = INVALID_HANDLE_VALUE;

    // Thread pool resources
    PTP_POOL pool = NULL;
    PTP_CLEANUP_GROUP cleanupGroup = NULL;
    PTP_WORK work = NULL;
    TP_CALLBACK_ENVIRON callBackEnviron;

    // Login check
    if (g_CurrentUsername[0] == '\0') {
        printf("[Retrieve] Error: No user logged in.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Filename validation
    if (!IsValidSubmissionName(SubmissionName, SubmissionNameLength)) {
        printf("[Retrieve] Error: Invalid submission name.\n");
        return STATUS_INVALID_PARAMETER;
    }

    char fullDestPath[MAX_PATH];
    char* filePart = NULL;

    // Check path is valid
    if (GetFullPathNameA(DestinationFilePath, MAX_PATH, fullDestPath, &filePart) == 0) {
        printf("[Retrieve] Error: Invalid destination path.\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Prevent overwriting sensitive system files
    if (!IsSafeExternalPath(fullDestPath)) {
        return STATUS_ACCESS_DENIED;
    }

    // Symlink check on the resolved path
    if (IsReparsePoint(fullDestPath)) {
        printf("[Retrieve] Security Alert: Destination path resolves to a symlink!\n");
        return STATUS_ACCESS_DENIED;
    }

    // Construct source path & security checks
    if (FAILED(StringCchPrintfA(userDir, MAX_PATH, "%s\\%s", g_UsersDir, g_CurrentUsername))) {
        return STATUS_BUFFER_OVERFLOW;
    }

    // Check if user dir is a symlink
    if (IsReparsePoint(userDir)) {
        printf("[Retrieve] Security Alert: User directory is a symlink! Cannot read safely.\n");
        return STATUS_ACCESS_DENIED;
    }

    if (FAILED(StringCchPrintfA(sourcePath, MAX_PATH, "%s\\%s", userDir, SubmissionName))) {
        return STATUS_BUFFER_OVERFLOW;
    }

    // Open source file
    hSource = CreateFileA(
        sourcePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // Async read
        NULL
    );

    if (hSource == INVALID_HANDLE_VALUE) {
        printf("[Retrieve] Error: Submission '%s' not found.\n", SubmissionName);
        return STATUS_UNSUCCESSFUL;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hSource, &fileSize)) {
        CloseHandle(hSource);
        return STATUS_UNSUCCESSFUL;
    }

    // Open destination file
    hDest = CreateFileA(
        DestinationFilePath,
        GENERIC_WRITE,
        0, // Exclusive access
        NULL,
        CREATE_ALWAYS, // Always overwrite
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // Async write
        NULL
    );

    if (hDest == INVALID_HANDLE_VALUE) {
        printf("[Retrieve] Error: Failed to create destination file at '%s'. LE: %d\n", DestinationFilePath, GetLastError());
        CloseHandle(hSource);
        return STATUS_UNSUCCESSFUL;
    }

    // Setup private thread pool
    InitializeThreadpoolEnvironment(&callBackEnviron);
    pool = CreateThreadpool(NULL);
    if (!pool) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    SetThreadpoolThreadMaximum(pool, THREAD_COUNT);
    SetThreadpoolThreadMinimum(pool, THREAD_COUNT);

    cleanupGroup = CreateThreadpoolCleanupGroup();
    if (!cleanupGroup) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    SetThreadpoolCallbackPool(&callBackEnviron, pool);
    SetThreadpoolCallbackCleanupGroup(&callBackEnviron, cleanupGroup, NULL);

    // Setup context
    COPY_CONTEXT ctx = { 0 };
    ctx.hSource = hSource;
    ctx.hDest = hDest;
    ctx.FileSize = fileSize;
    ctx.CurrentOffset = 0;
    ctx.Status = 0;

    // Create and submit work
    work = CreateThreadpoolWork(CopyWorkerCallback, &ctx, &callBackEnviron);
    if (!work) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        SubmitThreadpoolWork(work);
    }

    // Wait for completion
    WaitForThreadpoolWorkCallbacks(work, FALSE);

    // Check results
    if (ctx.Status != 0) {
        printf("[Retrieve] Error: Transfer failed (Status: 0x%x).\n", ctx.Status);
        status = (NTSTATUS)ctx.Status;
    }
    else {
        printf("[Retrieve] Success: File retrieved (%lld bytes) to '%s'.\n", fileSize.QuadPart, DestinationFilePath);
        status = STATUS_SUCCESS;
    }
    goto Cleanup;

Cleanup:
    if (cleanupGroup) {
        CloseThreadpoolCleanupGroupMembers(cleanupGroup, FALSE, NULL);
        CloseThreadpoolCleanupGroup(cleanupGroup);
    }
    if (pool) {
        CloseThreadpool(pool);
    }
    if (hSource != INVALID_HANDLE_VALUE) CloseHandle(hSource);
    if (hDest != INVALID_HANDLE_VALUE) CloseHandle(hDest);

    UNREFERENCED_PARAMETER(DestinationFilePathLength);
    return status;
}