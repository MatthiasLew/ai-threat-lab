#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>

/* Fixed test program. The host creates only private synthetic fixtures. */
static int failure(const wchar_t *operation, DWORD code) {
    fwprintf(stderr, L"%ls: 0x%08lX\n", operation, code);
    return 1;
}

static BOOL denied(const wchar_t *path, DWORD access, DWORD disposition) {
    HANDLE file = CreateFileW(path, access, FILE_SHARE_READ, NULL, disposition, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_ACCESS_DENIED;
    CloseHandle(file);
    return FALSE;
}

static BOOL handle_absent(HANDLE handle) {
    DWORD flags;
    __try {
        if (!GetHandleInformation(handle, &flags)) return GetLastError() == ERROR_INVALID_HANDLE;
        /* Handle numbers can be reused by the child loader. Compare the object. */
        if (GetFileType(handle) != FILE_TYPE_DISK) return TRUE;
        wchar_t name[MAX_PATH];
        DWORD length = GetFinalPathNameByHandleW(
            handle, name, ARRAYSIZE(name), FILE_NAME_OPENED
        );
        const wchar_t suffix[] = L"\\private\\canary.txt";
        size_t suffix_length = ARRAYSIZE(suffix) - 1;
        return length && length < ARRAYSIZE(name) &&
            (length < suffix_length || _wcsicmp(name + length - suffix_length, suffix) != 0);
    } __except (GetExceptionCode() == (DWORD)0xC0000008
                ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return TRUE;
    }
}

static BOOL denied_network(int family, int kind, int port) {
    SOCKADDR_IN ipv4 = {0};
    SOCKADDR_IN6 ipv6 = {0};
    SOCKADDR *address;
    int size;
    ipv4.sin_family = AF_INET;
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ipv4.sin_port = htons((u_short)port);
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_addr = in6addr_loopback;
    ipv6.sin6_port = htons((u_short)port);
    if (family == AF_INET) {
        address = (SOCKADDR *)&ipv4;
        size = sizeof(ipv4);
    } else {
        address = (SOCKADDR *)&ipv6;
        size = sizeof(ipv6);
    }
    SOCKET client = socket(family, kind, 0);
    if (client == INVALID_SOCKET) return WSAGetLastError() == WSAEACCES;
    u_long nonblocking = 1;
    if (ioctlsocket(client, FIONBIO, &nonblocking)) {
        closesocket(client);
        return FALSE;
    }
    int result = kind == SOCK_STREAM
        ? connect(client, address, size) : sendto(client, "probe", 5, 0, address, size);
    int error = WSAGetLastError();
    if (result == SOCKET_ERROR && kind == SOCK_STREAM && error == WSAEWOULDBLOCK) {
        fd_set writable, failed;
        FD_ZERO(&writable);
        FD_ZERO(&failed);
        FD_SET(client, &writable);
        FD_SET(client, &failed);
        struct timeval timeout = {1, 0};
        int ready = select(0, NULL, &writable, &failed, &timeout);
        if (ready == 0) error = WSAETIMEDOUT;
        else if (ready > 0) {
            int length = sizeof(error);
            if (getsockopt(client, SOL_SOCKET, SO_ERROR, (char *)&error, &length)) error = 0;
        } else error = 0;
    }
    closesocket(client);
    /* Winsock can accept a UDP datagram locally and WFP can drop it later.
       The host checks delivery at its positively controlled listener. */
    if (kind == SOCK_DGRAM && result == 5) return TRUE;
    return result == SOCKET_ERROR && (error == WSAEACCES || error == WSAECONNREFUSED
        || error == WSAETIMEDOUT);
}

static int payload(int argc, wchar_t **argv) {
    HANDLE token;
    DWORD is_container, size, written;
    char byte;
    if (argc != 9) return 10;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 11;
    BOOL queried = GetTokenInformation(
        token, TokenIsAppContainer, &is_container, sizeof(is_container), &size
    );
    CloseHandle(token);
    if (!queried || !is_container) return 12;
    if (!handle_absent((HANDLE)(ULONG_PTR)_wcstoui64(argv[2], NULL, 10))) return 13;
    HANDLE input = CreateFileW(
        L"input\\approved.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL
    );
    if (input == INVALID_HANDLE_VALUE) return 14;
    BOOL read = ReadFile(input, &byte, 1, &size, NULL);
    CloseHandle(input);
    if (!read || size != 1 || byte != 'x') return 15;
    if (!denied(L"input\\approved.txt", GENERIC_WRITE, OPEN_EXISTING)) return 16;
    if (!denied(L"private\\canary.txt", GENERIC_READ, OPEN_EXISTING)) return 17;
    if (!denied(L"outside.txt", GENERIC_WRITE, CREATE_NEW)) return 18;
    if (!denied(L"input\\junction\\canary.txt", GENERIC_READ, OPEN_EXISTING)) return 19;
    if (!wcscmp(argv[8], L"symlink")
        && !denied(L"input\\symlink", GENERIC_READ, OPEN_EXISTING)) return 32;
    HANDLE output = CreateFileW(
        L"scratch\\result", GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL
    );
    if (output == INVALID_HANDLE_VALUE) return 20;
    BOOL wrote = WriteFile(output, "x", 1, &written, NULL);
    CloseHandle(output);
    if (!wrote || written != 1) return 21;
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 22;
    for (int i = 0; i < 4; ++i) {
        if (!denied_network(i % 2 ? AF_INET6 : AF_INET,
                           i < 2 ? SOCK_STREAM : SOCK_DGRAM, _wtoi(argv[3 + i]))) {
            WSACleanup();
            return 23 + i;
        }
    }
    WSACleanup();
    wchar_t executable[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, executable, ARRAYSIZE(executable));
    if (!length || length >= ARRAYSIZE(executable)) return 27;
    wchar_t command[2 * MAX_PATH];
    if (swprintf_s(command, ARRAYSIZE(command), L"\"%ls\" noop", executable) < 0) return 28;
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {0};
    if (CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &startup, &process)) {
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
        return 29;
    }
    DWORD error = GetLastError();
    if (error != ERROR_ACCESS_DENIED && error != ERROR_NOT_ENOUGH_QUOTA) return 30;
    output = CreateFileW(L"scratch\\ready", GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (output == INVALID_HANDLE_VALUE) return 31;
    CloseHandle(output);
    if (!wcscmp(argv[7], L"wait")) Sleep(30000);
    return 0;
}

static int launch(wchar_t **argv) {
    SECURITY_CAPABILITIES capabilities = {0};
    HRESULT status = DeriveAppContainerSidFromAppContainerName(argv[2], &capabilities.AppContainerSid);
    if (FAILED(status)) return failure(L"DeriveAppContainerSidFromAppContainerName", status);
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(NULL, 2, 0, &bytes);
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!startup.lpAttributeList) {
        FreeSid(capabilities.AppContainerSid);
        return failure(L"HeapAlloc", ERROR_OUTOFMEMORY);
    }
    int result = 1;
    BOOL initialized = InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &bytes);
    HANDLE job = NULL;
    HANDLE canary = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION process = {0};
    if (!initialized) {
        failure(L"InitializeProcThreadAttributeList", GetLastError());
        goto cleanup;
    }
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities),
            NULL, NULL)) {
        failure(L"UpdateProcThreadAttribute", GetLastError());
        goto cleanup;
    }
    job = CreateJobObjectW(NULL, NULL);
    if (!job) {
        failure(L"CreateJobObjectW", GetLastError());
        goto cleanup;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.JobMemoryLimit = 128 * 1024 * 1024;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        failure(L"SetInformationJobObject", GetLastError());
        goto cleanup;
    }
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &job, sizeof(job), NULL, NULL)) {
        failure(L"UpdateProcThreadAttribute (job list)", GetLastError());
        goto cleanup;
    }
    SECURITY_ATTRIBUTES inherited = {sizeof(inherited), NULL, TRUE};
    canary = CreateFileW(
        L"private\\canary.txt", GENERIC_READ, FILE_SHARE_READ, &inherited, OPEN_EXISTING, 0, NULL
    );
    if (canary == INVALID_HANDLE_VALUE) {
        failure(L"CreateFileW synthetic handle", GetLastError());
        goto cleanup;
    }
    wchar_t executable[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, executable, ARRAYSIZE(executable));
    if (!length || length >= ARRAYSIZE(executable)) {
        failure(L"GetModuleFileNameW", GetLastError());
        goto cleanup;
    }
    wchar_t command[2 * MAX_PATH];
    if (swprintf_s(command, ARRAYSIZE(command), L"\"%ls\" payload %llu %ls %ls %ls %ls %ls %ls",
            executable, (unsigned long long)(ULONG_PTR)canary,
            argv[3], argv[4], argv[5], argv[6], argv[7], argv[8]) < 0) goto cleanup;
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &startup.StartupInfo, &process)) {
        failure(L"CreateProcessW (AppContainer)", GetLastError());
        goto cleanup;
    }
    if (ResumeThread(process.hThread) == (DWORD)-1) {
        failure(L"ResumeThread", GetLastError());
        goto cleanup;
    }
    printf("%lu\n", process.dwProcessId);
    fflush(stdout);
    DWORD wait = WaitForSingleObject(process.hProcess, 10000);
    if (wait == WAIT_TIMEOUT) {
        result = 124;
    } else if (wait == WAIT_OBJECT_0) {
        DWORD code;
        if (GetExitCodeProcess(process.hProcess, &code)) result = (int)code;
        else failure(L"GetExitCodeProcess", GetLastError());
    } else {
        failure(L"WaitForSingleObject", GetLastError());
    }
cleanup:
    if (process.hProcess) {
        if (result) {
            TerminateProcess(process.hProcess, 1);
            WaitForSingleObject(process.hProcess, 5000);
        }
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
    }
    if (job) CloseHandle(job);
    if (canary != INVALID_HANDLE_VALUE) CloseHandle(canary);
    if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    FreeSid(capabilities.AppContainerSid);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && !wcscmp(argv[1], L"noop")) return 0;
    if (argc >= 2 && !wcscmp(argv[1], L"payload")) return payload(argc, argv);
    if (argc == 9 && !wcscmp(argv[1], L"launch")) return launch(argv);
    if (argc != 3) return 2;
    if (!wcscmp(argv[1], L"delete")) {
        HRESULT status = DeleteAppContainerProfile(argv[2]);
        return FAILED(status) ? failure(L"DeleteAppContainerProfile", status) : 0;
    }
    if (wcscmp(argv[1], L"create")) return 2;
    PSID sid = NULL;
    HRESULT status = CreateAppContainerProfile(argv[2], argv[2], argv[2], NULL, 0, &sid);
    if (FAILED(status)) return failure(L"CreateAppContainerProfile", status);
    wchar_t *sid_string = NULL;
    if (!ConvertSidToStringSidW(sid, &sid_string)) {
        DWORD error = GetLastError();
        DeleteAppContainerProfile(argv[2]);
        FreeSid(sid);
        return failure(L"ConvertSidToStringSidW", error);
    }
    wprintf(L"%ls\n", sid_string);
    LocalFree(sid_string);
    FreeSid(sid);
    return 0;
}
