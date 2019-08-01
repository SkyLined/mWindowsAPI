from mWindowsSDK import *;
from ..fsGetPythonISA import fsGetPythonISA;

bIs64Bit = fsGetPythonISA() == "x64";

oKernel32 = cDLL(
  "kernel32.dll",
  {
    "AssignProcessToJobObject": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, HANDLE),
    },
    "CloseHandle": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE),
    },
    "CreateFileA": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE),
    },
    "CreateFileW": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE),
    },
    "CreateToolhelp32Snapshot": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (DWORD, DWORD),
    },
    "CreateJobObjectA": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (LPSECURITY_ATTRIBUTES, LPCSTR),
    },
    "CreateJobObjectW": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (LPSECURITY_ATTRIBUTES, LPCWSTR),
    },
    "CreateNamedPipeA": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES),
    },
    "CreateNamedPipeW": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES),
    },
    "CreatePipe": {
      "xReturnType": BOOL,
      "txArgumentTypes": (PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD),
    },
    "CreateProcessA": {
      "xReturnType": BOOL,
      "txArgumentTypes": (LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR , LPSTARTUPINFOA, LPPROCESS_INFORMATION),
    },
    "CreateProcessW": {
      "xReturnType": BOOL,
      "txArgumentTypes": (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR , LPSTARTUPINFOW, LPPROCESS_INFORMATION),
    },
    "CreateRemoteThread": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD),
    },
    "DebugActiveProcess": {
      "xReturnType": BOOL,
      "txArgumentTypes": (DWORD),
    },
    "DebugActiveProcessStop": {
      "xReturnType": BOOL,
      "txArgumentTypes": (DWORD),
    },
    "DebugBreakProcess": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE),
    },
    "DuplicateHandle": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD),
    },
    "GenerateConsoleCtrlEvent": {
      "xReturnType": BOOL,
      "txArgumentTypes": (DWORD, DWORD),
    },
    "GetConsoleMode": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, PDWORD),
    },
    "GetConsoleScreenBufferInfo": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, PCONSOLE_SCREEN_BUFFER_INFO),
    },
    "GetCurrentProcess": {
      "xReturnType": HANDLE,
    },
    "GetCurrentProcessId": {
      "xReturnType": DWORD,
    },
    "GetExitCodeProcess": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPDWORD),
    },
    "GetLastError": {
      "xReturnType": DWORD,
    },
    "GetNativeSystemInfo": {
      "txArgumentTypes": (LPSYSTEM_INFO),
    },
    "GetProcessHeap": {
      "xReturnType": HANDLE,
    },
    "GetShortPathNameA": {
      "xReturnType": DWORD,
      "txArgumentTypes": (LPCSTR, LPSTR, DWORD),
    },
    "GetShortPathNameW": {
      "xReturnType": DWORD,
      "txArgumentTypes": (LPCWSTR, LPWSTR, DWORD),
    },
    "GetStdHandle": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (DWORD),
    },
    "GetSystemInfo": {
      "txArgumentTypes": (LPSYSTEM_INFO),
    },
    "GetThreadDescription": {
      "xReturnType": HRESULT,
      "txArgumentTypes": (HANDLE, PPWSTR),
    },
    "GetWindowsDirectoryA": {
      "xReturnType": UINT,
      "txArgumentTypes": (LPSTR, UINT),
    },
    "GetWindowsDirectoryW": {
      "xReturnType": UINT,
      "txArgumentTypes": (LPWSTR, UINT),
    },
    "HeapAlloc": {
      "xReturnType": LPVOID,
      "txArgumentTypes": (HANDLE, DWORD, SIZE_T),
    },
    "HeapCreate": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (DWORD, SIZE_T, SIZE_T),
    },
    "HeapFree": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, DWORD, LPVOID),
    },
    "HeapReAlloc": {
      "xReturnType": LPVOID,
      "txArgumentTypes": (HANDLE, DWORD, LPVOID, SIZE_T),
    },
    "IsWow64Process": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, PBOOL),
    },
    "IsProcessInJob": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, HANDLE, PBOOL),
    },
    "K32EnumProcesses": {
      "xReturnType": BOOL,
      "txArgumentTypes": (PDWORD, DWORD, PDWORD),
    },
    "K32GetProcessMemoryInfo": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD),
    },
    "LocalFree": {
      "xReturnType": HLOCAL,
      "txArgumentTypes": (HLOCAL),
    },
    "Module32First": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPMODULEENTRY32A),
    },
    "Module32FirstW": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPMODULEENTRY32W),
    },
    "Module32Next": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPMODULEENTRY32A),
    },
    "Module32NextW": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPMODULEENTRY32W),
    },
    "OpenThread": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (DWORD, BOOL, DWORD),
    },
    "OpenProcess": {
      "xReturnType": HANDLE,
      "txArgumentTypes": (DWORD, BOOL, DWORD),
    },
    "OpenProcessToken": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, DWORD, PHANDLE),
    },
    "Process32First": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPPROCESSENTRY32A),
    },
    "Process32FirstW": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPPROCESSENTRY32W),
    },
    "Process32Next": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPPROCESSENTRY32A),
    },
    "Process32NextW": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPPROCESSENTRY32W),
    },
    "QueryInformationJobObject": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD, LPDWORD),
    },
    "ReadFile": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED),
    },
    "ReadProcessMemory": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPCVOID, LPVOID, SIZE_T, PSIZE_T),
    },
    "ResumeThread": {
      "xReturnType": DWORD,
      "txArgumentTypes": (HANDLE),
    },
    "SetConsoleTextAttribute": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, WORD),
    },
    "SetConsoleTitleA": {
      "xReturnType": BOOL,
      "txArgumentTypes": (LPCSTR),
    },
    "SetConsoleTitleW": {
      "xReturnType": BOOL,
      "txArgumentTypes": (LPCWSTR),
    },
    "SetHandleInformation": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, DWORD, DWORD),
    },
    "SetInformationJobObject": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD),
    },
    "SetLastError": {
      "txArgumentTypes": (DWORD),
    },
    "SetNamedPipeHandleState": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPDWORD, LPDWORD, LPDWORD),
    },
    "SuspendThread": {
      "xReturnType": DWORD,
      "txArgumentTypes": (HANDLE),
    },
    "TerminateProcess": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, UINT),
    },
    "TerminateThread": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, DWORD),
    },
    "Thread32First": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPTHREADENTRY32),
    },
    "Thread32Next": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPTHREADENTRY32),
    },
    "VirtualAlloc": {
      "xReturnType": LPVOID,
      "txArgumentTypes": (LPVOID, SIZE_T, DWORD, DWORD),
    },
    "VirtualAllocEx": {
      "xReturnType": LPVOID,
      "txArgumentTypes": (HANDLE, LPVOID, SIZE_T, DWORD, DWORD),
    },
    "VirtualFree": {
      "xReturnType": BOOL,
      "txArgumentTypes": (LPVOID, SIZE_T, DWORD),
    },
    "VirtualFreeEx": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPVOID, SIZE_T, DWORD),
    },
    "VirtualProtect": {
      "xReturnType": BOOL,
      "txArgumentTypes": (LPVOID, SIZE_T, DWORD, PDWORD),
    },
    "VirtualProtectEx": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPVOID, SIZE_T, DWORD, PDWORD),
    },
    "VirtualQuery": {
      "xReturnType": SIZE_T,
      "txArgumentTypes": (LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T),
    },
    "VirtualQueryEx": {
      "xReturnType": SIZE_T,
      "txArgumentTypes": (HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T),
    },
    "WaitForSingleObject": {
      "xReturnType": DWORD,
      "txArgumentTypes": (HANDLE, DWORD),
    },
    "WriteConsoleA": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPCSTR, DWORD, LPDWORD, LPVOID),
    },
    "WriteConsoleW": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPCWSTR, DWORD, LPDWORD, LPVOID),
    },
    "WriteFile": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED),
    },
    "WriteProcessMemory": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, LPVOID, LPCVOID, SIZE_T, PSIZE_T),
    },
    "GetThreadContext": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, PCONTEXT64 if bIs64Bit else PCONTEXT32),
    },
    "SetThreadContext": {
      "xReturnType": BOOL,
      "txArgumentTypes": (HANDLE, PCONTEXT64 if bIs64Bit else PCONTEXT32),
    },
  }
);

if bIs64Bit:
  cDLL.fAddFunctions(
    oKernel32,
    {
      "Wow64GetThreadContext": {
        "xReturnType": BOOL,
        "txArgumentTypes": (HANDLE, P64CONTEXT32),
      },
      "Wow64SetThreadContext": {
        "xReturnType": BOOL,
        "txArgumentTypes": (HANDLE, P64CONTEXT32),
      },
    }
  );
