from cDLL import cDLL;
from ..mTypes import *;
from ..fsGetPythonISA import fsGetPythonISA;

KERNEL32 = cDLL("kernel32.dll");

PCONTEXT = POINTER({"x86": CONTEXT_32, "x64": CONTEXT_64}[fsGetPythonISA()]);
PPCONTEXT = POINTER(PCONTEXT);

KERNEL32.fDefineFunction(BOOL,    "AssignProcessToJobObject", HANDLE, HANDLE);
KERNEL32.fDefineFunction(BOOL,    "CloseHandle", HANDLE);
KERNEL32.fDefineFunction(HANDLE,  "CreateToolhelp32Snapshot", DWORD, DWORD);
KERNEL32.fDefineFunction(HANDLE,  "CreateJobObjectA", LPSECURITY_ATTRIBUTES, LPCSTR);
KERNEL32.fDefineFunction(HANDLE,  "CreateJobObjectW", LPSECURITY_ATTRIBUTES, LPCWSTR);
KERNEL32.fDefineFunction(BOOL,    "CreatePipe", PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
KERNEL32.fDefineFunction(BOOL,    "CreateProcessA", LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR , LPSTARTUPINFOA, LPPROCESS_INFORMATION);
KERNEL32.fDefineFunction(BOOL,    "CreateProcessW", LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR , LPSTARTUPINFOW, LPPROCESS_INFORMATION);
KERNEL32.fDefineFunction(HANDLE,  "CreateRemoteThread", HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
KERNEL32.fDefineFunction(BOOL,    "DebugActiveProcess", DWORD);
KERNEL32.fDefineFunction(BOOL,    "DebugActiveProcessStop", DWORD);
KERNEL32.fDefineFunction(BOOL,    "DebugBreakProcess", HANDLE);
KERNEL32.fDefineFunction(BOOL,    "DuplicateHandle", HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
KERNEL32.fDefineFunction(BOOL,    "GenerateConsoleCtrlEvent", DWORD, DWORD);
KERNEL32.fDefineFunction(BOOL,    "GetConsoleMode", HANDLE, PDWORD);
KERNEL32.fDefineFunction(BOOL,    "GetConsoleScreenBufferInfo", HANDLE, PCONSOLE_SCREEN_BUFFER_INFO);
KERNEL32.fDefineFunction(HANDLE,  "GetCurrentProcess");
KERNEL32.fDefineFunction(DWORD,   "GetCurrentProcessId");
KERNEL32.fDefineFunction(BOOL,    "GetExitCodeProcess", HANDLE, LPDWORD);
KERNEL32.fDefineFunction(DWORD,   "GetLastError");
KERNEL32.fDefineFunction(VOID,    "GetNativeSystemInfo", LPSYSTEM_INFO);
KERNEL32.fDefineFunction(HANDLE,  "GetProcessHeap");
KERNEL32.fDefineFunction(DWORD,   "GetShortPathNameA", LPCSTR, LPSTR, DWORD);
KERNEL32.fDefineFunction(DWORD,   "GetShortPathNameW", LPCWSTR, LPWSTR, DWORD);
KERNEL32.fDefineFunction(HANDLE,  "GetStdHandle", DWORD);
KERNEL32.fDefineFunction(VOID,    "GetSystemInfo", LPSYSTEM_INFO);
KERNEL32.fDefineFunction(BOOL,    "GetThreadContext", HANDLE, PCONTEXT);
KERNEL32.fDefineFunction(UINT,    "GetWindowsDirectoryA", LPSTR, UINT);
KERNEL32.fDefineFunction(UINT,    "GetWindowsDirectoryW", LPWSTR, UINT);
KERNEL32.fDefineFunction(LPVOID,  "HeapAlloc", HANDLE, DWORD, SIZE_T);
KERNEL32.fDefineFunction(HANDLE,  "HeapCreate", DWORD, SIZE_T, SIZE_T);
KERNEL32.fDefineFunction(BOOL,    "HeapFree", HANDLE, DWORD, LPVOID);
KERNEL32.fDefineFunction(LPVOID,  "HeapReAlloc", HANDLE, DWORD, LPVOID, SIZE_T);
KERNEL32.fDefineFunction(BOOL,    "InitializeContext", PVOID, DWORD, PPCONTEXT, PWORD);
KERNEL32.fDefineFunction(BOOL,    "IsWow64Process", HANDLE, PBOOL);
KERNEL32.fDefineFunction(BOOL,    "IsProcessInJob", HANDLE, HANDLE, PBOOL);
KERNEL32.fDefineFunction(BOOL,    "K32EnumProcesses", PDWORD, DWORD, PDWORD);
KERNEL32.fDefineFunction(BOOL,    "K32GetProcessMemoryInfo", HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
KERNEL32.fDefineFunction(BOOL,    "Module32First", HANDLE, LPMODULEENTRY32A);
KERNEL32.fDefineFunction(BOOL,    "Module32FirstW", HANDLE, LPMODULEENTRY32W);
KERNEL32.fDefineFunction(BOOL,    "Module32Next", HANDLE, LPMODULEENTRY32A);
KERNEL32.fDefineFunction(BOOL,    "Module32NextW", HANDLE, LPMODULEENTRY32W);
KERNEL32.fDefineFunction(HANDLE,  "OpenThread", DWORD, BOOL, DWORD);
KERNEL32.fDefineFunction(HANDLE,  "OpenProcess", DWORD, BOOL, DWORD);
KERNEL32.fDefineFunction(BOOL,    "OpenProcessToken", HANDLE, DWORD, PHANDLE);
KERNEL32.fDefineFunction(BOOL,    "Process32First", HANDLE, LPPROCESSENTRY32A);
KERNEL32.fDefineFunction(BOOL,    "Process32FirstW", HANDLE, LPPROCESSENTRY32W);
KERNEL32.fDefineFunction(BOOL,    "Process32Next", HANDLE, LPPROCESSENTRY32A);
KERNEL32.fDefineFunction(BOOL,    "Process32NextW", HANDLE, LPPROCESSENTRY32W);
KERNEL32.fDefineFunction(BOOL,    "QueryInformationJobObject", HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD, LPDWORD);
KERNEL32.fDefineFunction(BOOL,    "ReadFile", HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
KERNEL32.fDefineFunction(BOOL,    "ReadProcessMemory", HANDLE, LPCVOID, LPVOID, SIZE_T, PSIZE_T);
KERNEL32.fDefineFunction(DWORD,   "ResumeThread", HANDLE);
KERNEL32.fDefineFunction(BOOL,    "SetHandleInformation", HANDLE, DWORD, DWORD);
KERNEL32.fDefineFunction(BOOL,    "SetInformationJobObject", HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD);
KERNEL32.fDefineFunction(BOOL,    "SetConsoleTextAttribute", HANDLE, WORD);
KERNEL32.fDefineFunction(BOOL,    "SetConsoleTitleA", LPCSTR);
KERNEL32.fDefineFunction(BOOL,    "SetConsoleTitleW", LPCWSTR);
KERNEL32.fDefineFunction(BOOL,    "SetThreadContext", HANDLE, PCONTEXT);
KERNEL32.fDefineFunction(DWORD,   "SuspendThread", HANDLE);
KERNEL32.fDefineFunction(BOOL,    "TerminateProcess", HANDLE, UINT);
KERNEL32.fDefineFunction(BOOL,    "TerminateThread", HANDLE, DWORD);
KERNEL32.fDefineFunction(BOOL,    "Thread32First", HANDLE, LPTHREADENTRY32);
KERNEL32.fDefineFunction(BOOL,    "Thread32Next", HANDLE, LPTHREADENTRY32);
KERNEL32.fDefineFunction(LPVOID,  "VirtualAlloc", LPVOID, SIZE_T, DWORD, DWORD);
KERNEL32.fDefineFunction(LPVOID,  "VirtualAllocEx", HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
KERNEL32.fDefineFunction(BOOL,    "VirtualFree", LPVOID, SIZE_T, DWORD);
KERNEL32.fDefineFunction(BOOL,    "VirtualFreeEx", HANDLE, LPVOID, SIZE_T, DWORD);
KERNEL32.fDefineFunction(BOOL,    "VirtualProtect", LPVOID, SIZE_T, DWORD, PDWORD);
KERNEL32.fDefineFunction(BOOL,    "VirtualProtectEx", HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
KERNEL32.fDefineFunction(SIZE_T,  "VirtualQuery", LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
KERNEL32.fDefineFunction(SIZE_T,  "VirtualQueryEx", HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
KERNEL32.fDefineFunction(DWORD,   "WaitForSingleObject", HANDLE, DWORD);
KERNEL32.fDefineFunction(BOOL,    "WriteConsoleA", HANDLE, LPCSTR, DWORD, LPDWORD, LPVOID);
KERNEL32.fDefineFunction(BOOL,    "WriteConsoleW", HANDLE, LPCWSTR, DWORD, LPDWORD, LPVOID);
KERNEL32.fDefineFunction(BOOL,    "WriteFile", HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
KERNEL32.fDefineFunction(BOOL,    "WriteProcessMemory", HANDLE, LPVOID, LPCVOID, SIZE_T, PSIZE_T);
