from cDLL import cDLL;
from Types import *;

KERNEL32 = cDLL("kernel32.dll");

KERNEL32.fDefineFunction(BOOL,    "GetConsoleMode", HANDLE, PDWORD);
KERNEL32.fDefineFunction(BOOL,    "GetConsoleScreenBufferInfo", HANDLE, PCONSOLE_SCREEN_BUFFER_INFO);
KERNEL32.fDefineFunction(DWORD,   "GetLastError");
KERNEL32.fDefineFunction(DWORD,   "GetShortPathNameA", LPCSTR, LPSTR, DWORD);
KERNEL32.fDefineFunction(DWORD,   "GetShortPathNameW", LPCWSTR, LPWSTR, DWORD);
KERNEL32.fDefineFunction(HANDLE,  "GetStdHandle", DWORD);
KERNEL32.fDefineFunction(BOOL,    "SetConsoleTextAttribute", HANDLE, WORD);
KERNEL32.fDefineFunction(BOOL,    "WriteConsoleA", HANDLE, LPCSTR, DWORD, LPDWORD, LPVOID);
KERNEL32.fDefineFunction(BOOL,    "WriteConsoleW", HANDLE, LPCWSTR, DWORD, LPDWORD, LPVOID);
KERNEL32.fDefineFunction(BOOL,    "WriteFile", HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);