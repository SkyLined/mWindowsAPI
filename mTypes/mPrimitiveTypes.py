import ctypes;
from ..mFunctions import *;

# We want a list of the names of the primitive types defined below so we can
# automatically generate pointer-to-types for them. We will do this by getting
# a list of the names of all globals now and after they have been defined, so
# we can determine what globals were added.
asGlobalsBeforeTypeDefinitions = globals().keys() + ["asGlobalsBeforeTypeDefinitions"];

################################################################################
# Non-pointer primitive types
################################################################################

#BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BOOL = ctypes.c_long;
BOOLEAN = ctypes.c_byte;
BYTE = ctypes.c_ubyte;
#CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
CHAR = ctypes.c_char;
#DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
DOUBLE = ctypes.c_double;
DWORD = ctypes.c_ulong;
DWORD_PTR = SIZEOF(ctypes.c_void_p) == 4 and ctypes.c_ulong or ctypes.c_ulonglong;
#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
FLOAT = ctypes.c_float;
#HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
HACCEL = ctypes.c_void_p;
HANDLE = ctypes.c_void_p;
HBITMAP = ctypes.c_void_p;
HBRUSH = ctypes.c_void_p;
HCOLORSPACE = ctypes.c_void_p;
HDC = ctypes.c_void_p;
HDESK = ctypes.c_void_p;
HDWP = ctypes.c_void_p;
HENHMETAFILE = ctypes.c_void_p;
HFONT = ctypes.c_void_p;
HGDIOBJ = ctypes.c_void_p;
HGLOBAL = ctypes.c_void_p;
HHOOK = ctypes.c_void_p;
HICON = ctypes.c_void_p;
HINSTANCE = ctypes.c_void_p;
HKEY = ctypes.c_void_p;
HKL = ctypes.c_void_p;
HLOCAL = ctypes.c_void_p;
HMENU = ctypes.c_void_p;
HMETAFILE = ctypes.c_void_p;
HMODULE = ctypes.c_void_p;
HMONITOR = ctypes.c_void_p;
HPALETTE = ctypes.c_void_p;
HPEN = ctypes.c_void_p;
HRESULT = ctypes.c_long;
HRGN = ctypes.c_void_p;
HRSRC = ctypes.c_void_p;
HSTR = ctypes.c_void_p;
HTASK = ctypes.c_void_p;
HWINSTA = ctypes.c_void_p;
HWND = ctypes.c_void_p;
#IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
INT = ctypes.c_int;
INT8 = ctypes.c_byte;
INT16 = ctypes.c_short;
INT32 = ctypes.c_int;
INT64 = ctypes.c_longlong;
#JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ
JOBOBJECTINFOCLASS = ctypes.c_size_t; # defined as an enum, so I'm guessing its size depends on the architecture.
#LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL
LONG = ctypes.c_long;
LONGLONG = ctypes.c_longlong;
LPASTR = ctypes.c_char_p;
LPCOLESTR = ctypes.c_wchar_p;
LPCSTR = ctypes.c_char_p;
LPCVOID = ctypes.c_void_p;
LPCWSTR = ctypes.c_wchar_p;
LPOLESTR = ctypes.c_wchar_p;
LPSTR = ctypes.c_char_p;
LPTHREAD_START_ROUTINE = ctypes.c_void_p;
LPVOID = ctypes.c_void_p;
LPWSTR = ctypes.c_wchar_p;
#OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO
OLESTR = ctypes.c_wchar_p;
#PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PROCESSINFOCLASS = ctypes.c_size_t; # defined as an enum, so I'm guessing its size depends on the architecture.
PVOID = ctypes.c_void_p;
#SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
SHORT = ctypes.c_short;
SIZE_T = ctypes.c_size_t;
#TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT
TOKEN_INFORMATION_CLASS = ctypes.c_ulong;
#UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU
UCHAR = ctypes.c_ubyte;
UINT = ctypes.c_uint;
UINT8 = ctypes.c_ubyte;
UINT16 = ctypes.c_ushort;
UINT32 = ctypes.c_uint;
UINT64 = ctypes.c_ulonglong;
ULONG = ctypes.c_ulong;
ULONGLONG = ctypes.c_ulonglong;
ULONG_PTR = SIZEOF(ctypes.c_void_p) == 4 and ctypes.c_ulong or ctypes.c_ulonglong;
USHORT = ctypes.c_ushort;
#VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV
VOID = None
#WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WCHAR = ctypes.c_wchar;
WORD = ctypes.c_ushort;
#QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QWORD = ctypes.c_ulonglong;

################################################################################
# Automatically define "P<type_name>" and "LP<type_name>" as pointer-to-type and
# "PP<type_name>" pointer-to-pointer-to-type. Some of these may make no sense,
# but they do not cause any problems and doing this automatically is a lot
# cleaner than manually adding them.
################################################################################
for sTypeName in globals().keys():
  if sTypeName not in asGlobalsBeforeTypeDefinitions:
    cType = globals()[sTypeName];
    globals()["P" + sTypeName] = POINTER(cType);
    globals()["LP" + sTypeName] = POINTER(cType);
    globals()["PP" + sTypeName] = POINTER(POINTER(cType));

    globals()["P" + sTypeName + "_32"] = POINTER_32(cType);
    globals()["LP" + sTypeName + "_32"] = POINTER_32(cType);
    globals()["PP" + sTypeName + "_32"] = POINTER_32(POINTER_32(cType));
    
    globals()["P" + sTypeName + "_64"] = POINTER_64(cType);
    globals()["LP" + sTypeName + "_64"] = POINTER_64(cType);
    globals()["PP" + sTypeName + "_64"] = POINTER_64(POINTER_64(cType));

# 32/64 bit values
SIZE_T_32 = ctypes.c_ulong;
SIZE_T_64 = ctypes.c_ulonglong;
HANDLE_32 = ctypes.c_ulong;
HANDLE_64 = ctypes.c_ulonglong;
PSIZE_T_32 = POINTER_32(SIZE_T_32);
PSIZE_T_64 = POINTER_64(SIZE_T_64);
PPSIZE_T_32 = POINTER_32(POINTER_32(SIZE_T_32));
PPSIZE_T_64 = POINTER_64(POINTER_64(SIZE_T_64));
PVOID_32 = POINTER_32();
PVOID_64 = POINTER_64();
PPVOID_32 = POINTER_32(POINTER_32());
PPVOID_64 = POINTER_64(POINTER_64());
PWSTR_32 = POINTER_32(ctypes.c_wchar);
PPWSTR_32 = POINTER_32(POINTER_32(ctypes.c_wchar));
PWSTR_64 = POINTER_64(ctypes.c_wchar);
PPWSTR_64 = POINTER_64(POINTER_64(ctypes.c_wchar));
