import ctypes;
from ..mDefines import *;
from ..mFunctions import *;
from mPrimitiveTypes import *;

uNamelessStructureOrUnionsCounter = 0;

class STRUCT_or_UNION(object):
  def __init__(oSelf, cBaseType, axFields):
    oSelf.cBaseType = cBaseType;
    oSelf.axFields = axFields;
def STRUCT(*axFields):
  return STRUCT_or_UNION(ctypes.Structure, axFields);
def UNION(*axFields):
  return STRUCT_or_UNION(ctypes.Union, axFields);

cSimpleType = type(ctypes.c_int);
cArrayType = type(ctypes.Array);
cStructureType = type(ctypes.Structure);
cUnionType = type(ctypes.Union);
tcStructureAndUnionType = (cStructureType, cUnionType);
def fDumpStructure(oStructureOrUnion, sName = None):
  sName = sName or oStructureOrUnion.__class__.__name__;
  print (",--- %s " % sName).ljust(80, "-");
  uIndex = 0;
  sLine = "| 0000 ";
  for sChar in oStructureOrUnion.fsToString():
    if uIndex % (oStructureOrUnion._pack_ / 8) == 0:
      sLine += " ";
    sLine += " %02X" % ord(sChar);
    uIndex += 1;
    if uIndex % 0x10 == 0:
      print sLine;
      sLine = "| %04X " % uIndex;
  if uIndex % 0x10 != 0:
    print sLine;
  print "|".ljust(80, "-");
  fDumpStructureOrUnionHelper(0, 0, oStructureOrUnion);
  print "'".ljust(80, "-");

def fDumpStructureOrUnionHelper(uOffset, uDepth, oStructureOrUnion):
  cStructureOrUnionType = type(oStructureOrUnion.__class__);
  for (sFieldName, cFieldType) in oStructureOrUnion._fields_:
    oField = getattr(oStructureOrUnion, sFieldName);
    cField = getattr(oStructureOrUnion.__class__, sFieldName);
    cFieldType = type(cFieldType);
    if cFieldType in tcStructureAndUnionType:
      sFieldType = cFieldType == cStructureType and "struct" or "union";
      print "| %s%04X %02X %-30s %s {" % ("  " * uDepth, uOffset + cField.offset, cField.size, sFieldName, sFieldType);
      fDumpStructureOrUnionHelper(uOffset + cField.offset, uDepth + 1, oField);
      print "| %s%4s %2s %30s }" % ("  " * uDepth, "", "", "");
    elif cFieldType == cArrayType:
      print "| %s%04X %02X %-30s [" % ("  " * uDepth, uOffset + cField.offset, cField.size, sFieldName);
      assert type(oField._type_) == cSimpleType, \
          "Unhandled array element type %s" % repr(oField._type_);
      uElementSize = SIZEOF(oField._type_);
      for uIndex in xrange(oField._length_):
        sIndex = uIndex < 10 and ("%d" % uIndex) or ("%d/0x%X" % (uIndex, uIndex));
        print "| %s  %04X %02X %-30s 0x%X" % \
            ("  " * uDepth, uOffset + cField.offset + uIndex * uElementSize, uElementSize, sIndex, oField[uIndex]);
      print "| %s%4s %2s %30s ]" % ("  " * uDepth, "", "", "");
    else:
      assert cFieldType == cSimpleType, \
          "Unhandled field type %s" % repr(cFieldType);
      cFieldType = type(oField);
      if cFieldType in [str, unicode]:
        uChar = ord(oField);
        sChar = uChar in xrange(0x20, 0x7e) and oField or ".";
        print "| %s%04X %02X %-30s '%s' (0x%X)" % ("  " * uDepth, uOffset + cField.offset, cField.size, sFieldName, sChar, uChar);
      else:
        assert cFieldType in [int, long], \
            "Unhandled simple field type %s" % repr(cFieldType);
        print "| %s%04X %02X %-30s 0x%X" % ("  " * uDepth, uOffset + cField.offset, cField.size, sFieldName, oField);

def fcStructureOrUnion(cBaseType, sName, axFields, uBits = None):
  if uBits == None:
    import platform;
    uBits = {"32bit": 32, "64bit": 64}[platform.architecture()[0]];
  else:
    assert uBits in [32, 64], \
        "Invalid uBits value %s" % repr(uBits);
  global uNamelessStructureOrUnionsCounter;
  if sName is None:
    uNamelessStructureOrUnionsCounter += 1;
    sName = "_nameless_%s_%d_" % (cBaseType.__name__.lower(), uNamelessStructureOrUnionsCounter);
  asAnonymousFieldNames = [];
  atxFields = [];
  for xField in axFields:
    if isinstance(xField, tuple):
      cFieldType, sFieldName = xField;
    else:
      cFieldType = xField;
      sFieldName = "_anonymous_field_%d_" % len(asAnonymousFieldNames);
      asAnonymousFieldNames.append(sFieldName);
    if cFieldType.__class__ is STRUCT_or_UNION:
      cFieldType = fcStructureOrUnion(cFieldType.cBaseType, None, cFieldType.axFields, uBits);
    atxFields.append((sFieldName, cFieldType));
  cStructureOrUnion = type(
    sName,
    (cBaseType,),
    {
      "_anonymous_": asAnonymousFieldNames,
      "foFromString": classmethod(
        lambda cStructureOrUnion, sData, uOffset = 0:
          cStructureOrUnion.from_buffer_copy(sData[uOffset : uOffset + ctypes.sizeof(cStructureOrUnion)])
      ),
      "fsToString": (
        lambda oStructureOrUnion:
          ctypes.string_at(ctypes.addressof(oStructureOrUnion),ctypes.sizeof(oStructureOrUnion))
      ),
      "fuSizeOf": (
        lambda oStructureOrUnion, sFieldName:
          getattr(oStructureOrUnion.__class__, sFieldName).size
      ),
      "fuOffsetOf": (
        lambda oStructureOrUnion, sFieldName:
          getattr(oStructureOrUnion.__class__, sFieldName).offset
      ),
      "fDump": fDumpStructure,
    },
  );
  cStructureOrUnion._pack_ = uBits;
  cStructureOrUnion._fields_ = atxFields;
  return cStructureOrUnion;
def fcStructure(sName, *axFields):
  return fcStructureOrUnion(ctypes.Structure, sName, axFields);
def fcStructure_32(sName, *axFields):
  return fcStructureOrUnion(ctypes.Structure, sName, axFields, 32);
def fcStructure_64(sName, *axFields):
  return fcStructureOrUnion(ctypes.Structure, sName, axFields, 64);
def fcUnion(sName, *axFields):
  return fcStructureOrUnion(ctypes.Union, sName, axFields);

# Defining a structure also defines "P<struct_name>" and "PP<struct_name>" as a
# pointer-to-structure and a pointer-to-pointer-to-structure respectively.
def fDefineHelper(fcDefineType, fPointer, sName, *atxFields):
  cType = fcDefineType(sName, *atxFields);
  globals()[sName] = cType;
  globals()["LP" + sName] = fPointer(cType);
  globals()["P" + sName] = fPointer(cType);
  globals()["PP" + sName] = fPointer(fPointer(cType));
def fDefineStructure(sName, *atxFields):
  fDefineHelper(fcStructure, POINTER, sName, *atxFields);
def fDefineStructure32(sName, *atxFields):
  fDefineHelper(fcStructure_32, POINTER_32, sName, *atxFields);
def fDefineStructure64(sName, *atxFields):
  fDefineHelper(fcStructure_64, POINTER_64, sName, *atxFields);
def fDefineUnion(sName, *atxFields):
  fDefineHelper(fcUnion, POINTER, sName, *atxFields);

################################################################################
# Simple structures that contain only primitives and no other structures are   #
# defined first, strcutures that contain other structures must wait until      #
# those structures are defined and will therefore be defined in a second round #
################################################################################

#UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU
fDefineStructure32("UNICODE_STRING_32",
  (USHORT,      "Length"),
  (USHORT,      "MaximumLength"),
  (PWSTR_32,    "Buffer"),
);
fDefineStructure64("UNICODE_STRING_64",
  (USHORT,      "Length"),
  (USHORT,      "MaximumLength"),
  (PWSTR_64,    "Buffer"),
);

#CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
fDefineStructure("COORD", 
  (SHORT,       "X"),
  (SHORT,       "Y"),
);
fDefineStructure32("CURDIR_32",
  (UNICODE_STRING_32, "DosPath"),
  (HANDLE_32,   "Handle"),
);
fDefineStructure64("CURDIR_64",
  (UNICODE_STRING_64, "DosPath"),
  (HANDLE_64,   "Handle"),
);
#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
fDefineStructure("FILETIME",
  (DWORD,       "dwLowDateTime"),
  (DWORD,       "dwHighDateTime"),
);
#IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
fDefineStructure("IO_COUNTERS",
  (ULONGLONG,   "ReadOperationCount"),
  (ULONGLONG,   "WriteOperationCount"),
  (ULONGLONG,   "OtherOperationCount"),
  (ULONGLONG,   "ReadTransferCount"),
  (ULONGLONG,   "WriteTransferCount"),
  (ULONGLONG,   "OtherTransferCount"),
);
#LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL
fDefineUnion("LARGE_INTEGER",
  STRUCT(
    (DWORD,     "LowPart"),
    (LONG,      "HighPart"),
  ),
  (STRUCT(
    (DWORD,       "LowPart"),
    (LONG,        "HighPart"),
  ),            "u"),
  (LONGLONG,    "QuadPart"),
);
fDefineStructure("LIST_ENTRY",
  (PVOID,       "Flink"), # Should be PLIST_ENTRY but circular references are not implemented.
  (PVOID,       "Blink"), # Should be PLIST_ENTRY but circular references are not implemented.
);
fDefineStructure32("LIST_ENTRY_32",
  (PVOID_32,    "Flink"), # Should be PLIST_ENTRY_32 but circular references are not implemented.
  (PVOID_32,    "Blink"), # Should be PLIST_ENTRY_32 but circular references are not implemented.
);
fDefineStructure64("LIST_ENTRY_64",
  (PVOID_64,    "Flink"), # Should be PLIST_ENTRY_64 but circular references are not implemented.
  (PVOID_64,    "Blink"), # Should be PLIST_ENTRY_64 but circular references are not implemented.
);
#MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
fDefineStructure("MEMORY_BASIC_INFORMATION", 
  (PVOID,       "BaseAddress"),
  (PVOID,       "AllocationBase"),
  (DWORD,       "AllocationProtect"),
  (SIZE_T,      "RegionSize"),
  (DWORD,       "State"),
  (DWORD,       "Protect"),
  (DWORD,       "Type"),
);
fDefineStructure("MEMORY_BASIC_INFORMATION32", 
  (DWORD,       "BaseAddress"),
  (DWORD,       "AllocationBase"),
  (DWORD,       "AllocationProtect"),
  (DWORD,       "RegionSize"),
  (DWORD,       "State"),
  (DWORD,       "Protect"),
  (DWORD,       "Type"),
);
fDefineStructure("MEMORY_BASIC_INFORMATION64", 
  (ULONGLONG,   "BaseAddress"),
  (ULONGLONG,   "AllocationBase"),
  (DWORD,       "AllocationProtect"),
  (DWORD,       "__alignment1"),
  (ULONGLONG,   "RegionSize"),
  (DWORD,       "State"),
  (DWORD,       "Protect"),
  (DWORD,       "Type"),
  (DWORD,       "__alignment2"),
);

fDefineStructure("MODULEENTRY32A",
  (DWORD,       "dwSize"),
  (DWORD,       "th32ModuleID"),
  (DWORD,       "th32ProcessID"),
  (DWORD,       "GlblcntUsage"),
  (DWORD,       "ProccntUsage"),
  (PBYTE,       "modBaseAddr"),
  (DWORD,       "modBaseSize"),
  (HMODULE,     "hModule"),
  (CHAR * (MAX_MODULE_NAME32 + 1), "szModule"),
  (CHAR * MAX_PATH, "szExePath"),
);
fDefineStructure("MODULEENTRY32W",
  (DWORD,       "dwSize"),
  (DWORD,       "th32ModuleID"),
  (DWORD,       "th32ProcessID"),
  (DWORD,       "GlblcntUsage"),
  (DWORD,       "ProccntUsage"),
  (PBYTE,       "modBaseAddr"),
  (DWORD,       "modBaseSize"),
  (HMODULE,     "hModule"),
  (WCHAR * (MAX_MODULE_NAME32 + 1), "szModule"),
  (WCHAR * MAX_PATH, "szExePath"),
);
#OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO
fDefineStructure("OVERLAPPED",
  (PULONG,      "Internal"),
  (PULONG,      "InternalHigh"),
  UNION(
    STRUCT(
      (DWORD,   "Offset"),
      (DWORD,   "OffsetHigh"),
    ),
    (PVOID,     "Pointer"),
  ),
  (HANDLE,      "hEvent"),
);
#PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
fDefineStructure("POINT",
  (LONG,        "x"),
  (LONG,        "y"),
);
fDefineStructure32("PEB_LDR_DATA_32", 
  (BYTE * 8,    "Reserved1"),
  (PVOID_32 * 3, "Reserved2"),
  (LIST_ENTRY_32, "InMemoryOrderModuleList"),
);
fDefineStructure64("PEB_LDR_DATA_64", 
  (BYTE * 8,    "Reserved1"),
  (PVOID_64 * 3, "Reserved2"),
  (LIST_ENTRY_64, "InMemoryOrderModuleList"),
);
fDefineStructure("PROCESS_BASIC_INFORMATION",
  (PVOID,       "Reserved1"),
  (PVOID,       "PebBaseAddress"), # Should be PPEB, but PEB is defined differently on x86 than on x64, so not sure which this points to.
  (PVOID * 2,   "Reserved2"),
  (ULONG_PTR,   "UniqueProcessId"),
  (PVOID,       "Reserved3"),
);
fDefineStructure("PROCESS_INFORMATION",
  (HANDLE,      "hProcess"),
  (HANDLE,      "hThread"),
  (DWORD,       "dwProcessId"),
  (DWORD,       "dwThreadId"),
);
fDefineStructure("PROCESS_MEMORY_COUNTERS",
  (DWORD,       "cb"),
  (DWORD,       "PageFaultCount"),
  (SIZE_T,      "PeakWorkingSetSize"),
  (SIZE_T,      "WorkingSetSize"),
  (SIZE_T,      "QuotaPeakPagedPoolUsage"),
  (SIZE_T,      "QuotaPagedPoolUsage"),
  (SIZE_T,      "QuotaPeakNonPagedPoolUsage"),
  (SIZE_T,      "QuotaNonPagedPoolUsage"),
  (SIZE_T,      "PagefileUsage"),
  (SIZE_T,      "PeakPagefileUsage"),
);
fDefineStructure("PROCESS_MEMORY_COUNTERS_EX",
  (DWORD,       "cb"),
  (DWORD,       "PageFaultCount"),
  (SIZE_T,      "PeakWorkingSetSize"),
  (SIZE_T,      "WorkingSetSize"),
  (SIZE_T,      "QuotaPeakPagedPoolUsage"),
  (SIZE_T,      "QuotaPagedPoolUsage"),
  (SIZE_T,      "QuotaPeakNonPagedPoolUsage"),
  (SIZE_T,      "QuotaNonPagedPoolUsage"),
  (SIZE_T,      "PagefileUsage"),
  (SIZE_T,      "PeakPagefileUsage"),
  (SIZE_T,      "PrivateUsage"),
);
fDefineStructure("PROCESSENTRY32A",
  (DWORD,       "dwSize"),
  (DWORD,       "cntUsage"),
  (DWORD,       "th32ProcessID"),
  (PULONG,      "th32DefaultHeapID"),
  (DWORD,       "th32ModuleID"),
  (DWORD,       "cntThreads"),
  (DWORD,       "th32ParentProcessID"),
  (LONG,        "pcPriClassBase"),
  (DWORD,       "dwFlags"),
  (CHAR * MAX_PATH, "szExeFile"),
);
fDefineStructure("PROCESSENTRY32W",
  (DWORD,       "dwSize"),
  (DWORD,       "cntUsage"),
  (DWORD,       "th32ProcessID"),
  (PULONG,      "th32DefaultHeapID"),
  (DWORD,       "th32ModuleID"),
  (DWORD,       "cntThreads"),
  (DWORD,       "th32ParentProcessID"),
  (LONG,        "pcPriClassBase"),
  (DWORD,       "dwFlags"),
  (WCHAR * MAX_PATH, "szExeFile"),
);
#RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
fDefineStructure("RECT",
  (LONG,        "left"),
  (LONG,        "top"),
  (LONG,        "right"),
  (LONG,        "bottom"),
);
#SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
fDefineStructure("SECURITY_ATTRIBUTES",
  (DWORD,       "nLength"),
  (LPVOID,      "lpSecurityDescriptor"),
  (BOOL,        "bInheritHandle"),
);
fDefineStructure("SID");
fDefineStructure("SIZE",
  (LONG,        "cx"),
  (LONG,        "cy"),
);
fDefineStructure("SMALL_RECT",
  (SHORT,       "Left"),
  (SHORT,       "Top"),
  (SHORT,       "Right"),
  (SHORT,       "Bottom"),
);
fDefineStructure("STARTUPINFOA",
  (DWORD,       "cb"),
  (LPSTR,       "lpReserved"),
  (LPSTR,       "lpDesktop"),
  (LPSTR,       "lpTitle"),
  (DWORD,       "dwX"),
  (DWORD,       "dwY"),
  (DWORD,       "dwXSize"),
  (DWORD,       "dwYSize"),
  (DWORD,       "dwXCountChars"),
  (DWORD,       "dwYCountChars"),
  (DWORD,       "dwFillAttribute"),
  (DWORD,       "dwFlags"),
  (WORD,        "wShowWindow"),
  (WORD,        "cbReserved2"),
  (LPBYTE,      "lpReserved2"),
  (HANDLE,      "hStdInput"),
  (HANDLE,      "hStdOutput"),
  (HANDLE,      "hStdError"),
);
fDefineStructure("STARTUPINFOW",
  (DWORD,       "cb"),
  (LPWSTR,      "lpReserved"),
  (LPWSTR,      "lpDesktop"),
  (LPWSTR,      "lpTitle"),
  (DWORD,       "dwX"),
  (DWORD,       "dwY"),
  (DWORD,       "dwXSize"),
  (DWORD,       "dwYSize"),
  (DWORD,       "dwXCountChars"),
  (DWORD,       "dwYCountChars"),
  (DWORD,       "dwFillAttribute"),
  (DWORD,       "dwFlags"),
  (WORD,        "wShowWindow"),
  (WORD,        "cbReserved2"),
  (LPBYTE,      "lpReserved2"),
  (HANDLE,      "hStdInput"),
  (HANDLE,      "hStdOutput"),
  (HANDLE,      "hStdError"),
);
fDefineStructure("SYSTEM_INFO",
  UNION (
    (DWORD,     "dwOemId"),
    STRUCT(
      (WORD,    "wProcessorArchitecture"),
      (WORD,    "wReserved"),
    ),
  ),
  (DWORD,       "dwPageSize"),
  (LPVOID,      "lpMinimumApplicationAddress"),
  (LPVOID,      "lpMaximumApplicationAddress"),
  (DWORD_PTR,   "dwActiveProcessorMask"),
  (DWORD,       "dwNumberOfProcessors"),
  (DWORD,       "dwProcessorType"),
  (DWORD,       "dwAllocationGranularity"),
  (WORD,        "wProcessorLevel"),
  (WORD,        "wProcessorRevision"),
);

################################################################################
# Structures that contain or refer to other structures                         #
################################################################################

#CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
fDefineStructure("CONSOLE_SCREEN_BUFFER_INFO", 
  (COORD,       "dwSize"),
  (COORD,       "dwCursorPosition"),
  (WORD,        "wAttributes"),
  (SMALL_RECT,  "srWindow"),
  (COORD,       "dwMaximumWindowSize"),
);
#JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ
fDefineStructure("JOBOBJECT_BASIC_LIMIT_INFORMATION",
  (LARGE_INTEGER, "PerProcessUserTimeLimit"),
  (LARGE_INTEGER, "PerJobUserTimeLimit"),
  (DWORD,       "LimitFlags"),
  (SIZE_T,      "MinimumWorkingSetSize"),
  (SIZE_T,      "MaximumWorkingSetSize"),
  (DWORD,       "ActiveProcessLimit"),
  (ULONG_PTR,   "Affinity"),
  (DWORD,       "PriorityClass"),
  (DWORD,       "SchedulingClass"),
);
fDefineStructure("JOBOBJECT_EXTENDED_LIMIT_INFORMATION",
  (JOBOBJECT_BASIC_LIMIT_INFORMATION, "BasicLimitInformation"),
  (IO_COUNTERS, "IoInfo"),
  (SIZE_T,      "ProcessMemoryLimit"),
  (SIZE_T,      "JobMemoryLimit"),
  (SIZE_T,      "PeakProcessMemoryUsed"),
  (SIZE_T,      "PeakJobMemoryUsed"),
);
#RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
fDefineStructure32("RTL_USER_PROCESS_PARAMETERS_32",
  (UINT32,      "MaximumLength"),
  (UINT32,      "Length"),
  (UINT32,      "Flags"),
  (UINT32,      "DebugFlags"),
  (HANDLE_32,   "ConsoleHandle"),
  (UINT32,      "ConsoleFlags"),
  (HANDLE_32,   "StandardInput"),
  (HANDLE_32,   "StandardOutput"),
  (HANDLE_32,   "StandardError"),
  (CURDIR_32,   "CurrentDirectory"),
  (UNICODE_STRING_32, "DllPath"),
  (UNICODE_STRING_32, "ImagePathName"),
  (UNICODE_STRING_32, "CommandLine"),
  (PVOID_32,    "Environment"),
  # There's more, but I don't need it
);
fDefineStructure64("RTL_USER_PROCESS_PARAMETERS_64",
  (UINT32,      "MaximumLength"),
  (UINT32,      "Length"),
  (UINT32,      "Flags"),
  (UINT32,      "DebugFlags"),
  (HANDLE_64,   "ConsoleHandle"),
  (UINT32,      "ConsoleFlags"),
  (HANDLE_64,   "StandardInput"),
  (HANDLE_64,   "StandardOutput"),
  (HANDLE_64,   "StandardError"),
  (CURDIR_64,   "CurrentDirectory"),
  (UNICODE_STRING_64, "DllPath"),
  (UNICODE_STRING_64, "ImagePathName"),
  (UNICODE_STRING_64, "CommandLine"),
);
#SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
fDefineStructure("SID_AND_ATTRIBUTES",
  (PSID,        "Sid"),
  (DWORD,       "Attributes"),
);
#TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT
fDefineStructure("TOKEN_MANDATORY_LABEL",
  (SID_AND_ATTRIBUTES, "Label"),
);

################################################################################
# Structures that contain or refer to other structures which in turn refer to  #
# other structures as well                                                     #
################################################################################

#PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
fDefineStructure32("PEB_32",
  (BYTE,        "InheritedAddressSpace"),
  (BYTE,        "ReadImageFileExecOptions"),
  (BYTE,        "BeingDebugged"),
  (BYTE,        "BitField"),
  (PVOID_32,    "Mutant"),
  (PVOID_32,    "ImageBaseAddress"),
  (PPEB_LDR_DATA_32, "Ldr"),
  (PRTL_USER_PROCESS_PARAMETERS_32, "ProcessParameters"),
  # There's lots more, but since I do not need it, I did not define it.
);
fDefineStructure64("PEB_64",
  (BYTE,        "InheritedAddressSpace"),
  (BYTE,        "ReadImageFileExecOptions"),
  (BYTE,        "BeingDebugged"),
  (BYTE,        "BitField"),
  (BYTE * 4,    "Padding0"),
  (PVOID_64,    "Mutant"),
  (PVOID_64,    "ImageBaseAddress"),
  (PPEB_LDR_DATA_64, "Ldr"),
  (PRTL_USER_PROCESS_PARAMETERS_64, "ProcessParameters"),
  # There's lots more, but since I do not need it, I did not define it.
);
