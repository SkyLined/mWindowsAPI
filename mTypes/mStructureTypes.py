import ctypes;
from ..mDefines import *;
from ..mFunctions import *;
from mPrimitiveTypes import *;
from ..fsGetPythonISA import fsGetPythonISA;

uNamelessStructureOrUnionsCounter = 0;

__all__ = asExportedNames = [
  "fcStructure",
  "fcStructure_32",
  "fcStructure_64",
  "fcUnion",
  "STRUCT",
  "UNION",
];

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
def fasDumpStructure(oStructureOrUnion, sName = None):
  sName = sName or oStructureOrUnion.__class__.__name__;
  auBytes = oStructureOrUnion.fauToBytes();
  return [
    "Name: %s" % sName,
    "Alignment: %d bytes" % oStructureOrUnion.__class__.uAlignmentBytes,
    len(auBytes) < 10 \
        and "Size: %d bytes" % len(auBytes) \
        or "Size: %d/0x%X bytes" % (len(auBytes), len(auBytes)),
    "Offset Size  Data                     Name                           Value",
  ] + fasDumpStructureOrUnionHelper(0, 0, oStructureOrUnion, auBytes);

def fasDumpStructureOrUnionHelper(uOffset, uDepth, oStructureOrUnion, auBytes):
  cStructureOrUnionType = type(oStructureOrUnion.__class__);
  asDumpData = [];
  for (sFieldName, cFieldType) in oStructureOrUnion._fields_:
    oField = getattr(oStructureOrUnion, sFieldName);
    cField = getattr(oStructureOrUnion.__class__, sFieldName);
    cFieldType = type(cFieldType);
    uFieldOffset = uOffset + cField.offset;
    sHeaderFormat = "  %04X %04X %%-24s %s%%-30s %%s" % (uFieldOffset, cField.size, "  " * uDepth);
    sFooterFormat = "  %4s %4s %24s %s%30s %%s" % ("", "", "", "  " * uDepth, "");
    if cFieldType in tcStructureAndUnionType:
      sFieldType = cFieldType == cStructureType and "struct" or "union";
      asDumpData.extend([
        sHeaderFormat % ("", sFieldName, sFieldType + " {"),
      ] + fasDumpStructureOrUnionHelper(uOffset + cField.offset, uDepth + 1, oField, auBytes) + [
        sFooterFormat % "}",
      ]);
    elif cFieldType == cArrayType:
      asDumpData.append(sHeaderFormat % ("", sFieldName, "["));
      assert type(oField._type_) in [int, long], \
          "Unhandled array element type %s for field %s" % (repr(oField._type_), sFieldName);
      uElementSize = SIZEOF(oField._type_);
      for uElementIndex in xrange(oField._length_):
        sElementIndex = uElementIndex < 10 and ("[%d]" % uElementIndex) or ("[%d/0x%X]" % (uElementIndex, uElementIndex));
        uElementOffset = uOffset + cField.offset + uElementIndex * uElementSize
        sElementBytes = " ".join(["%02X" % auBytes[uByteOffset] for uByteOffset in xrange(uElementOffset, uElementOffset + uElementSize)]);
        sElementValue = "%s0x%%0%dX" % (oField[uElementIndex] < 0 and "-" or "", uElementSize * 2) % abs(oField[uElementIndex]);
        asDumpData.append("  %04X %04X %-24s %s  %-30s %s" % \
            (uElementOffset, uElementSize, sElementBytes, "  " * uDepth, sElementIndex, sElementValue));
      asDumpData.append(sFooterFormat % "]");
    else:
      sFieldBytes = " ".join(["%02X" % auBytes[uByteOffset] for uByteOffset in xrange(uFieldOffset, uFieldOffset + cField.size)]);
      assert cFieldType == cSimpleType, \
          "Unhandled field type %s for field %s" % (repr(cFieldType), sFieldName);
      cFieldType = type(oField);
      if cFieldType in [str, unicode]:
        uByte = ord(oField);
        sByte = uByte in xrange(0x20, 0x7e) and oField or ".";
        sValue = "'%s' (0x%X)" % (sByte, uByte);
      else:
        assert cFieldType in [int, long], \
            "Unhandled simple field type %s for field %s" % (repr(cFieldType), sFieldName);
        sValue = "%s0x%%0%dX" % (oField < 0 and "-" or "", cField.size * 2) % abs(oField);
      asDumpData.append(sHeaderFormat % (sFieldBytes, sFieldName, sValue));
  return asDumpData;

def fcStructureOrUnion(cBaseType, sName, axFields, uAlignmentBytes = None):
  if uAlignmentBytes == None:
    uAlignmentBytes = {"x86": 4, "x64": 8}[fsGetPythonISA()];
  else:
    assert uAlignmentBytes in [1, 2, 4, 8], \
        "Invalid uAlignmentBytes value %s" % repr(uAlignmentBytes);
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
      cFieldType = fcStructureOrUnion(cFieldType.cBaseType, None, cFieldType.axFields, uAlignmentBytes);
    atxFields.append((sFieldName, cFieldType));
  cStructureOrUnion = type(
    sName,
    (cBaseType,),
    {
      "_anonymous_": asAnonymousFieldNames,
      "foFromBytesString": classmethod(
        lambda cStructureOrUnion, sData, uOffset = 0:
          cStructureOrUnion.from_buffer_copy(sData[uOffset : uOffset + ctypes.sizeof(cStructureOrUnion)])
      ),
      "fsToBytesString": (
        lambda oStructureOrUnion:
          ctypes.string_at(ctypes.addressof(oStructureOrUnion),ctypes.sizeof(oStructureOrUnion))
      ),
      "fauToBytes": (
        lambda oStructureOrUnion:
          [ord(sByte) for sByte in oStructureOrUnion.fsToBytesString()]
      ),
      "fuSizeOf": (
        lambda oStructureOrUnion, sFieldName:
          getattr(oStructureOrUnion.__class__, sFieldName).size
      ),
      "fuOffsetOf": (
        lambda oStructureOrUnion, sFieldName:
          getattr(oStructureOrUnion.__class__, sFieldName).offset
      ),
      "fasDump": fasDumpStructure,
    },
  );
  cStructureOrUnion.uAlignmentBytes = uAlignmentBytes;
  cStructureOrUnion._pack_ = uAlignmentBytes;
  cStructureOrUnion._fields_ = atxFields;
  return cStructureOrUnion;
def fcStructure(sName, *axFields, **dxOption_by_sName):
  return fcStructureOrUnion(ctypes.Structure, sName, axFields, **dxOption_by_sName);
def fcStructure_32(sName, *axFields):
  return fcStructureOrUnion(ctypes.Structure, sName, axFields, uAlignmentBytes = 4);
def fcStructure_64(sName, *axFields):
  return fcStructureOrUnion(ctypes.Structure, sName, axFields, uAlignmentBytes = 8);
def fcUnion(sName, *axFields, **dxOption_by_sName):
  return fcStructureOrUnion(ctypes.Union, sName, axFields, **dxOption_by_sName);

# Defining a structure also defines "P<struct_name>" and "PP<struct_name>" as a
# pointer-to-structure and a pointer-to-pointer-to-structure respectively.
def fExportStructureOrUnion(fcDefineType, fPointer, sName, *atxFields):
  cType = fcDefineType(sName, *atxFields);
  globals()[sName] = cType;
  globals()["LP" + sName] = fPointer(cType);
  globals()["P" + sName] = fPointer(cType);
  globals()["PP" + sName] = fPointer(fPointer(cType));
  asExportedNames.extend([sName, "LP" + sName, "P" + sName, "PP" + sName]);
def fExportStructure(sName, *atxFields):
  fExportStructureOrUnion(fcStructure, POINTER, sName, *atxFields);
def fExportStructure32(sName, *atxFields):
  fExportStructureOrUnion(fcStructure_32, POINTER_32, sName, *atxFields);
def fExportStructure64(sName, *atxFields):
  fExportStructureOrUnion(fcStructure_64, POINTER_64, sName, *atxFields);
def fDefineUnion(sName, *atxFields):
  fExportStructureOrUnion(fcUnion, POINTER, sName, *atxFields);

################################################################################
# Simple structures that contain only primitives and no other structures are   #
# defined first, strcutures that contain other structures must wait until      #
# those structures are defined and will therefore be defined in a second round #
################################################################################

#UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU
fExportStructure32("UNICODE_STRING_32",
  (USHORT,      "Length"),
  (USHORT,      "MaximumLength"),
  (PWSTR_32,    "Buffer"),
);
fExportStructure64("UNICODE_STRING_64",
  (USHORT,      "Length"),
  (USHORT,      "MaximumLength"),
  (PWSTR_64,    "Buffer"),
);

#CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
fExportStructure("COORD", 
  (SHORT,       "X"),
  (SHORT,       "Y"),
);
fExportStructure32("CURDIR_32",
  (UNICODE_STRING_32, "DosPath"),
  (HANDLE_32,   "Handle"),
);
fExportStructure64("CURDIR_64",
  (UNICODE_STRING_64, "DosPath"),
  (HANDLE_64,   "Handle"),
);
#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
fExportStructure("FILETIME",
  (DWORD,       "dwLowDateTime"),
  (DWORD,       "dwHighDateTime"),
);
#IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
fExportStructure("IMAGE_DATA_DIRECTORY",
  (DWORD,       "VirtualAddress"),
  (DWORD,       "Size"),
);
fExportStructure("IMAGE_DOS_HEADER",
  (BYTE * 2,    "e_magic_byte"),  # Magic number
  (UINT16,      "e_cblp"),        # Bytes on last page of file
  (UINT16,      "e_cp"),          # Pages in file
  (UINT16,      "e_crlc"),        # Relocations
  (UINT16,      "e_cparhdr"),     # Size of header in paragraphs
  (UINT16,      "e_minalloc"),    # Minimum extra paragraphs needed
  (UINT16,      "e_maxalloc"),    # Maximum extra paragraphs needed
  (UINT16,      "e_ss"),          # Initial (relative) SS value
  (UINT16,      "e_sp"),          # Initial SP value
  (UINT16,      "e_csum"),        # Checksum
  (UINT16,      "e_ip"),          # Initial IP value
  (UINT16,      "e_cs"),          # Initial (relative) CS value
  (UINT16,      "e_lfarlc"),      # File address of relocation table
  (UINT16,      "e_ovno"),        # Overlay number
  (UINT16 * 4,  "e_res1"),        # Reserved words
  (UINT16,      "e_oemid"),       # OEM identifier (for e_oeminfo)
  (UINT16,      "e_oeminfo"),     # OEM information; e_oemid specific
  (UINT16 * 10, "e_res2"),        # Reserved words
  (INT32,       "e_lfanew"),      # File address of new exe header
);
fExportStructure("IMAGE_FILE_HEADER",
  (WORD,        "Machine"),
  (WORD,        "NumberOfSections"),
  (DWORD,       "TimeDateStamp"),
  (DWORD,       "PointerToSymbolTable"),
  (DWORD,       "NumberOfSymbols"),
  (WORD,        "SizeOfOptionalHeader"),
  (WORD,        "Characteristics"),
);
fExportStructure("IMAGE_OPTIONAL_HEADER32",
  (WORD,        "Magic"),
  (BYTE,        "MajorLinkerVersion"),
  (BYTE,        "MinorLinkerVersion"),
  (DWORD,       "SizeOfCode"),
  (DWORD,       "SizeOfInitializedData"),
  (DWORD,       "SizeOfUninitializedData"),
  (DWORD,       "AddressOfEntryPoint"),
  (DWORD,       "BaseOfCode"),
  (DWORD,       "BaseOfData"),
  (DWORD,       "ImageBase"),
  (DWORD,       "SectionAlignment"),
  (DWORD,       "FileAlignment"),
  (WORD,        "MajorOperatingSystemVersion"),
  (WORD,        "MinorOperatingSystemVersion"),
  (WORD,        "MajorImageVersion"),
  (WORD,        "MinorImageVersion"),
  (WORD,        "MajorSubsystemVersion"),
  (WORD,        "MinorSubsystemVersion"),
  (DWORD,       "Win32VersionValue"),
  (DWORD,       "SizeOfImage"),
  (DWORD,       "SizeOfHeaders"),
  (DWORD,       "CheckSum"),
  (WORD,        "Subsystem"),
  (WORD,        "DllCharacteristics"),
  (DWORD,       "SizeOfStackReserve"),
  (DWORD,       "SizeOfStackCommit"),
  (DWORD,       "SizeOfHeapReserve"),
  (DWORD,       "SizeOfHeapCommit"),
  (DWORD,       "LoaderFlags"),
  (DWORD,       "NumberOfRvaAndSizes"),
  (IMAGE_DATA_DIRECTORY, "ExportTable"),
  (IMAGE_DATA_DIRECTORY, "ImportTable"),
  (IMAGE_DATA_DIRECTORY, "ResourceTable"),
  (IMAGE_DATA_DIRECTORY, "ExceptionTable"),
  (IMAGE_DATA_DIRECTORY, "CertificateTable"),
  (IMAGE_DATA_DIRECTORY, "BaseRelocationTable"),
  (IMAGE_DATA_DIRECTORY, "DebugInformation"),
  (IMAGE_DATA_DIRECTORY, "ArchitectureSpecificData"),
  (IMAGE_DATA_DIRECTORY, "GlobalPointerRegister"),
  (IMAGE_DATA_DIRECTORY, "TLSTable"),
  (IMAGE_DATA_DIRECTORY, "LoadConfigurationTable"),
  (IMAGE_DATA_DIRECTORY, "BoundImportTable"),
  (IMAGE_DATA_DIRECTORY, "ImportAddressTable"),
  (IMAGE_DATA_DIRECTORY, "DelayImportDescriptor"),
  (IMAGE_DATA_DIRECTORY, "CLRHeader"),
  (IMAGE_DATA_DIRECTORY, "ReservedDataDirectory"),
);
fExportStructure("IMAGE_OPTIONAL_HEADER64",
  (WORD,        "Magic"),
  (BYTE,        "MajorLinkerVersion"),
  (BYTE,        "MinorLinkerVersion"),
  (DWORD,       "SizeOfCode"),
  (DWORD,       "SizeOfInitializedData"),
  (DWORD,       "SizeOfUninitializedData"),
  (DWORD,       "AddressOfEntryPoint"),
  (DWORD,       "BaseOfCode"),
  (DWORD,       "BaseOfData"),
  (ULONGLONG,   "ImageBase"),
  (DWORD,       "SectionAlignment"),
  (DWORD,       "FileAlignment"),
  (WORD,        "MajorOperatingSystemVersion"),
  (WORD,        "MinorOperatingSystemVersion"),
  (WORD,        "MajorImageVersion"),
  (WORD,        "MinorImageVersion"),
  (WORD,        "MajorSubsystemVersion"),
  (WORD,        "MinorSubsystemVersion"),
  (DWORD,       "Win32VersionValue"),
  (DWORD,       "SizeOfImage"),
  (DWORD,       "SizeOfHeaders"),
  (DWORD,       "CheckSum"),
  (WORD,        "Subsystem"),
  (WORD,        "DllCharacteristics"),
  (ULONGLONG,   "SizeOfStackReserve"),
  (ULONGLONG,   "SizeOfStackCommit"),
  (ULONGLONG,   "SizeOfHeapReserve"),
  (ULONGLONG,   "SizeOfHeapCommit"),
  (DWORD,       "LoaderFlags"),
  (DWORD,       "NumberOfRvaAndSizes"),
  (IMAGE_DATA_DIRECTORY, "DataDirectory"),
);
fExportStructure32("IO_COUNTERS_32",
  (ULONGLONG,   "ReadOperationCount"),
  (ULONGLONG,   "WriteOperationCount"),
  (ULONGLONG,   "OtherOperationCount"),
  (ULONGLONG,   "ReadTransferCount"),
  (ULONGLONG,   "WriteTransferCount"),
  (ULONGLONG,   "OtherTransferCount"),
);
fExportStructure64("IO_COUNTERS_64",
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
    (DWORD,     "LowPart"),
    (LONG,      "HighPart"),
  ),            "u"),
  (LONGLONG,    "QuadPart"),
);
fExportStructure("LIST_ENTRY",
  (PVOID,       "Flink"), # Should be PLIST_ENTRY but circular references are not implemented.
  (PVOID,       "Blink"), # Should be PLIST_ENTRY but circular references are not implemented.
);
fExportStructure32("LIST_ENTRY_32",
  (PVOID_32,    "Flink"), # Should be PLIST_ENTRY_32 but circular references are not implemented.
  (PVOID_32,    "Blink"), # Should be PLIST_ENTRY_32 but circular references are not implemented.
);
fExportStructure64("LIST_ENTRY_64",
  (PVOID_64,    "Flink"), # Should be PLIST_ENTRY_64 but circular references are not implemented.
  (PVOID_64,    "Blink"), # Should be PLIST_ENTRY_64 but circular references are not implemented.
);
#MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
fExportStructure("MEMORY_BASIC_INFORMATION", 
  (PVOID,       "BaseAddress"),
  (PVOID,       "AllocationBase"),
  (DWORD,       "AllocationProtect"),
  (SIZE_T,      "RegionSize"),
  (DWORD,       "State"),
  (DWORD,       "Protect"),
  (DWORD,       "Type"),
);
fExportStructure("MEMORY_BASIC_INFORMATION32", 
  (DWORD,       "BaseAddress"),
  (DWORD,       "AllocationBase"),
  (DWORD,       "AllocationProtect"),
  (DWORD,       "RegionSize"),
  (DWORD,       "State"),
  (DWORD,       "Protect"),
  (DWORD,       "Type"),
);
fExportStructure("MEMORY_BASIC_INFORMATION64", 
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

fExportStructure("MODULEENTRY32A",
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
fExportStructure("MODULEENTRY32W",
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
fExportStructure("OVERLAPPED",
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
fExportStructure("POINT",
  (LONG,        "x"),
  (LONG,        "y"),
);
fExportStructure32("PEB_LDR_DATA_32", 
  (BYTE * 8,    "Reserved1"),
  (PVOID_32 * 3, "Reserved2"),
  (LIST_ENTRY_32, "InMemoryOrderModuleList"),
);
fExportStructure64("PEB_LDR_DATA_64", 
  (BYTE * 8,    "Reserved1"),
  (PVOID_64 * 3, "Reserved2"),
  (LIST_ENTRY_64, "InMemoryOrderModuleList"),
);
fExportStructure("PROCESS_INFORMATION",
  (HANDLE,      "hProcess"),
  (HANDLE,      "hThread"),
  (DWORD,       "dwProcessId"),
  (DWORD,       "dwThreadId"),
);
fExportStructure("PROCESS_MEMORY_COUNTERS",
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
fExportStructure("PROCESS_MEMORY_COUNTERS_EX",
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
fExportStructure("PROCESSENTRY32A",
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
fExportStructure("PROCESSENTRY32W",
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
fExportStructure("RECT",
  (LONG,        "left"),
  (LONG,        "top"),
  (LONG,        "right"),
  (LONG,        "bottom"),
);
#SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
fExportStructure("SECURITY_ATTRIBUTES",
  (DWORD,       "nLength"),
  (LPVOID,      "lpSecurityDescriptor"),
  (BOOL,        "bInheritHandle"),
);
fExportStructure("SID");
fExportStructure("SIZE",
  (LONG,        "cx"),
  (LONG,        "cy"),
);
fExportStructure("SMALL_RECT",
  (SHORT,       "Left"),
  (SHORT,       "Top"),
  (SHORT,       "Right"),
  (SHORT,       "Bottom"),
);
fExportStructure("STARTUPINFOA",
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
fExportStructure("STARTUPINFOW",
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
fExportStructure("STOWED_EXCEPTION_INFORMATION_HEADER",
  (ULONG,       "Size"),
  (ULONG,       "Signature"),
);
fExportStructure32("STOWED_EXCEPTION_INFORMATION_V1_32",
  (STOWED_EXCEPTION_INFORMATION_HEADER, "Header"),
  (HRESULT,     "ResultCode"),
  (DWORD,       "ExceptionForm_ThreadId"),
  UNION(
    STRUCT(
      (PVOID_32, "ExceptionAddress"),
      (ULONG,   "StackTraceWordSize"),
      (ULONG,   "StackTraceWords"),
      (PVOID_32, "StackTrace"),
    ),
    STRUCT(
      (PWSTR_32, "ErrorText"),
    ),
  ),
);
fExportStructure64("STOWED_EXCEPTION_INFORMATION_V1_64",
  (STOWED_EXCEPTION_INFORMATION_HEADER, "Header"),
  (HRESULT,     "ResultCode"),
  (DWORD,       "ExceptionForm_ThreadId"),
  UNION(
    STRUCT(
      (PVOID_64, "ExceptionAddress"),
      (ULONG,   "StackTraceWordSize"),
      (ULONG,   "StackTraceWords"),
      (PVOID_64, "StackTrace"),
    ),
    STRUCT(
      (PWSTR_64, "ErrorText"),
    ),
  ),
);
fExportStructure32("STOWED_EXCEPTION_INFORMATION_V2_32",
  (STOWED_EXCEPTION_INFORMATION_HEADER, "Header"),
  (HRESULT,     "ResultCode"),
  (DWORD,       "ExceptionForm_ThreadId"),
  UNION(
    STRUCT(
      (PVOID_32, "ExceptionAddress"),
      (ULONG,   "StackTraceWordSize"),
      (ULONG,   "StackTraceWords"),
      (PVOID_32, "StackTrace"),
    ),
    STRUCT(
      (PWSTR_32, "ErrorText"),
    ),
  ),
  (ULONG,       "NestedExceptionType"),
  (PVOID_32,    "NestedException"),
);
fExportStructure64("STOWED_EXCEPTION_INFORMATION_V2_64",
  (STOWED_EXCEPTION_INFORMATION_HEADER, "Header"),
  (HRESULT,     "ResultCode"),
  (DWORD,       "ExceptionForm_ThreadId"),
  UNION(
    STRUCT(
      (PVOID_64, "ExceptionAddress"),
      (ULONG,   "StackTraceWordSize"),
      (ULONG,   "StackTraceWords"),
      (PVOID_64, "StackTrace"),
    ),
    STRUCT(
      (PWSTR_64, "ErrorText"),
    ),
  ),
  (ULONG,       "NestedExceptionType"),
  (PVOID_64,    "NestedException"),
);
fExportStructure("SYSTEM_INFO",
  UNION(
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
fExportStructure("CONSOLE_SCREEN_BUFFER_INFO", 
  (COORD,       "dwSize"),
  (COORD,       "dwCursorPosition"),
  (WORD,        "wAttributes"),
  (SMALL_RECT,  "srWindow"),
  (COORD,       "dwMaximumWindowSize"),
);
#JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ
fExportStructure32("JOBOBJECT_BASIC_LIMIT_INFORMATION_32",
  (LARGE_INTEGER, "PerProcessUserTimeLimit"),
  (LARGE_INTEGER, "PerJobUserTimeLimit"),
  (DWORD,       "LimitFlags"),
  (SIZE_T_32,   "MinimumWorkingSetSize"),
  (SIZE_T_32,    "MaximumWorkingSetSize"),
  (DWORD,       "ActiveProcessLimit"),
  (PULONG_32,   "Affinity"),
  (DWORD,       "PriorityClass"),
  (DWORD,       "SchedulingClass"),
);
fExportStructure64("JOBOBJECT_BASIC_LIMIT_INFORMATION_64",
  (LARGE_INTEGER, "PerProcessUserTimeLimit"),
  (LARGE_INTEGER, "PerJobUserTimeLimit"),
  (DWORD,       "LimitFlags"),
  (SIZE_T_64,      "MinimumWorkingSetSize"),
  (SIZE_T_64,      "MaximumWorkingSetSize"),
  (DWORD,       "ActiveProcessLimit"),
  (PULONG_64,   "Affinity"),
  (DWORD,       "PriorityClass"),
  (DWORD,       "SchedulingClass"),
);
fExportStructure32("JOBOBJECT_EXTENDED_LIMIT_INFORMATION_32",
  (JOBOBJECT_BASIC_LIMIT_INFORMATION_32, "BasicLimitInformation"),
  (DWORD,       "Padding0"), # Apparently... but this is not documented anywhere.
  (IO_COUNTERS_32, "IoInfo"),
  (SIZE_T_32,   "ProcessMemoryLimit"),
  (SIZE_T_32,   "JobMemoryLimit"),
  (SIZE_T_32,   "PeakProcessMemoryUsed"),
  (SIZE_T_32,   "PeakJobMemoryUsed"),
);
fExportStructure64("JOBOBJECT_EXTENDED_LIMIT_INFORMATION_64",
  (JOBOBJECT_BASIC_LIMIT_INFORMATION_64, "BasicLimitInformation"),
  (IO_COUNTERS_64, "IoInfo"),
  (SIZE_T_64,   "ProcessMemoryLimit"),
  (SIZE_T_64,   "JobMemoryLimit"),
  (SIZE_T_64,   "PeakProcessMemoryUsed"),
  (SIZE_T_64,   "PeakJobMemoryUsed"),
);
#NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN
fExportStructure("IMAGE_NT_HEADERS32",
  (DWORD,       "Signature"),
  (IMAGE_FILE_HEADER, "FileHeader"),
  (IMAGE_OPTIONAL_HEADER32, "OptionalHeader"),
);
fExportStructure("IMAGE_NT_HEADERS64",
  (DWORD,       "Signature"),
  (IMAGE_FILE_HEADER, "FileHeader"),
  (IMAGE_OPTIONAL_HEADER64, "OptionalHeader"),
);
#RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
fExportStructure32("RTL_USER_PROCESS_PARAMETERS_32",
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
fExportStructure64("RTL_USER_PROCESS_PARAMETERS_64",
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
fExportStructure("SID_AND_ATTRIBUTES",
  (PSID,        "Sid"),
  (DWORD,       "Attributes"),
);
#TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT
fExportStructure("TOKEN_MANDATORY_LABEL",
  (SID_AND_ATTRIBUTES, "Label"),
);

################################################################################
# Structures that contain or refer to other structures which in turn refer to  #
# other structures as well                                                     #
################################################################################

#PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
fExportStructure32("PEB_32",
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
fExportStructure64("PEB_64",
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
fExportStructure32("PROCESS_BASIC_INFORMATION_32",
  (PVOID_32,    "Reserved1"),
  (PPEB_32,     "PebBaseAddress"),
  (PVOID_32 * 2, "Reserved2"),
  (PULONG_32,   "UniqueProcessId"),
  (PVOID_32,    "Reserved3"),
);
fExportStructure64("PROCESS_BASIC_INFORMATION_64",
  (PVOID_64,    "Reserved1"),
  (PPEB_64,     "PebBaseAddress"),
  (PVOID_64 * 2, "Reserved2"),
  (PULONG_64,   "UniqueProcessId"),
  (PVOID_64,    "Reserved3"),
);
