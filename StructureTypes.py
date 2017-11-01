import ctypes;
from Defines import *;
from Functions import *;
from PrimitiveTypes import *;

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

# Defining a structure also defines "P<struct_name>" and "PP<struct_name>" as a
# pointer-to-structure and a pointer-to-pointer-to-structure respectively.
def fDefineStructure(sName, *atxFields):
  cStructure = fcStructure(sName, *atxFields);
  globals()[sName] = cStructure;
  globals()["LP" + sName] = POINTER(cStructure);
  globals()["P" + sName] = POINTER(cStructure);
  globals()["PP" + sName] = POINTER(POINTER(cStructure));
def fDefineStructure32(sName, *atxFields):
  cStructure = fcStructure_32(sName, *atxFields);
  globals()[sName] = cStructure;
  globals()["LP" + sName] = POINTER(cStructure);
  globals()["P" + sName] = POINTER(cStructure);
  globals()["PP" + sName] = POINTER(POINTER(cStructure));
def fDefineStructure64(sName, *atxFields):
  cStructure = fcStructure_64(sName, *atxFields);
  globals()[sName] = cStructure;
  globals()["LP" + sName] = POINTER(cStructure);
  globals()["P" + sName] = POINTER(cStructure);
  globals()["PP" + sName] = POINTER(POINTER(cStructure));

################################################################################
# Simple structures that contain only primitives and no other structures are   #
# defined first, strcutures that contain other structures must wait until      #
# those structures are defined and will therefore be defined in a second round #
################################################################################

#CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
fDefineStructure("COORD", 
  (SHORT,       "X"),
  (SHORT,       "Y"),
);

#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
fDefineStructure("FILETIME",
  (DWORD,       "dwLowDateTime"),
  (DWORD,       "dwHighDateTime"),
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
      (DWORD, "Offset"),
      (DWORD, "OffsetHigh"),
    ),
    (PVOID, "Pointer"),
  ),
  (HANDLE,      "hEvent"),
);
#PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
fDefineStructure("POINT",
  (LONG,        "x"),
  (LONG,        "y"),
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
# Structures that contain other structures                                     #
################################################################################

#CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
fDefineStructure("CONSOLE_SCREEN_BUFFER_INFO", 
  (COORD,       "dwSize"),
  (COORD,       "dwCursorPosition"),
  (WORD,        "wAttributes"),
  (SMALL_RECT,  "srWindow"),
  (COORD,       "dwMaximumWindowSize"),
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

