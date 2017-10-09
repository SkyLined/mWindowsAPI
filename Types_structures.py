import ctypes;
from Functions import *;
from Types import *;

def fsAnonymousFieldName(asAnonymousFieldNames):
  sName = "_anonymous_field_%d_" % len(asAnonymousFieldNames);
  asAnonymousFieldNames.append(sName);
  return sName;

uNamelessStructureOrUnionsCounter = 0;
def fcStructureOrUnion(sStructure_or_Union, sName, axFields):
  global uNamelessStructureOrUnionsCounter;
  if sName is None:
    uNamelessStructureOrUnionsCounter += 1;
    sName = "_nameless_%s_%d_" % (sStructure_or_Union.lower(), uNamelessStructureOrUnionsCounter);
  asAnonymousFieldNames = []
  atxFields = [
    isinstance(xField, tuple) and xField or (fsAnonymousFieldName(asAnonymousFieldNames), xField)
    for xField in axFields
  ];
  cBaseType = sStructure_or_Union == "Structure" and ctypes.Structure or ctypes.Union;
  return type(
    sName,
    (cBaseType,),
    {
      "_anonymous_": asAnonymousFieldNames,
      "_fields_": atxFields,
    },
  );

def UNION(*axFields):
  return fcStructureOrUnion("Union", None, axFields);

def STRUCT(*axFields):
  return fcStructureOrUnion("Structure", None, axFields);

# Defining a structure also defines "P<struct_name>" and "PP<struct_name>" as a
# pointer-to-structure and a pointer-to-pointer-to-structure respectively.
def fDefineStructure(sName, *atxFields):
  cStructure = fcStructureOrUnion("Structure", sName, atxFields);
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
  ("X", SHORT),
  ("Y", SHORT),
);

#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
fDefineStructure("FILETIME",
  ("dwLowDateTime", DWORD),
  ("dwHighDateTime", DWORD),
);

#OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO
fDefineStructure("OVERLAPPED",
  ("Internal", PULONG),
  ("InternalHigh", PULONG),
  UNION(
    STRUCT(
      ("Offset", DWORD),
      ("OffsetHigh", DWORD),
    ),
    ("Pointer", PVOID),
  ),
  ("hEvent", HANDLE),
);
#PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
fDefineStructure("POINT",
  ("x", LONG),
  ("y", LONG),
);
#RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
fDefineStructure("RECT",
  ("left", LONG),
  ("top", LONG),
  ("right", LONG),
  ("bottom", LONG),
);

#SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
fDefineStructure("SID");
fDefineStructure("SIZE",
  ("cx", LONG),
  ("cy", LONG),
);
fDefineStructure("SMALL_RECT",
  ("Left", SHORT),
  ("Top", SHORT),
  ("Right", SHORT),
  ("Bottom", SHORT),
);

################################################################################
# Structures that contain other structures                                     #
################################################################################

#CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
fDefineStructure("CONSOLE_SCREEN_BUFFER_INFO", 
  ("dwSize", COORD),
  ("dwCursorPosition", COORD),
  ("wAttributes", WORD),
  ("srWindow", SMALL_RECT),
  ("dwMaximumWindowSize", COORD),
);
#SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
fDefineStructure("SID_AND_ATTRIBUTES",
  ("Sid", PSID),
  ("Attributes", DWORD),
);
#TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT
fDefineStructure("TOKEN_MANDATORY_LABEL",
  ("Label", SID_AND_ATTRIBUTES),
);

