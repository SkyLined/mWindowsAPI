from mWindowsSDK import *;
from .fbLastErrorIs import fbLastErrorIs;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fsGetISAForProcessHandle import fsGetISAForProcessHandle;
from .fsGetPythonISA import fsGetPythonISA;
from .fThrowLastError import fThrowLastError;
from .oSystemInfo import oSystemInfo;

# When reading a NULL terminated string from a process, we do not know the length up front. So we will need to read
# bytes until we find a NULL. We could read one byte at a time from the process, but reading bytes from another process
# is the slowest part of the operation, so it is often faster to read blocks of multiple bytes (aka read-ahead
# buffering). The code below does this and uses the following value for the size of these blocks:
guStringReadAheadBlockSize = 0x400;

uBasicProtectionFlagsMask = 0xFF;

def fsProtection(uProtection):
  if uProtection is None: return None;
  return " | ".join([s for s in [
    {
      PAGE_NOACCESS: "PAGE_NOACCESS",
      PAGE_READONLY: "PAGE_READONLY",
      PAGE_READWRITE: "PAGE_READWRITE",
      PAGE_WRITECOPY: "PAGE_WRITECOPY",
      PAGE_EXECUTE: "PAGE_EXECUTE",
      PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
      PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
      PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
    }[uProtection & uBasicProtectionFlagsMask],
    "PAGE_GUARD" if uProtection & PAGE_GUARD else None,
  ] if s]);

def fasAllowedAccessTypesForProtection(uProtection):
  return {
    PAGE_NOACCESS: [],
    PAGE_READONLY: ["read"],
    PAGE_READWRITE: ["read", "write"],
    PAGE_WRITECOPY: ["read", "write"],
    PAGE_EXECUTE: ["read", "execute"],
    PAGE_EXECUTE_READ: ["read", "execute"],
    PAGE_EXECUTE_READWRITE: ["read", "write", "execute"],
    PAGE_EXECUTE_WRITECOPY: ["read", "write", "execute"],
  }[uProtection & uBasicProtectionFlagsMask];

class cVirtualAllocation(object):
  @staticmethod
  def foCreateForProcessIdAndString(
    uProcessId,
    sString,
    bUnicode = False,
    uAddress = None,
    uProtection = None,
  ):
    oVirtualAllocation = cVirtualAllocation.foCreateForProcessId(
      uProcessId = uProcessId,
      uSize = len(sString) * (bUnicode and 2 or 1),
      uAddress = uAddress,
      uProtection = uProtection,
    );
    oVirtualAllocation.fWriteStringForOffset(
      sString = sString,
      uOffset = 0,
      bUnicode = bUnicode
    );
    return oVirtualAllocation;
  @staticmethod
  def foCreateForProcessId(
    uProcessId,
    uSize,
    uAddress = None,
    bReserved = False,
    uProtection = None,
  ):
    oKernel32 = foLoadKernel32DLL();
    if uProtection is None:
      uProtection = PAGE_NOACCESS;
    else:
      assert fsProtection(uProtection), \
          "Unknown uProtection values 0x%08X" % uProtection;
    # Try to open the process...
    ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_VM_OPERATION);
    try:
      opBaseAddress = oKernel32.VirtualAllocEx(
          ohProcess,
          LPVOID(uAddress or 0), # lpAddress
          uSize, # dwSize
          MEM_RESERVE | (not bReserved and MEM_COMMIT or 0), # flAllocationType
          uProtection, # flProtect
      );
      if opBaseAddress.fbIsNULLPointer():
        fThrowLastError("VirtualAllocEx(%s, 0x%08X, 0x%X, MEM_COMMIT, %s)" % \
            (repr(ohProcess), uAddress or 0, uSize, fsProtection(uProtection)));
      # Return a cVirtualAllocation object that represents the newly allocated memory.
      return cVirtualAllocation(uProcessId, opBaseAddress.fuGetValue());
    finally:
      if not oKernel32.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  
  def __init__(oSelf, uProcessId, uAddress):
    oSelf.__uProcessId = uProcessId;
    oSelf.__uPointerSize = None; # Will be set in __fUpdate
    oSelf.__fUpdate(uAddress);
  
  def __fUpdate(oSelf, uAddress = None):
    oKernel32 = foLoadKernel32DLL();
    # Address is only supplied the first time (by __init__). After that, we know the start address and use that:
    if uAddress is None:
      uAddress = oSelf.__uStartAddress;
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_QUERY_INFORMATION);
    try:
      # Accessing a virtual allocation in a 64-bit processes from 32-bit Python is theoretically possible with a few
      # hacks, but very complex and not worth the effort IMHO.
      # https://stackoverflow.com/questions/5714297/is-it-possible-to-read-process-memory-of-a-64-bit-process-from-a-32bit-app
      # For now, we simply detect this an throw an error.
      # First we find out if the OS is 64-bit, as this problem can only occur on a 64-bit OS:
      if oSelf.__uPointerSize is None:
        if oSystemInfo.sOSISA == "x86":
          sProcessISA = "x86";
        else:
          # Finally we find out if the remote process is 64-bit:
          sProcessISA = fsGetISAForProcessHandle(ohProcess);
          # Throw an error if this is the case:
          assert fsGetPythonISA() == "x64" or sProcessISA != "x64", \
              "Accessing a virtual allocation in a 64-bit process from 32-bit Python process is not implemented";
          # Next we find out if the python process is 32-bit, as this problem can only occur in a 32-bit python process:
        oSelf.__uPointerSize = {"x86": 4, "x64": 8}[sProcessISA];
      oMemoryBasicInformation = MEMORY_BASIC_INFORMATION();
      oStoredBytes = oKernel32.VirtualQueryEx(
        ohProcess,
        uAddress, # lpAddress
        oMemoryBasicInformation.foCreatePointer(), # lpBuffer,
        MEMORY_BASIC_INFORMATION.fuGetSize(), # nLength
      );
      if oStoredBytes != MEMORY_BASIC_INFORMATION.fuGetSize():
        # This can fail if the address is not valid, which is acceptable.
        if not fbLastErrorIs(ERROR_INVALID_PARAMETER):
          foThrowLastError("VirtualQueryEx(%s, 0x%08X, ..., 0x%X) = %s" % \
              (repr(ohProcess), uAddress, MEMORY_BASIC_INFORMATION.fuGetSize(), repr(oStoredBytes)));
        oSelf.__uAllocationBaseAddress = None;
        oSelf.__uAllocationProtection = None;
        oSelf.__uStartAddress = None;
        oSelf.__uSize = None;
        oSelf.__uState = None;
        oSelf.__uProtection = None;
        oSelf.__uType = None;
        oSelf.__sBytes = None;
      else:
        # Not all information is valid when there is no memory allocated at the address.
        bNotFree = oMemoryBasicInformation.State != MEM_FREE;
        oSelf.__uAllocationBaseAddress = oMemoryBasicInformation.AllocationBase.fuGetValue() if bNotFree else None;
        oSelf.__uAllocationProtection = oMemoryBasicInformation.AllocationProtect.fuGetValue() if bNotFree else None;
        oSelf.__uStartAddress = oMemoryBasicInformation.BaseAddress.fuGetValue() if bNotFree else None;
        oSelf.__uSize = oMemoryBasicInformation.RegionSize.fuGetValue() if bNotFree else None;
        oSelf.__uState = oMemoryBasicInformation.State.fuGetValue();
        oSelf.__uProtection = oMemoryBasicInformation.Protect.fuGetValue() if bNotFree else None;
        oSelf.__uType = oMemoryBasicInformation.Type.fuGetValue() if bNotFree else None;
        oSelf.__sBytes = None;
    finally:
      if not oKernel32.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  
  def fbContainsAddress(oSelf, uAddress, uSize = 1):
    return (
      oSelf.uStartAddress is not None
      and oSelf.uStartAddress <= uAddress
      and oSelf.uEndAddress >= uAddress + uSize
    );
  
  # Process id
  @property
  def uProcessId(oSelf):
    return oSelf.__uProcessId;
  
  # Allocation start address and protection
  @property
  def uAllocationBaseAddress(oSelf):
    return oSelf.__uAllocationBaseAddress;
  @property
  def uAllocationProtection(oSelf):
    return oSelf.__uAllocationProtection;
  @property
  def sAllocationProtection(oSelf):
    return fsProtection(oSelf.__uAllocationProtection);

  # Start/End address and size
  @property
  def uAddress(oSelf):
    return oSelf.__uStartAddress;
  @property
  def uStartAddress(oSelf):
    return oSelf.__uStartAddress;
  @property
  def uSize(oSelf):
    return oSelf.__uSize;
  @property
  def uEndAddress(oSelf):
    return oSelf.__uStartAddress and (oSelf.__uStartAddress + oSelf.__uSize);
  
  # State
  @property
  def uState(oSelf):
    return oSelf.__uState;
  @property
  def sState(oSelf):
    return {
      MEM_COMMIT: "MEM_COMMIT",
      MEM_FREE: "MEM_FREE",
      MEM_RESERVE: "MEM_RESERVE",
      None: None,
    }[oSelf.__uState];
  @property
  def bAllocated(oSelf):
    return oSelf.uState == MEM_COMMIT;
  @property
  def bReserved(oSelf):
    return oSelf.uState == MEM_RESERVE;
  @property
  def bFree(oSelf):
    return oSelf.uState == MEM_FREE;
  @property
  def bInvalid(oSelf):
    return oSelf.uState is None;
  
  # Protection
  @property
  def uProtection(oSelf):
    return oSelf.__uProtection;
  @property
  def sProtection(oSelf):
   # Only mentions "basic" access protection flags! (not PAGE_GUARD, etc.)
    return fsProtection(oSelf.__uProtection);
  
  @property
  def bReadable(oSelf):
    return oSelf.bAllocated and "read" in fasAllowedAccessTypesForProtection(oSelf.uProtection);
  @property
  def bWritable(oSelf):
    return oSelf.bAllocated and "write" in fasAllowedAccessTypesForProtection(oSelf.uProtection);
  @property
  def bExecutable(oSelf):
    return oSelf.bAllocated and "execute" in fasAllowedAccessTypesForProtection(oSelf.uProtection);
  @property
  def bGuard(oSelf):
    return oSelf.bAllocated and (oSelf.uAllocationProtection & PAGE_GUARD);
  
  @uProtection.setter
  def uProtection(oSelf, uNewProtection):
    oKernel32 = foLoadKernel32DLL();
    assert oSelf.bAllocated, \
        "Cannot modify protection on a virtual allocation that is not allocated";
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_OPERATION);
    try:
      flOldProtection = DWORD();
      if not oKernel32.VirtualProtectEx(
        ohProcess,
        LPVOID(oSelf.__uStartAddress), # lpAddress,
        SIZE_T(oSelf.__uSize), # nSize
        DWORD(uNewProtection), # flNewProtection
        PDWORD(flOldProtection), # lpflOldProtection
      ):
        fThrowLastError("VirtualProtectEx(%s, 0x%08X, 0x%X, 0x%08X, ...)" % \
            (repr(ohProcess), oSelf.__uStartAddress, oSelf.__uSize, uNewProtection,));
      oSelf.__uProtection = uNewProtection;
    finally:
      if not oKernel32.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));

  @sProtection.setter
  def sProtection(oSelf, sNewProtection):
    # sNewProtection can only contain "basic" access protection flags, like these:
    uNewProtection = {
      "PAGE_NOACCESS": PAGE_NOACCESS,
      "PAGE_READONLY": PAGE_READONLY,
      "PAGE_READWRITE": PAGE_READWRITE,
      "PAGE_WRITECOPY": PAGE_WRITECOPY,
      "PAGE_EXECUTE": PAGE_EXECUTE,
      "PAGE_EXECUTE_READ": PAGE_EXECUTE_READ,
      "PAGE_EXECUTE_READWRITE": PAGE_EXECUTE_READWRITE,
      "PAGE_EXECUTE_WRITECOPY": PAGE_EXECUTE_WRITECOPY,
    }.get(sNewProtection);
    assert uNewProtection is not None, \
        "Unknown protection %s" % sNewProtection;
    oSelf.uProtection = uNewProtection;
  
  # Type
  @property
  def uType(oSelf):
    return oSelf.__uType;
  @property
  def sType(oSelf):
    return {
      MEM_IMAGE: "MEM_IMAGE",
      MEM_MAPPED: "MEM_MAPPED",
      MEM_PRIVATE: "MEM_PRIVATE",
      None: None,
    }[oSelf.__uType];
  @property
  def bImage(oSelf):
    return oSelf.__uType == MEM_IMAGE;
  @property
  def bMapped(oSelf):
    return oSelf.__uType == MEM_MAPPED;
  @property
  def bPrivate(oSelf):
    return oSelf.__uType == MEM_PRIVATE;
  
  def fsReadBytesForOffsetAndSize(oSelf, uOffset, uSize):
    # Read ASCII string without NULL terminator.
    return oSelf.fsReadStringForOffsetAndLength(uOffset, uSize, bUnicode = False, bNullTerminated = False);
  def fsReadStringForOffsetAndLength(oSelf, uOffset, uLength, bUnicode = False, bNullTerminated = False):
    oKernel32 = foLoadKernel32DLL();
    # Sanity checks
    uSize = uLength * (2 if bUnicode else 1);
    assert oSelf.bAllocated, \
        "Cannot read data from a virtual allocation that is not allocated";
    assert uOffset >= 0, \
        "Offset -0x%X must be positive" % (-uOffset);
    assert uLength >= 0, \
        "uLength -0x%X must be positive" % (-uLength);
    assert uOffset < oSelf.__uSize, \
        "Offset 0x%X is outside of the virtual allocation of 0x%X bytes at 0x%08X" % \
        (uOffset, oSelf.__uSize, oSelf.__uStartAddress);
    assert uOffset + uSize <= oSelf.__uSize, \
        "Offset 0x%X + size 0x%X is outside of the virtual allocation of 0x%X bytes at 0x%08X" % \
        (uOffset, uSize, oSelf.__uSize, oSelf.__uStartAddress);
    # If needed, modify the protection to make sure the pages can be read.
    uOriginalProtection = oSelf.uProtection;
    if "read" not in fasAllowedAccessTypesForProtection(oSelf.uProtection):
      # Temporarily allow reading from this page.
      oSelf.uProtection = PAGE_READONLY;
    # Open process to read memory
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_READ);
    try:
      osBuffer = (WCHAR if bUnicode else CHAR)[uLength]();
      ouBytesRead = SIZE_T(0);
      opsBuffer = osBuffer.foCreatePointer(LPVOID);
      opuBytesRead = ouBytesRead.foCreatePointer();
      if not oKernel32.ReadProcessMemory(
        ohProcess,
        oSelf.__uStartAddress + uOffset, # lpBaseAddress
        opsBuffer, # lpBuffer
        uSize, # nSize
        opuBytesRead, # lpNumberOfBytesRead
      ):
        fThrowLastError("ReadProcessMemory(%s, 0x%08X+0x%X, %s, 0x%X, %s)" % \
            (repr(ohProcess), oSelf.__uStartAddress, uOffset, repr(opsBuffer), uSize, repr(opuBytesRead)));
      assert ouBytesRead == uSize, \
          "ReadProcessMemory(%s, 0x%08X+0x%X, %s, 0x%X, %s) => %s bytes read" % \
          (repr(ohProcess), oSelf.__uStartAddress, uOffset, repr(opsBuffer), uSize, repr(opuBytesRead), ouBytesRead.fuGetValue());
      # Return read data as a string.
      if bNullTerminated:
        return osBuffer.fsGetNullTerminatedString();
      return osBuffer.fsGetValue();
    finally:
      if not oKernel32.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
      # Restore original protection if needed
      if uOriginalProtection in [PAGE_NOACCESS, PAGE_EXECUTE]:
        oSelf.uProtection = uOriginalProtection;
  
  def fs0ReadNullTerminatedStringForOffset(oSelf, uOffset, bUnicode = False):
    # If the string is not terminated with a '\0', we will read it up to the
    # end of the virtual allocation before finding out and return None.
    # This normally indicates that you're not reading a NULL terminated string.
    # However, there is an extremely unlikely possibility that an application
    # created two adjacent virtual allocations to store the string. I'm writing
    # this here in case you are debugging and find this to be the case.
    uCharSize = 2 if bUnicode else 1;
    sString = "";
    while 1:
      uSize = min(guStringReadAheadBlockSize, oSelf.uSize - uOffset);
      uLength = uSize / uCharSize;
      if uLength == 0:
        return None; # String is not NULL terminated because it runs until the end of the virtual allocation.
      s0SubString = oSelf.fsReadStringForOffsetAndLength(uOffset, uLength, bUnicode, bNullTerminated = True);
      if s0SubString is None:
        return None; # Apparently he string can no longer be read.
      sString += s0SubString;
      if len(s0SubString) < uLength: # We found a NULL terminator
        return sString;
      uOffset += uSize;
  
  def fauReadValuesForOffsetSizeAndCount(oSelf, uOffset, uSize, uCount):
    sBytes = oSelf.fsReadBytesForOffsetAndSize(uOffset, uCount * uSize);
    sUnpackValueFormat = {1: "B", 2: "H", 4: "L", 8: "Q"}.get(uSize);
    assert sUnpackValueFormat, \
        "Unsupported size %d (try 1,2,4 or 8)" % uSize;
    return struct.unpack("<%s" % (sUnpackValueFormat * uCount), sBytes);
  
  def fauReadBytesForOffsetAndSize(oSelf, uOffset, uSize):
    # Read `uSize` values of 1 byte:
    return oSelf.fauReadValuesForOffsetSizeAndCount(uOffset, 1, uSize);
  
  def fuReadValueForOffsetAndSize(oSelf, uOffset, uSize):
    # Read 1 values of `uSize` byte:
    return oSelf.fauReadValuesForOffsetSizeAndCount(uOffset, uSize, 1)[0];
  
  def fuReadPointerForOffset(oSelf, uOffset):
    # Read 1 value of `uPointerSize` bytes
    return oSelf.fauReadValuesForOffsetAndSize(uOffset, oSelf.__uPointerSize, 1)[0];
  
  def fauReadPointersForOffsetAndCount(oSelf, uOffset, uCount):
    # Read `uCount` values of `uPointerSize` bytes
    return oSelf.fauReadValuesForOffsetSizeAndCount(uOffset, oSelf.__uPointerSize, uCount);
  
  def foReadStructureForOffset(oSelf, cStructure, uOffset):
    sData = oSelf.fsReadBytesForOffsetAndSize(uOffset, cStructure.fuGetSize());
    return cStructure.foFromBytesString(sData);
  
  def fWriteBytesForOffset(oSelf, sBytes, uOffset):
    return oSelf.fWriteStringForOffset(sBytes, uOffset, bUnicode = False);
  def fWriteStringForOffset(oSelf, sString, uOffset, bUnicode = False):
    oKernel32 = foLoadKernel32DLL();
    # Sanity checks
    assert oSelf.bAllocated, \
        "Cannot write memory that is not allocated!";
    assert uOffset >= 0, \
        "Offset -0x%X must be positive" % (-uOffset);
    uSize = len(sString) * (bUnicode and 2 or 1);
    assert uSize, \
        "You must supply data to write";
    assert uOffset < oSelf.__uSize, \
        "Offset 0x%X is outside of the virtual allocation of 0x%X bytes at 0x%08X" % \
        (uOffset, oSelf.__uSize, oSelf.__uStartAddress);
    assert uOffset + uSize <= oSelf.__uSize, \
        "Offset 0x%X + sString size (0x%X) is outside of the virtual allocation of 0x%X bytes at 0x%08X" % \
        (uOffset, uSize, oSelf.__uSize, oSelf.__uStartAddress);
    # Modify protection to make sure the pages can be read.
    uOriginalProtection = oSelf.uProtection;
    if oSelf.uProtection in [PAGE_NOACCESS, PAGE_READONLY]:
      oSelf.uProtection = PAGE_READWRITE;
    elif oSelf.uProtection in [PAGE_EXECUTE, PAGE_EXECUTE_READ]:
      oSelf.uProtection = PAGE_EXECUTE_READWRITE;
    # Open process to read memory
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
    try:
      oBuffer = (PWCHAR if bUnicode else PCHAR)(sString);
      ouBytesWritten = SIZE_T(0);
      if not oKernel32.WriteProcessMemory(
        ohProcess,
        oSelf.__uStartAddress + uOffset, # lpBaseAddress
        oBuffer.foCreatePointer(LPVOID), # lpBuffer
        uSize, # nSize
        ouBytesWritten.foCreatePointer(), # lpNumberOfBytesRead
      ):
        fThrowLastError("WriteProcessMemory(%s, 0x%08X, ..., 0x%X, ...)" % \
            (repr(ohProcess), oSelf.__uStartAddress + uOffset, uSize,));
      assert ouBytesWritten == uSize, \
          "WriteProcessMemory(%s, 0x%08X, ..., 0x%X, ...) => 0x%X bytes written" % \
          (repr(ohProcess), oSelf.__uStartAddress + uOffset, uSize, ouBytesWritten.fuGetValue());
    finally:
      if not oKernel32.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
      # Restore original protection if needed
      if uOriginalProtection in [PAGE_NOACCESS, PAGE_READONLY, PAGE_EXECUTE, PAGE_EXECUTE_READ]:
        oSelf.uProtection = uOriginalProtection;
  
  def fasDump(oSelf):
    def fsNumberOrNone(uValue, sValue = None):
      return (uValue is not None and "0x%X" % uValue or "None") + (sValue and " (%s)" % sValue or "");
    return [
      "uAllocationBaseAddress = %s" % fsNumberOrNone(oSelf.uAllocationBaseAddress),
      "uAllocationProtection  = %s" % fsNumberOrNone(oSelf.uAllocationProtection, oSelf.sAllocationProtection),
      "uStartAddress          = %s" % fsNumberOrNone(oSelf.uStartAddress),
      "uSize                  = %s" % fsNumberOrNone(oSelf.uSize),
      "uEndAddress            = %s" % fsNumberOrNone(oSelf.uEndAddress),
      "uState                 = %s" % fsNumberOrNone(oSelf.uState, oSelf.sState),
      "uProtection            = %s" % fsNumberOrNone(oSelf.uProtection, oSelf.sProtection),
      "uType                  = %s" % fsNumberOrNone(oSelf.uType, oSelf.sType),
    ];
  
  def fAllocate(oSelf, uProtection = None):
    oKernel32 = foLoadKernel32DLL();
    # Commit this virtual allocation if it is reserved
    assert oSelf.bReserved, \
        "You can only allocate a reserved virtual allocation";
    if uProtection is None:
      uProtection = PAGE_NOACCESS;
    else:
      assert fsProtection(uProtection), \
          "Unknown uProtection values 0x%08X" % uProtection;
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_OPERATION);
    try:
      opBaseAddress = oKernel32.VirtualAllocEx(
        ohProcess,
        LPVOID(oSelf.__uStartAddress), # lpAddress
        oSelf.__uSize, # dwSize
        MEM_COMMIT, # flAllocationType
        uProtection, # flProtect
      );
      if opBaseAddress.fbIsNULLPointer():
        fThrowLastError("VirtualAllocEx(%s, 0x%08X, 0x%X, MEM_COMMIT, 0x%08X)" % \
            (repr(ohProcess), oSelf.__uStartAddress, oSelf.__uSize, uProtection));
      uBaseAddress = opBaseAddress.fuGetValue();
      assert uBaseAddress == oSelf.__uStartAddress, \
          "Allocating reserved virtual allocation at 0x%08X allocated memory at %08X" % \
          (oSelf.__uStartAddress, uBaseAddress);
    finally:
      try:
        if not oKernel32.CloseHandle(ohProcess):
          fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
      finally:
        oSelf.__fUpdate();
  
  def fReserve(oSelf):
    oKernel32 = foLoadKernel32DLL();
    # Decommit this virtual allocation if it is committed
    assert oSelf.bAllocated, \
        "You can only reserve an allocated virtual allocation";
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_OPERATION);
    try:
      if not oKernel32.VirtualFreeEx(
        ohProcess,
        LPVOID(oSelf.__uStartAddress), # lpAddress
        oSelf.__uSize, # dwSize
        MEM_DECOMMIT, # dwFreeType
      ):
        fThrowLastError("VirtualFreeEx(%s, 0x%08X, 0, 0x%08X)" % \
          (repr(ohProcess), oSelf.__uStartAddress, MEM_DECOMMIT,));
    finally:
      try:
        if not oKernel32.CloseHandle(ohProcess):
          fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
      finally:
        oSelf.__fUpdate();
  
  def fFree(oSelf):
    oKernel32 = foLoadKernel32DLL();
    # Free this virtual allocation if it is reserved or committed
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_OPERATION);
    try:
      if not oKernel32.VirtualFreeEx(
        ohProcess,
        LPVOID(oSelf.__uStartAddress), # lpAddress
        0, # dwSize
        MEM_RELEASE, # dwFreeType
      ):
        fThrowLastError("VirtualFreeEx(%s, 0x%08X, 0, 0x%08X)" % \
            (repr(ohProcess), oSelf.__uStartAddress, MEM_RELEASE,));
    finally:
      try:
        if not oKernel32.CloseHandle(ohProcess):
          fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
      finally:
        oSelf.__fUpdate();
