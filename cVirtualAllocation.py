from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fThrowError import fThrowError;
from oSystemInfo import oSystemInfo;
from fsGetPythonISA import fsGetPythonISA;

# When reading a NULL terminated string from a process, we do not know the length up front. So we will need to read
# bytes until we find a NULL. We could read one byte at a time from the process, but reading bytes from another process
# is the slowest part of the operation, so it is often faster to read blocks of multiple bytes (aka read-ahead
# buffering). The code below does this and uses the following value for the size of these blocks:
guStringReadAheadBlockSize = 0x400;

uBasicProtectionFlagsMask = 0xFF;

def fsProtection(uProtection):
  return {
      PAGE_NOACCESS: "PAGE_NOACCESS",
      PAGE_READONLY: "PAGE_READONLY",
      PAGE_READWRITE: "PAGE_READWRITE",
      PAGE_WRITECOPY: "PAGE_WRITECOPY",
      PAGE_EXECUTE: "PAGE_EXECUTE",
      PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
      PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
      PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
    }[uProtection & uBasicProtectionFlagsMask];

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
  def foCreateInProcessForIdAndString(
    uProcessId,
    sString,
    bUnicode = False,
    uAddress = None,
    uProtection = None,
  ):
    oVirtualAllocation = cVirtualAllocation.foCreateInProcessForId(
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
  def foCreateInProcessForId(
    uProcessId,
    uSize,
    uAddress = None,
    bReserved = False,
    uProtection = None,
  ):
    if uProtection is None:
      uProtection = PAGE_NOACCESS;
    else:
      assert fsProtection(uProtection), \
          "Unknown uProtection values 0x%08X" % uProtection;
    # Try to open the process...
    uFlags = PROCESS_VM_OPERATION;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, 0x%08X)" % (uFlags, uProcessId,));
    try:
      uBaseAddress = KERNEL32.VirtualAllocEx(
          hProcess,
          CAST(LPVOID, uAddress or 0), # lpAddress
          uSize, # dwSize
          MEM_RESERVE | (not bReserved and MEM_COMMIT or 0), # flAllocationType
          uProtection, # flProtect
      );
      if not uBaseAddress:
        fThrowError("VirtualAllocEx(0x%08X, 0x%08X, 0x%X, MEM_COMMIT, %s)" % \
            (hProcess, uAddress or 0, uSize, fsProtection(uProtection)));
      # Return a cVirtualAllocation object that represents the newly allocated memory.
      return cVirtualAllocation(uProcessId, uBaseAddress);
    finally:
      KERNEL32.CloseHandle(hProcess) \
          or fThrowError("CloseHandle(0x%X)" % (hProcess,));
  
  def __init__(oSelf, uProcessId, uAddress):
    oSelf.__uProcessId = uProcessId;
    oSelf.__uPointerSize = None; # Will be set in __fUpdate
    oSelf.__fUpdate(uAddress);
  
  def __fUpdate(oSelf, uAddress = None):
    # Address is only supplied the first time (by __init__). After that, we know the start address and use that:
    if uAddress is None:
      uAddress = oSelf.__uStartAddress;
    uFlags = PROCESS_QUERY_INFORMATION;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, oSelf.__uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, oSelf.__uProcessId, oSelf.__uProcessId,));
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
          bIsWow64Process = BOOL();
          KERNEL32.IsWow64Process(hProcess, POINTER(bIsWow64Process)) \
                or fThrowError("IsWow64Process(0x%08X, ...)" % (hProcess,));
          sProcessISA = bIsWow64Process and "x86" or "x64";
          # Throw an error if this is the case:
          assert fsGetPythonISA() == "x64" or sProcessISA != "x64", \
              "Accessing a virtual allocation in a 64-bit process from 32-bit Python process is not implemented";
          # Next we find out if the python process is 32-bit, as this problem can only occur in a 32-bit python process:
        oSelf.__uPointerSize = {"x86": 4, "x64": 8}[sProcessISA];
      oMemoryBasicInformation = MEMORY_BASIC_INFORMATION();
      uStoredBytes = KERNEL32.VirtualQueryEx(
        hProcess,
        LPVOID(uAddress), # lpAddress
        POINTER(oMemoryBasicInformation), # lpBuffer,
        SIZEOF(MEMORY_BASIC_INFORMATION), # nLength
      );
      if uStoredBytes != SIZEOF(MEMORY_BASIC_INFORMATION):
        # This can fail if the address is not valid, which is acceptable.
        uVirtualQueryExError = KERNEL32.GetLastError();
        (HRESULT_FROM_WIN32(uVirtualQueryExError) == ERROR_INVALID_PARAMETER) \
            or fThrowError("VirtualQueryEx(0x%08X, 0x%08X, ..., 0x%X) = 0x%X" % \
            (hProcess, uAddress, SIZEOF(MEMORY_BASIC_INFORMATION), uStoredBytes), uVirtualQueryExError);
        oSelf.__uAllocationBaseAddress = None;
        oSelf.__uAllocationProtection = None;
        oSelf.__uStartAddress = None;
        oSelf.__uSize = None;
        oSelf.__uState = None;
        oSelf.__uProtection = None;
        oSelf.__uType = None;
        oSelf.__sBytes = None;
      else:
        # Not all information is valid when therer is no memory allocated at the address.
        bValid = oMemoryBasicInformation.State != MEM_FREE;
        oSelf.__uAllocationBaseAddress = bValid and oMemoryBasicInformation.AllocationBase or None;
        oSelf.__uAllocationProtection = bValid and oMemoryBasicInformation.AllocationProtect or None;
        oSelf.__uStartAddress = bValid and oMemoryBasicInformation.BaseAddress or None;
        oSelf.__uSize = bValid and oMemoryBasicInformation.RegionSize or None;
        oSelf.__uState = oMemoryBasicInformation.State;
        oSelf.__uProtection = bValid and oMemoryBasicInformation.Protect or None;
        oSelf.__uType = bValid and oMemoryBasicInformation.Type or None;
        oSelf.__sBytes = None;
    finally:
      KERNEL32.CloseHandle(hProcess) \
          or fThrowError("CloseHandle(0x%X)" % (hProcess,));
  
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
    return oSelf.uState == None;
  
  # Protection
  @property
  def uProtection(oSelf):
    return oSelf.__uProtection;
  @property
  def sProtection(oSelf):
    return fsProtection(oSelf.__uProtection); # Only mentions "basic" access protection flags! (not PAGE_GUARD, etc.)
  
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
    return oSelf.bAllocated and (oSelf.uProtection & PAGE_GUARD);
  
  @uProtection.setter
  def uProtection(oSelf, uNewProtection):
    assert oSelf.bAllocated, \
        "Cannot modify protection on a virtual allocation that is not allocated";
    uFlags = PROCESS_VM_OPERATION;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, oSelf.__uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % \
        (uFlags, oSelf.__uProcessId, oSelf.__uProcessId,));
    try:
      flOldProtection = DWORD();
      KERNEL32.VirtualProtectEx(
        hProcess,
        LPVOID(oSelf.__uStartAddress), # lpAddress,
        SIZE_T(oSelf.__uSize), # nSize
        DWORD(uNewProtection), # flNewProtection
        PDWORD(flOldProtection), # lpflOldProtection
      ) or fThrowError("VirtualProtectEx(0x%08X, 0x%08X, 0x%X, 0x%08X, ...)" % \
          (hProcess, oSelf.__uStartAddress, oSelf.__uSize, uNewProtection,));
      oSelf.__uProtection = uNewProtection;
    finally:
      KERNEL32.CloseHandle(hProcess) \
          or fThrowError("CloseHandle(0x%X)" % (hProcess,));

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
  
  # Data
  @property
  def sBytes(oSelf):
    if not oSelf.__sBytes:
      oSelf.__sBytes = oSelf.fsReadBytesForOffsetAndSize(0, oSelf.__uSize);
    return oSelf.__sBytes;
  
  def fsReadBytesForOffsetAndSize(oSelf, uOffset, uSize):
    # Read ASCII string.
    return oSelf.fsReadStringForOffsetAndSize(uOffset, uSize);
  def fsReadStringForOffsetAndSize(oSelf, uOffset, uSize, bUnicode = False):
    # Sanity checks
    assert oSelf.bAllocated, \
        "Cannot read data from a virtual allocation that is not allocated";
    assert uOffset >= 0, \
        "Offset -0x%X must be positive" % (-uOffset);
    assert uSize >= 0, \
        "Size -0x%X must be positive" % (-uSize);
    assert uOffset < oSelf.__uSize, \
        "Offset 0x%X is outside of the virtual allocation of 0x%X bytes at 0x%08X" % \
        (uOffset, oSelf.__uSize, oSelf.__uStartAddress);
    assert uOffset + uSize <= oSelf.__uSize, \
        "Offset 0x%X + size 0x%X is outside of the virtual allocation of 0x%X bytes at 0x%08X" % \
        (uOffset, uSize, oSelf.__uSize, oSelf.__uStartAddress);
    assert not bUnicode or uSize % 2 == 0, \
        "Cannot read a Unicode string that has an odd number of bytes (%d)" % uSize;
    if oSelf.__sBytes:
      return oSelf.__sBytes[uOffset: uOffset + uSize];
    # If needed, modify the protection to make sure the pages can be read.
    uOriginalProtection = oSelf.uProtection;
    if "read" not in fasAllowedAccessTypesForProtection(oSelf.uProtection):
      # Temporarily allow reading from this page.
      oSelf.uProtection = PAGE_READONLY;
    # Open process to read memory
    hProcess = KERNEL32.OpenProcess(PROCESS_VM_READ, FALSE, oSelf.__uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (PROCESS_VM_READ, oSelf.__uProcessId,));
    try:
      sBytes = bUnicode and WSTR(uSize / 2) or STR(uSize);
      uBytesRead = SIZE_T(0);
      KERNEL32.ReadProcessMemory(
        hProcess,
        LPVOID(oSelf.__uStartAddress + uOffset), # lpBaseAddress
        POINTER(sBytes), # lpBuffer
        SIZE_T(uSize), # nSize
        POINTER(uBytesRead), # lpNumberOfBytesRead
      ) or fThrowError("ReadProcessMemory(0x%08X, 0x%08X, ..., 0x%X, ...)" % \
          (hProcess, oSelf.__uStartAddress + uOffset, uSize,));
      assert uBytesRead.value == uSize, \
          "ReadProcessMemory(0x%08X, 0x%08X, ..., 0x%X, ...) => 0x%X bytes read" % \
          (hProcess, oSelf.__uStartAddress + uOffset, uSize, uBytesRead.value);
      # Return read data as a string.
      if bUnicode:
        return sBytes.value;
      return sBytes.raw;
    finally:
      KERNEL32.CloseHandle(hProcess) \
          or fThrowError("CloseHandle(0x%X)" % (hProcess,));
      # Restore original protection if needed
      if uOriginalProtection in [PAGE_NOACCESS, PAGE_EXECUTE]:
        oSelf.uProtection = uOriginalProtection;
  
  def fsReadNullTerminatedStringForOffset(oSelf, uOffset, bUnicode = False):
    sNull = bUnicode and u"\0" or "\0";
    sString = "";
    while 1:
      uSize = min(guStringReadAheadBlockSize, oSelf.uSize - uOffset);
      if uSize == 0:
        return None; # String is not NULL terminated because it runs until the end of the virtual allocation.
      sSubString = oSelf.fsReadStringForOffsetAndSize(uOffset, uSize, bUnicode);
      uEndIndex = sSubString.find(sNull);
      if uEndIndex >= 0:
        return sString + sSubString[:uEndIndex];
      sString += sSubString;
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
    return cStructure.foFromBytesString(oSelf.fsReadBytesForOffsetAndSize(uOffset, SIZEOF(cStructure)));
  
  def fWriteBytesForOffset(oSelf, sBytes, uOffset):
    return oSelf.fWriteStringForOffset(sBytes, uOffset);
  def fWriteStringForOffset(oSelf, sString, uOffset, bUnicode = False):
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
    uFlags = PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, oSelf.__uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, oSelf.__uProcessId,));
    try:
      sBytes = bUnicode and WSTR(sString) or STR(sString);
      uBytesWritten = SIZE_T(0);
      KERNEL32.WriteProcessMemory(
        hProcess,
        LPVOID(oSelf.__uStartAddress + uOffset), # lpBaseAddress
        POINTER(sBytes), # lpBuffer
        SIZE_T(uSize), # nSize
        POINTER(uBytesWritten), # lpNumberOfBytesRead
      ) or fThrowError("WriteProcessMemory(0x%08X, 0x%08X, ..., 0x%X, ...)" % \
          (hProcess, oSelf.__uStartAddress + uOffset, uSize,));
      assert uBytesWritten.value == uSize, \
          "WriteProcessMemory(0x%08X, 0x%08X, ..., 0x%X, ...) => 0x%X bytes written" % \
          (hProcess, oSelf.__uStartAddress + uOffset, uSize, uBytesWritten.value);
    finally:
      KERNEL32.CloseHandle(hProcess) \
          or fThrowError("CloseHandle(0x%X)" % (hProcess,));
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
    # Commit this virtual allocation if it is reserved
    assert oSelf.bReserved, \
        "You can only allocate a reserved virtual allocation";
    if uProtection is None:
      uProtection = PAGE_NOACCESS;
    else:
      assert fsProtection(uProtection), \
          "Unknown uProtection values 0x%08X" % uProtection;
    hProcess = KERNEL32.OpenProcess(PROCESS_VM_OPERATION, FALSE, oSelf.__uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, 0x%08X)" % (PROCESS_VM_OPERATION, oSelf.__uProcessId,));
    try:
      uBaseAddress = KERNEL32.VirtualAllocEx(
        hProcess,
        CAST(LPVOID, oSelf.__uStartAddress), # lpAddress
        oSelf.__uSize, # dwSize
        MEM_COMMIT, # flAllocationType
        uProtection, # flProtect
      );
      if not uBaseAddress:
        fThrowError("VirtualAllocEx(0x%X, 0x%08X, 0x%X, 0x%08X, 0x%08X)" % \
            (hProcess,oSelf.__uStartAddress, oSelf.__uSize, MEM_COMMIT, uProtection));
      assert uBaseAddress == oSelf.__uStartAddress, \
          "Allocating reserved virtual allocation at 0x%08X allocated memory at %08X" % \
          (oSelf.__uStartAddress, uBaseAddress);
    finally:
      try:
        KERNEL32.CloseHandle(hProcess) \
            or fThrowError("CloseHandle(0x%X)" % (hProcess,));
      finally:
        oSelf.__fUpdate();
  
  def fReserve(oSelf):
    # Decommit this virtual allocation if it is committed
    assert oSelf.bAllocated, \
        "You can only reserve an allocated virtual allocation";
    hProcess = KERNEL32.OpenProcess(PROCESS_VM_OPERATION, FALSE, oSelf.__uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, 0x%08X)" % (PROCESS_VM_OPERATION, oSelf.__uProcessId,));
    try:
      KERNEL32.VirtualFreeEx(
        hProcess,
        CAST(LPVOID, oSelf.__uStartAddress), # lpAddress
        oSelf.__uSize, # dwSize
        MEM_DECOMMIT, # dwFreeType
      ) or fThrowError("VirtualFreeEx(0x%08X, 0x%08X, 0, 0x%08X)" % \
          (hProcess, oSelf.__uStartAddress, MEM_DECOMMIT,));
    finally:
      try:
        KERNEL32.CloseHandle(hProcess) \
            or fThrowError("CloseHandle(0x%X)" % (hProcess,));
      finally:
        oSelf.__fUpdate();
  
  def fFree(oSelf):
    # Free this virtual allocation if it is reserved or committed
    hProcess = KERNEL32.OpenProcess(PROCESS_VM_OPERATION, FALSE, oSelf.__uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, 0x%08X)" % (PROCESS_VM_OPERATION, oSelf.__uProcessId,));
    try:
      KERNEL32.VirtualFreeEx(
        hProcess,
        CAST(LPVOID, oSelf.__uStartAddress), # lpAddress
        0, # dwSize
        MEM_RELEASE, # dwFreeType
      ) or fThrowError("VirtualFreeEx(0x%08X, 0x%08X, 0, 0x%08X)" % \
          (hProcess, oSelf.__uStartAddress, MEM_RELEASE,));
    finally:
      try:
        KERNEL32.CloseHandle(hProcess) \
            or fThrowError("CloseHandle(0x%X)" % (hProcess,));
      finally:
        oSelf.__fUpdate();
