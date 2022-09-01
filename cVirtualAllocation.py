import math, struct;

from mWindowsSDK import \
  ERROR_INVALID_PARAMETER, \
  MEMORY_BASIC_INFORMATION, \
  MEM_COMMIT, MEM_DECOMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE, \
  PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_GUARD, \
  PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, \
  PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_QUERY_INFORMATION, \
  CHAR, PCHAR, WCHAR, PWCHAR, DWORD, PDWORD, LPVOID, SIZE_T;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fsHexNumber import fsHexNumber;
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

def fs0Protection(uProtection):
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
    }[uProtection & uBasicProtectionFlagsMask] if uProtection else None,
    "PAGE_GUARD" if uProtection & PAGE_GUARD else None,
  ] if s]) or None;

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
  uPageSize = oSystemInfo.uPageSize;
  @staticmethod
  def fo0CreateForProcessIdAndString(
    uProcessId,
    sString,
    bUnicode = False,
    uAddress = None,
    uProtection = None,
  ):
    o0VirtualAllocation = cVirtualAllocation.fo0CreateForProcessId(
      uProcessId = uProcessId,
      uSize = len(sString) * (bUnicode and 2 or 1),
      uAddress = uAddress,
      uProtection = uProtection,
    );
    if o0VirtualAllocation:
      o0VirtualAllocation.fWriteStringForOffset(
        sString = sString,
        uOffset = 0,
        bUnicode = bUnicode
      );
    return o0VirtualAllocation;
  @staticmethod
  def fo0CreateForProcessId(
    uProcessId,
    uSize,
    uAddress = 0,
    bReserved = False,
    uProtection = None,
  ):
    if uProtection is None:
      uProtection = PAGE_NOACCESS;
    else:
      assert fs0Protection(uProtection) is not None, \
          "Unknown uProtection values %s" % fsHexNumber(uProtection);
    # Try to open the process...
    ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_VM_OPERATION);
    try:
      opBaseAddress = oKernel32DLL.VirtualAllocEx(
          ohProcess,
          LPVOID(uAddress), # lpAddress
          uSize, # dwSize
          MEM_COMMIT if not bReserved else MEM_RESERVE, # flAllocationType
          uProtection, # flProtect
      );
      if opBaseAddress.fbIsNULLPointer():
        fThrowLastError("VirtualAllocEx(%s, %s, %s, MEM_COMMIT, %s)" % (
          repr(ohProcess),
          fsHexNumber(uAddress),
          fsHexNumber(uSize),
          fs0Protection(uProtection) or fsHexNumber(uProtection),
        ));
      # Return a cVirtualAllocation object that represents the newly allocated memory.
      oVirtualAllocation = cVirtualAllocation(uProcessId, opBaseAddress.fuGetValue());
      if not oVirtualAllocation.bIsValid:
        return None; # invalid address.
      return oVirtualAllocation;
    finally:
      if not oKernel32DLL.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  
  def __init__(oSelf, uProcessId, uAddress):
    oSelf.__uProcessId = uProcessId;
    oSelf.__uUserProvidedAddress = uAddress;
    # Accessing a virtual allocation in a 64-bit processes from 32-bit Python is theoretically possible with a few
    # hacks, but very complex and not worth the effort IMHO.
    # https://stackoverflow.com/questions/5714297/is-it-possible-to-read-process-memory-of-a-64-bit-process-from-a-32bit-app
    # For now, we simply detect this an throw an error.
    # First we find out if the OS is 64-bit, as this problem can only occur on a 64-bit OS:
    oSelf.__u0PointerSize = None;
    oSelf.__fUpdate(uAddress);
  
  @property
  def uPointerSize(oSelf):
    if oSelf.__u0PointerSize is None:
      oSelf.__fUpdate();
    return oSelf.__u0PointerSize;
  
  def __fUpdate(oSelf, u0Address = None):
    # Address is only supplied the first time (by __init__). After that, we know the start address and use that:
    uAddress = (
      u0Address if u0Address is not None
      else oSelf.__uUserProvidedAddress if not (oSelf.bIsValid or oSelf.bIsFree)
      else oSelf.__u0StartAddress
    );
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_QUERY_INFORMATION);
    if oSelf.__u0PointerSize is None:
      if oSystemInfo.sOSISA == "x86":
        sProcessISA = "x86";
      else:
        # Finally we find out if the remote process is 64-bit:
        sProcessISA = fsGetISAForProcessHandle(ohProcess);
        # Throw an error if this is the case:
        assert fsGetPythonISA() == "x64" or sProcessISA != "x64", \
            "Accessing a virtual allocation in a 64-bit process from 32-bit Python process is not implemented";
        # Next we find out if the python process is 32-bit, as this problem can only occur in a 32-bit python process:
      oSelf.__u0PointerSize = {"x86": 4, "x64": 8}[sProcessISA];
    assert 0 <= uAddress < (1 << (oSelf.__u0PointerSize * 8)), \
        "uAddress %s is not a valid %d-bit pointer!" % (fsHexNumber(uAddress), oSelf.__u0PointerSize * 8);
    try:
      oMemoryBasicInformation = MEMORY_BASIC_INFORMATION();
      oStoredBytes = oKernel32DLL.VirtualQueryEx(
        ohProcess,
        uAddress, # lpAddress
        oMemoryBasicInformation.foCreatePointer(), # lpBuffer,
        MEMORY_BASIC_INFORMATION.fuGetSize(), # nLength
      );
      # This can fail if the address is not valid, which is acceptable.
      oSelf.bIsValid = oStoredBytes == MEMORY_BASIC_INFORMATION.fuGetSize();
      if not oSelf.bIsValid:
        if not fbLastErrorIs(ERROR_INVALID_PARAMETER):
          fThrowLastError("VirtualQueryEx(%s, %s, ..., %s) = %s" % (
            repr(ohProcess),
            fsHexNumber(uAddress),
            fsHexNumber(MEMORY_BASIC_INFORMATION.fuGetSize()),
            repr(oStoredBytes),
          ));
        oSelf.__u0State = None;
        oSelf.__u0AllocationBaseAddress = None;
        oSelf.__u0AllocationProtection = None;
        oSelf.__u0StartAddress = None;
        oSelf.__u0Size = None;
        oSelf.__u0Protection = None;
        oSelf.__u0Type = None;
      else:
        oSelf.__u0State = oMemoryBasicInformation.State.fuGetValue();
        oSelf.__u0AllocationBaseAddress = oMemoryBasicInformation.AllocationBase.fuGetValue();
        oSelf.__u0AllocationProtection = oMemoryBasicInformation.AllocationProtect.fuGetValue();
        oSelf.__u0StartAddress = oMemoryBasicInformation.BaseAddress.fuGetValue();
        oSelf.__u0Size = oMemoryBasicInformation.RegionSize.fuGetValue();
        oSelf.__u0Protection = oMemoryBasicInformation.Protect.fuGetValue();
        oSelf.__u0Type = oMemoryBasicInformation.Type.fuGetValue();
    finally:
      if not oKernel32DLL.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  
  def fbContainsAddress(oSelf, uAddress, uSize = 1):
    assert oSelf.bIsValid, \
        "The virtual allocation is not valid, please check 'oSelf.bIsValid' before making this call!";
    return (
      not oSelf.bFree
      and oSelf.__u0StartAddress <= uAddress
      and oSelf.uEndAddress >= uAddress + uSize
    );
  
  # Process id
  @property
  def uProcessId(oSelf):
    return oSelf.__uProcessId;
  
  # Allocation start address and protection
  @property
  def uAllocationBaseAddress(oSelf):
    assert oSelf.bIsValid and not oSelf.bFree, \
        "Virtual Allocation %s is %s, please check 'oSelf.%s' before making this call!" % \
        (oSelf, "free" if oSelf.bIsValid else "not valid", "bFree" if oSelf.bIsValid else "bIsValid");
    return oSelf.__u0AllocationBaseAddress;
  @property
  def uAllocationProtection(oSelf):
    assert oSelf.bIsValid and not oSelf.bFree, \
        "Virtual Allocation %s is %s, please check 'oSelf.%s' before making this call!" % \
        (oSelf, "free" if oSelf.bIsValid else "not valid", "bFree" if oSelf.bIsValid else "bIsValid");
    return oSelf.__u0AllocationProtection;
  @property
  def sAllocationProtection(oSelf):
    return fs0Protection(oSelf.__u0AllocationProtection) or fsHexNumber("0x%X");
  
  # Start/End address and size
  @property
  def uAddress(oSelf):
    assert oSelf.bIsValid, \
        "The virtual allocation is not valid, please check 'oSelf.bIsValid' before making this call!";
    return oSelf.__u0StartAddress;
  @property
  def uStartAddress(oSelf):
    assert oSelf.bIsValid, \
        "The virtual allocation is not valid, please check 'oSelf.bIsValid' before making this call!";
    return oSelf.__u0StartAddress;
  @property
  def uSize(oSelf):
    assert oSelf.bIsValid, \
        "The virtual allocation is not valid, please check 'oSelf.bIsValid' before making this call!";
    return oSelf.__u0Size;
  @property
  def uEndAddress(oSelf):
    assert oSelf.bIsValid, \
        "The virtual allocation is not valid, please check 'oSelf.bIsValid' before making this call!";
    return oSelf.__u0StartAddress + oSelf.__u0Size;
  
  # State
  @property
  def uState(oSelf):
    assert oSelf.bIsValid, \
        "The virtual allocation is not valid, please check 'oSelf.bIsValid' before making this call!";
    return oSelf.__u0State;
  @property
  def sState(oSelf):
    return {
      MEM_COMMIT: "MEM_COMMIT",
      MEM_FREE: "MEM_FREE",
      MEM_RESERVE: "MEM_RESERVE",
      None: None,
    }[oSelf.uState];
  @property
  def bAllocated(oSelf):
    return oSelf.bIsValid and oSelf.uState == MEM_COMMIT;
  @property
  def bReserved(oSelf):
    return oSelf.bIsValid and oSelf.uState == MEM_RESERVE;
  @property
  def bFree(oSelf):
    return oSelf.bIsValid and oSelf.uState == MEM_FREE;
  @property
  def bInvalid(oSelf):
    return not oSelf.bIsValid;
  
  # Protection
  @property
  def uProtection(oSelf):
    assert oSelf.bIsValid and not oSelf.bFree, \
        "Virtual allocation %s is %s, please check 'oSelf.%s' before making this call!" % \
        (oSelf, "free" if oSelf.bIsValid else "not valid", "bFree" if oSelf.bIsValid else "bIsValid");
    return oSelf.__u0Protection;
  @property
  def sProtection(oSelf):
   # Only mentions "basic" access protection flags! (not PAGE_GUARD, etc.)
    return fs0Protection(oSelf.uProtection) or fsHexNumber(oSelf.uProtection);
  
  @property
  def bReadable(oSelf):
    return oSelf.bAllocated and not oSelf.bGuard and "read" in fasAllowedAccessTypesForProtection(oSelf.uProtection);
  @property
  def bWritable(oSelf):
    return oSelf.bAllocated and not oSelf.bGuard and "write" in fasAllowedAccessTypesForProtection(oSelf.uProtection);
  @property
  def bExecutable(oSelf):
    return oSelf.bAllocated and not oSelf.bGuard and "execute" in fasAllowedAccessTypesForProtection(oSelf.uProtection);
  @property
  def bGuard(oSelf):
    return oSelf.bAllocated and (oSelf.uAllocationProtection & PAGE_GUARD);
  
  @uProtection.setter
  def uProtection(oSelf, uNewProtection):
    assert oSelf.bIsValid and not oSelf.bFree, \
        "Virtual Allocation %s is %s, please check 'oSelf.%s' before making this call!" % \
        (oSelf, "free" if oSelf.bIsValid else "not valid", "bFree" if oSelf.bIsValid else "bIsValid");
    assert isinstance(uNewProtection, int) and uNewProtection > 0, \
        "Cannot set uProtection to %s" % repr(uNewProtection);
    assert oSelf.bAllocated, \
        "Cannot modify protection on a virtual allocation that is not allocated";
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_OPERATION);
    try:
      flOldProtection = DWORD(0);
      if not oKernel32DLL.VirtualProtectEx(
        ohProcess,
        LPVOID(oSelf.__u0StartAddress), # lpAddress,
        SIZE_T(oSelf.__u0Size), # nSize
        DWORD(uNewProtection), # flNewProtection
        PDWORD(flOldProtection), # lpflOldProtection
      ):
        fThrowLastError("VirtualProtectEx(%s, %s, %s, %s, &(%s))" % (
          repr(ohProcess),
          fsHexNumber(oSelf.__u0StartAddress),
          fsHexNumber(oSelf.__u0Size),
          fsHexNumber(uNewProtection),
          fsHexNumber(flOldProtection.fuGetValue()),
        ));
      oSelf.__u0Protection = uNewProtection;
    finally:
      if not oKernel32DLL.CloseHandle(ohProcess):
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
    assert oSelf.bIsValid, \
        "Virtual Allocation %s is not valid, please check 'oSelf.bIsValid' before making this call!" % (oSelf,);
    return oSelf.__u0Type;
  @property
  def sType(oSelf):
    return {
      MEM_IMAGE: "MEM_IMAGE",
      MEM_MAPPED: "MEM_MAPPED",
      MEM_PRIVATE: "MEM_PRIVATE",
      None: None,
    }[oSelf.uType];
  @property
  def bImage(oSelf):
    return oSelf.uType == MEM_IMAGE;
  @property
  def bMapped(oSelf):
    return oSelf.uType == MEM_MAPPED;
  @property
  def bPrivate(oSelf):
    return oSelf.uType == MEM_PRIVATE;
  
  def fsbReadBytesStringForOffsetAndSize(oSelf, uOffset, uSize):
    # Read bytes without NULL terminator.
    return oSelf.fsReadStringForOffsetAndLength(uOffset, uSize, bUnicode = False, bNullTerminated = False, bBytes = True);
  def fsReadStringForOffsetAndLength(oSelf, uOffset, uLength, bUnicode = False, bNullTerminated = False, bBytes = False):
    assert oSelf.bIsValid, \
        "Please check .bIsValid == True before making this call";
    assert oSelf.bAllocated, \
        "Please check .bAllocated == True before making this call";
    assert not bUnicode or not bBytes, \
        "Unicode strings cannot be returned as a string of bytes";
    # Sanity checks
    uSize = uLength * (2 if bUnicode else 1);
    assert uOffset >= 0, \
        "Offset %s must be positive" % fsHexNumber(uOffset);
    assert uLength >= 0, \
        "uLength %s must be positive" % fsHexNumber(uLength);
    assert uOffset < oSelf.__u0Size, \
        "Offset %s is outside of the virtual allocation of %s bytes at %s" % \
        (fsHexNumber(uOffset), fsHexNumber(oSelf.__u0Size), fsHexNumber(oSelf.__u0StartAddress));
    assert uOffset + uSize <= oSelf.__u0Size, \
        "Offset %s + size %s is outside of the virtual allocation of %s bytes at %s" % \
        (fsHexNumber(uOffset), fsHexNumber(uSize), fsHexNumber(oSelf.__u0Size), fsHexNumber(oSelf.__u0StartAddress));
    # If needed, modify the protection to make sure the pages can be read.
    uOriginalProtection = oSelf.uProtection;
    if oSelf.uProtection not in [
      PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY
    ]:
      # Temporarily allow reading from this page.
      try:
        oSelf.uProtection = PAGE_READONLY;
      except Exception as oException:
        if isinstance(oException.args[0], str):
          oException.args[0] += " (oVirtualAllocation = %s)" % repr(oSelf);
        raise;
    try:
      # Open process to read memory
      ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_READ);
      try:
        osMemoryBuffer = (WCHAR if bUnicode else CHAR)[uLength]();
        ouBytesRead = SIZE_T(0);
        opsMemoryBuffer = LPVOID(osMemoryBuffer, bCast = True);
        opuBytesRead = ouBytesRead.foCreatePointer();
        if not oKernel32DLL.ReadProcessMemory(
          ohProcess,
          oSelf.__u0StartAddress + uOffset, # lpBaseAddress
          opsMemoryBuffer, # lpBuffer
          uSize, # nSize
          opuBytesRead, # lpNumberOfBytesRead
        ):
          fThrowLastError("ReadProcessMemory(%s, %s+%s, %s, %s, %s)" % (
            repr(ohProcess),
            fsHexNumber(oSelf.__u0StartAddress),
            fsHexNumber(uOffset),
            repr(opsMemoryBuffer),
            fsHexNumber(uSize),
            repr(opuBytesRead))
          );
        assert ouBytesRead == uSize, \
            "ReadProcessMemory(%s, %s+%s, %s, %s, %s) => %s bytes read" % (
              repr(ohProcess),
              fsHexNumber(oSelf.__u0StartAddress),
              fsHexNumber(uOffset),
              repr(opsMemoryBuffer),
              fsHexNumber(uSize),
              repr(opuBytesRead),
              fsHexNumber(ouBytesRead.fuGetValue()),
            );
        # Return all of the data in the appropriate type if we do not need to look for a '\0' terminator.
        if not bNullTerminated:
          return osMemoryBuffer.fsbGetValue() if bBytes else osMemoryBuffer.fsGetValue();
        # Look for a '\0' terminator and assert if none is found.
        x0String = osMemoryBuffer.fsb0GetNullTerminatedBytesString() if bBytes else osMemoryBuffer.fs0GetNullTerminatedString();
        assert x0String, \
            "The %s string at address %s in process %d/0x%X is not NULL terminated: %s." % (
              fsHexNumber(oSelf.__u0StartAddress + uOffset),
              oSelf.__uProcessId, oSelf.__uProcessId,
              repr(osMemoryBuffer.sbGetValue()),
            );
        # Return part of the data in the appropriate type up until, but not including, the '\0' terminator.
        return x0String;
      finally:
        if not oKernel32DLL.CloseHandle(ohProcess):
          fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
    finally:
      # Restore original protection if needed
      if oSelf.uProtection != uOriginalProtection:
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
      uLength = math.ceil(uSize / uCharSize);
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
    sbBytes = oSelf.fsbReadBytesStringForOffsetAndSize(uOffset, uCount * uSize);
    sUnpackValueFormat = {1: "B", 2: "H", 4: "L", 8: "Q"}.get(uSize);
    assert sUnpackValueFormat, \
        "Unsupported size %d (try 1,2,4 or 8)" % uSize;
    return struct.unpack("<%s" % (sUnpackValueFormat * uCount), sbBytes);
  
  def fauReadBytesForOffsetAndSize(oSelf, uOffset, uSize):
    # Read `uSize` values of 1 byte:
    return [int(uByte) for uByte in oSelf.fsbReadBytesStringForOffsetAndSize(uOffset, uSize)];
  
  def fuReadValueForOffsetAndSize(oSelf, uOffset, uSize):
    # Read 1 values of `uSize` byte:
    return oSelf.fauReadValuesForOffsetSizeAndCount(uOffset, uSize, 1)[0];
  
  def fuReadPointerForOffset(oSelf, uOffset):
    # Read 1 value of `uPointerSize` bytes
    return oSelf.fauReadValuesForOffsetAndSize(uOffset, oSelf.uPointerSize, 1)[0];
  
  def fauReadPointersForOffsetAndCount(oSelf, uOffset, uCount):
    # Read `uCount` values of `uPointerSize` bytes
    return oSelf.fauReadValuesForOffsetSizeAndCount(uOffset, oSelf.uPointerSize, uCount);
  
  def foReadStructureForOffset(oSelf, cStructure, uOffset):
    sbData = oSelf.fsbReadBytesStringForOffsetAndSize(uOffset, cStructure.fuGetSize());
    return cStructure.foFromBytesString(sbData);
  
  def fWriteBytesForOffset(oSelf, sBytes, uOffset):
    return oSelf.fWriteStringForOffset(sBytes, uOffset, bUnicode = False);
  def fWriteStringForOffset(oSelf, sString, uOffset, bUnicode = False):
    assert oSelf.bAllocated, \
        "Please check .bAllocated == True before making this call";
    # Sanity checks
    assert uOffset >= 0, \
        "Offset %s must be positive" % fsHexNumber(uOffset);
    uSize = len(sString) * (bUnicode and 2 or 1);
    assert uSize, \
        "You must supply data to write";
    assert uOffset < oSelf.__u0Size, \
        "Offset %s is outside of the virtual allocation of %s bytes at %s" % \
        (fsHexNumber(uOffset), fsHexNumber(oSelf.__u0Size), fsHexNumber(oSelf.__u0StartAddress));
    assert uOffset + uSize <= oSelf.__u0Size, \
        "Offset %s + string size (%s) is outside of the virtual allocation of %s bytes at %s" % \
        (fsHexNumber(uOffset), fsHexNumber(uSize), fsHexNumber(oSelf.__u0Size), fsHexNumber(oSelf.__u0StartAddress));
    # Modify protection to make sure the pages can be read.
    uOriginalProtection = oSelf.uProtection;
    if oSelf.uProtection not in [
      PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    ]:
      oSelf.uProtection = PAGE_READWRITE;
    try:
      # Open process to read memory
      ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
      try:
        oBuffer = (PWCHAR if bUnicode else PCHAR)(sString);
        ouBytesWritten = SIZE_T(0);
        if not oKernel32DLL.WriteProcessMemory(
          ohProcess,
          oSelf.__u0StartAddress + uOffset, # lpBaseAddress
          LPVOID(oBuffer, bCast = True), # lpBuffer
          uSize, # nSize
          ouBytesWritten.foCreatePointer(), # lpNumberOfBytesRead
        ):
          fThrowLastError("WriteProcessMemory(%s, %s, ..., %s, ...)" % (
            repr(ohProcess),
            fsHexNumber(oSelf.__u0StartAddress + uOffset),
            fsHexNumber(uSize),
          ));
        assert ouBytesWritten == uSize, \
            "WriteProcessMemory(%s, %s, ..., %s, ...) => %s bytes written" % (
              repr(ohProcess),
              fsHexNumber(oSelf.__u0StartAddress + uOffset),
              fsHexNumber(uSize),
              fsHexNumber(ouBytesWritten.fuGetValue(),
            ));
      finally:
        if not oKernel32DLL.CloseHandle(ohProcess):
          fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
    finally:
      # Restore original protection if needed
      if oSelf.uProtection != uOriginalProtection:
        oSelf.uProtection = uOriginalProtection;
  
  def fasDump(oSelf):
    if not oSelf.bIsValid or oSelf.bFree:
      return [
        "uUserAddress           = %s (%s)" % fsHexNumber((oSelf.__uUserProvidedAddress), "free" if oSelf.bIsValid else "invalid"),
      ];
    return [
      "uAllocationBaseAddress = %s" % (fsHexNumber(oSelf.uAllocationBaseAddress),),
      "uAllocationProtection  = %s (%s)" % (fsHexNumber(oSelf.uAllocationProtection), oSelf.sAllocationProtection),
      "uStartAddress          = %s" % (fsHexNumber(oSelf.uStartAddress),),
      "uSize                  = %s" % (fsHexNumber(oSelf.uSize),),
      "uEndAddress            = %s" % (fsHexNumber(oSelf.uEndAddress),),
      "uState                 = %s (%s)" % (fsHexNumber(oSelf.uState), oSelf.sState),
      "uProtection            = %s (%s)" % (fsHexNumber(oSelf.uProtection), oSelf.sProtection),
      "uType                  = %s (%s)" % (fsHexNumber(oSelf.uType), oSelf.sType),
    ];
  def fasDumpContents(oSelf, uStartOffset = 0, u0EndOffset = None, u0Size = None, uWordSize = 1):
    assert uStartOffset >= 0, \
        "uStartOffset (%s) must not be negative" % (
          fsHexNumber(uStartOffset),
        );
    assert uStartOffset < oSelf.uSize, \
        "uStartOffset (%s) must not be greater than the size of the virtual memory (%s)" % (
          fsHexNumber(uStartOffset), fsHexNumber(oSelf.uSize),
        );
    if u0EndOffset is not None:
      assert u0Size is None, \
        "u0EndOffset (%s) and u0Size (%s) must not both be provided" % (
          fsHexNumber(u0EndOffset), fsHexNumber(u0Size),
        );
      assert u0EndOffset <= oSelf.uSize, \
        "u0EndOffset (%s) must not be greater than the size of the virtual memory (%s)" % (
          fsHexNumber(u0EndOffset), fsHexNumber(oSelf.uSize),
        );
      assert u0EndOffset > uStartOffset, \
        "u0EndOffset (%s) must be greater than uStartOffset (%s)" % (
          fsHexNumber(u0EndOffset), fsHexNumber(uStartOffset),
        );
      uSize = u0EndOffset - uStartOffset;
    elif u0Size is not None:
      assert u0Size > 0, \
        "u0Size (%s) must be larger than 0" % (
          fsHexNumber(u0Size),
        );
      assert u0Size <= oSelf.uSize, \
        "u0Size (%s) must not be greater than the size of the virtual memory (%s)" % (
          fsHexNumber(u0Size), fsHexNumber(oSelf.uSize),
        );
      uSize = u0Size;
    else:
      uSize = oSelf.uSize - uStartOffset;
    uBytesPerLine = 32;
    asContents = [("┌──[ %s offset %s - %s " % (
      fsHexNumber(oSelf.uStartAddress),
      fsHexNumber(uStartOffset),
      fsHexNumber(uStartOffset + uSize),
    )).ljust(80, "─")];
    asHexWordsBuffer = [""];
    uCurrentWordSize = 0;
    sCharsBuffer = "";
    uCurrentOffset = uLineStartOffset = uStartOffset;
    def fCopyBuffersToResult():
      asContents.append("│ %4X  %s  %s" % (
        uLineStartOffset,
        " ".join(asHexWordsBuffer).ljust(uBytesPerLine * 3 - 1),
        sCharsBuffer),
      );
    for uByte in oSelf.fauReadBytesForOffsetAndSize(uStartOffset, uSize):
      sCharsBuffer += chr(uByte) if 0x20 <= uByte <= 0x7E else ".";
      uCurrentOffset += 1;
      asHexWordsBuffer[-1] = ("%02X" % uByte) + asHexWordsBuffer[-1];
      uCurrentWordSize += 1;
      if uCurrentWordSize >= uWordSize:
        uCurrentWordSize = 0;
        if len(sCharsBuffer) < uBytesPerLine:
          asHexWordsBuffer.append("");
        else:
          fCopyBuffersToResult();
          asHexWordsBuffer = [""];
          sCharsBuffer = "";
          uLineStartOffset = uCurrentOffset;
      elif uCurrentWordSize % 4 == 0:
        asHexWordsBuffer[-1] = "`" + asHexWordsBuffer[-1];
    if len(sCharsBuffer) != 0:
      while uCurrentWordSize < uWordSize:
        asHexWordsBuffer[-1] = "  " + asHexWordsBuffer[-1];
        uCurrentWordSize += 1;
      fCopyBuffersToResult();
    return asContents + ["└".ljust(80, "─")];
  
  def fCommit(oSelf, uProtection = None):
    # This function can be used to commit memory to a reserved virtual allocation.
    # It cannot be used on a freed virtual allocation; since it has no size defined.
    assert oSelf.bIsValid and not oSelf.bFree, \
        "Virtual Allocation %s is %s, please check 'oSelf.%s' before making this call!" % \
        (oSelf, "free" if oSelf.bIsValid else "not valid", "bFree" if oSelf.bIsValid else "bIsValid");
    # Commit this virtual allocation if it is reserved
    assert oSelf.bReserved, \
        "You can only allocate a reserved virtual allocation";
    if uProtection is None:
      uProtection = PAGE_NOACCESS;
    else:
      assert fs0Protection(uProtection) is not None, \
          "Unknown uProtection values %s" % (fsHexNumber(uProtection),);
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_OPERATION);
    try:
      opBaseAddress = oKernel32DLL.VirtualAllocEx(
        ohProcess,
        LPVOID(oSelf.__u0StartAddress), # lpAddress
        oSelf.__u0Size, # dwSize
        MEM_COMMIT, # flAllocationType
        uProtection, # flProtect
      );
      if opBaseAddress.fbIsNULLPointer():
        fThrowLastError("VirtualAllocEx(%s, %s, %s, MEM_COMMIT, %s)" % (
          repr(ohProcess),
          fsHexNumber(oSelf.__u0StartAddress),
          fsHexNumber(oSelf.__u0Size),
          fsHexNumber(uProtection),
        ));
      uBaseAddress = opBaseAddress.fuGetValue();
      assert uBaseAddress == oSelf.__u0StartAddress, \
          "Allocating reserved virtual allocation at 0x%08X allocated memory at %08X" % \
          (oSelf.__u0StartAddress, uBaseAddress);
    finally:
      try:
        if not oKernel32DLL.CloseHandle(ohProcess):
          fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
      finally:
        oSelf.__fUpdate();
  
  def fReserve(oSelf):
    assert oSelf.bIsValid and not oSelf.bFree, \
        "Virtual Allocation %s is %s, please check 'oSelf.%s' before making this call!" % \
        (oSelf, "free" if oSelf.bIsValid else "not valid", "bFree" if oSelf.bIsValid else "bIsValid");
    # Decommit this virtual allocation if it is committed
    assert oSelf.bAllocated, \
        "You can only reserve an allocated virtual allocation";
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_OPERATION);
    try:
      if not oKernel32DLL.VirtualFreeEx(
        ohProcess,
        LPVOID(oSelf.__u0StartAddress), # lpAddress
        oSelf.__u0Size, # dwSize
        MEM_DECOMMIT, # dwFreeType
      ):
        fThrowLastError("VirtualFreeEx(%s, %s, 0, %s)" % (
          repr(ohProcess),
          fsHexNumber(oSelf.__u0StartAddress),
          fsHexNumber(MEM_DECOMMIT),
        ));
    finally:
      try:
        if not oKernel32DLL.CloseHandle(ohProcess):
          fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
      finally:
        oSelf.__fUpdate();
  
  def fFree(oSelf):
    assert oSelf.bIsValid, \
        "The virtual allocation is not valid, please check 'oSelf.bIsValid' before making this call!";
    # Free this virtual allocation if it is reserved or committed
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.__uProcessId, PROCESS_VM_OPERATION);
    try:
      if not oKernel32DLL.VirtualFreeEx(
        ohProcess,
        LPVOID(oSelf.__u0StartAddress), # lpAddress
        0, # dwSize
        MEM_RELEASE, # dwFreeType
      ):
        fThrowLastError("VirtualFreeEx(%s, %s, 0, %s)" % (
          repr(ohProcess),
          fsHexNumber(oSelf.__u0StartAddress),
          fsHexNumber(MEM_RELEASE),
        ));
    finally:
      try:
        if not oKernel32DLL.CloseHandle(ohProcess):
          fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
      finally:
        oSelf.__fUpdate();
  
  def __repr__(oSelf):
    return "<%s at 0x%X>" % (oSelf, id(oSelf));
  def __str__(oSelf):
    return "VirtualAllocation(%s)" % (
      "Invalid @ %s" % (
        fsHexNumber(oSelf.__uUserProvidedAddress),
      ) if not oSelf.bIsValid else 
      "Free @ %s, [%s-%s] (%s bytes)" % (
        fsHexNumber(oSelf.__uUserProvidedAddress),
        fsHexNumber(oSelf.__u0StartAddress) if oSelf.__u0StartAddress else "??",
        fsHexNumber(oSelf.__u0StartAddress + oSelf.__u0Size) if oSelf.__u0StartAddress and oSelf.__u0Size else "??",
        fsHexNumber(oSelf.__u0Size) if oSelf.__u0Size else "??",
      ) if oSelf.bFree else
      "Reserved, base @ %s, [%s-%s] (%s bytes)" % (
        fsHexNumber(oSelf.uAllocationBaseAddress),
        fsHexNumber(oSelf.__u0StartAddress) if oSelf.__u0StartAddress else "??",
        fsHexNumber(oSelf.__u0StartAddress + oSelf.__u0Size) if oSelf.__u0StartAddress and oSelf.__u0Size else "??",
        fsHexNumber(oSelf.__u0Size) if oSelf.__u0Size else "??",
      ) if oSelf.bReserved else
      "Allocated, uState=%s, uType=%s, base @ %s, [%s-%s] (%s bytes, uProtection = %s%s)" % (
        oSelf.sState,
        oSelf.sType,
        fsHexNumber(oSelf.uAllocationBaseAddress),
        fsHexNumber(oSelf.__u0StartAddress) if oSelf.__u0StartAddress else "??",
        fsHexNumber(oSelf.__u0StartAddress + oSelf.__u0Size) if oSelf.__u0StartAddress and oSelf.__u0Size else "??",
        fsHexNumber(oSelf.__u0Size) if oSelf.__u0Size else "??",
        "PAGE_GUARD | " if oSelf.bGuard else "",
        oSelf.sProtection,
      )
    );
    