from mWindowsAPI import *;

class cVirtualAllocation(object):
  @staticmethod
  def foGetForProcessIdAndAddress(uProcessId, uAddress):
    hProcess = KERNEL32.OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, uProcessId);
    assert hProcess, \
        "KERNEL32.OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, %d/0x%X): 0x%X" % \
        (uProcessId, uProcessId, KERNEL32.GetLastError());
    try:
      # Accessing a virtual allocation in a 64-bit processes from 32-bit Python is theoretically possible with a few
      # hacks, but very complex and not worth the effort IMHO.
      # https://stackoverflow.com/questions/5714297/is-it-possible-to-read-process-memory-of-a-64-bit-process-from-a-32bit-app
      # For now, we simply detect this an throw an error.
      # First we find out if the OS is 64-bit, as this problem can only occur on a 64-bit OS:
      from fsGetOSISA import fsGetOSISA;
      if fsGetOSISA() == "x64":
        # Next we find out if the python process is 32-bit, as this problem can only occur in a 32-bit python process:
        from fsGetPythonISA import fsGetPythonISA;
        if fsGetPythonISA() == "x86":
          # Finally we find out if the remote process is 64-bit:
          bIsWow64Process = BOOL();
          assert KERNEL32.IsWow64Process(hProcess, POINTER(bIsWow64Process)), \
                "KERNEL32.IsWow64Process(%d/0x%X, ...): 0x%X" % \
                (uProcessId, uProcessId, uErrorCode);
          sProcessISA = bIsWow64Process and "x86" or "x64";
          # Throw an error if this is the case:
          assert sProcessISA != "x64", \
              "Accessing a virtual allocation in a 64-bit process from 32-bit Python process is not implemented";
      oMemoryBasicInformation = MEMORY_BASIC_INFORMATION();
      uStoredBytes = KERNEL32.VirtualQueryEx(
        hProcess,
        LPVOID(uAddress), # lpAddress
        POINTER(oMemoryBasicInformation), # lpBuffer,
        SIZEOF(MEMORY_BASIC_INFORMATION), # nLength
      );
      if uStoredBytes != SIZEOF(MEMORY_BASIC_INFORMATION):
        # This can fail if the address is not valid, which is acceptable.
        uErrorCode = KERNEL32.GetLastError();
        assert uErrorCode == WIN32_FROM_HRESULT(ERROR_INVALID_PARAMETER), \
            "KERNEL32.VirtualQueryEx(%d/0x%X, 0x%08X, ..., 0x%X) = 0x%X: 0x%X" % \
            (uProcessId, uProcessId, uAddress, SIZEOF(MEMORY_BASIC_INFORMATION), uStoredBytes, uErrorCode);
        return None;
      # I am not sure what the AllocationBase and AllocationProtect members are used for, so I ignore them.
      return cVirtualAllocation(
        uProcessId = uProcessId,
        uAllocationBaseAddress = oMemoryBasicInformation.AllocationBase,
        uAllocationProtection = oMemoryBasicInformation.AllocationProtect,
        uStartAddress = oMemoryBasicInformation.BaseAddress,
        uSize = oMemoryBasicInformation.RegionSize,
        uState = oMemoryBasicInformation.State,
        uProtection = oMemoryBasicInformation.Protect,
        uType = oMemoryBasicInformation.Type,
      );
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
  
  def __init__(oSelf, uProcessId, uAllocationBaseAddress, uAllocationProtection, uStartAddress, uSize, uState, uProtection, uType):
    oSelf.__uProcessId = uProcessId;
    oSelf.__uAllocationBaseAddress = uAllocationBaseAddress;
    oSelf.__uAllocationProtection = uAllocationProtection;
    oSelf.__uStartAddress = uStartAddress;
    oSelf.__uSize = uSize;
    oSelf.__uState = uState;
    oSelf.__uProtection = uProtection;
    oSelf.__uType = uType;
    oSelf.__sData = None;
    oSelf.__bFreed = False;
  
  # Allocation start address and protection
  @property
  def uAllocationBaseAddress(oSelf):
    assert not oSelf.__bFreed, \
        "This virtual allocation has been freed; you can no longer use this property";
    return oSelf.__uAllocationBaseAddress;
  @property
  def uAllocationProtection(oSelf):
    return oSelf.__uAllocationProtection;
  @property
  def sAllocationProtection(oSelf):
    return {
      PAGE_NOACCESS: "PAGE_NOACCESS",
      PAGE_READONLY: "PAGE_READONLY",
      PAGE_READWRITE: "PAGE_READWRITE",
      PAGE_WRITECOPY: "PAGE_WRITECOPY",
      PAGE_EXECUTE: "PAGE_EXECUTE",
      PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
      PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
      PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
      None: None,
    }.get(oSelf.__uAllocationProtection);

  # Start/End address and size
  @property
  def uStartAddress(oSelf):
    assert not oSelf.__bFreed, \
        "This virtual allocation has been freed; you can no longer use this property";
    return oSelf.__uStartAddress;
  
  @property
  def uSize(oSelf):
    assert not oSelf.__bFreed, \
        "This virtual allocation has been freed; you can no longer use this property";
    return oSelf.__uSize;

  @property
  def uEndAddress(oSelf):
    assert not oSelf.__bFreed, \
        "This virtual allocation has been freed; you can no longer use this property";
    return oSelf.__uStartAddress + oSelf.__uSize;
  
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
    return {
      PAGE_NOACCESS: "PAGE_NOACCESS",
      PAGE_READONLY: "PAGE_READONLY",
      PAGE_READWRITE: "PAGE_READWRITE",
      PAGE_WRITECOPY: "PAGE_WRITECOPY",
      PAGE_EXECUTE: "PAGE_EXECUTE",
      PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
      PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
      PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
      None: None,
    }.get(oSelf.__uProtection);
  
  @uProtection.setter
  def uProtection(oSelf, uNewProtection):
    assert not oSelf.__bFreed, \
        "This virtual allocation has been freed; you can  no longer set this property";
    hProcess = KERNEL32.OpenProcess(PROCESS_VM_OPERATION, FALSE, oSelf.__uProcessId);
    assert hProcess, \
        "KERNEL32.OpenProcess(PROCESS_VM_OPERATION, FALSE, %d/0x%X): 0x%X" % \
        (oSelf.__uProcessId, oSelf.__uProcessId, KERNEL32.GetLastError());
    try:
      flOldProtection = DWORD();
      assert KERNEL32.VirtualProtectEx(
        hProcess,
        LPVOID(oSelf.__uStartAddress), # lpAddress,
        SIZE_T(oSelf.__uSize), # nSize
        DWORD(uNewProtection), # flNewProtection
        PDWORD(flOldProtection), # lpflOldProtection
      ), \
          "KERNEL32.VirtualProtectEx(%d/0x%X, 0x%08X, 0x%X, 0x%08X, ...): 0x%X" % \
           (oSelf.__uProcessId, oSelf.__uProcessId, lpAddress.value, nSize.value, flNewProtection.value, KERNEL32.GetLastError());
      oSelf.__uProtection = uNewProtection;
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());

  @sProtection.setter
  def sProtection(oSelf, sNewProtection):
    assert not oSelf.__bFreed, \
        "This virtual allocation has been freed; you can  no longer set this property";
    # uNewProtection can also be one of the following strings:
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
      0: "<N/A>",
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
  def sData(oSelf):
    assert not oSelf.__bFreed, \
        "This virtual allocation has been freed; you can  no longer use this property";
    if not oSelf.__sData:
      oSelf.__sData = oSelf.fsReadDataForOffsetAndSize(0, oSelf.__uSize);
    return oSelf.__sData;
  
  def fsReadDataForOffsetAndSize(oSelf, uOffset, uSize, bUnicode = False):
    # Sanity checks
    assert oSelf.bAllocated, \
        "Cannot read memory that is not allocated!";
    assert uOffset >= 0, \
        "Offset -0x%X must be positive" % (-uOffset);
    assert uSize >= 0, \
        "Size -0x%X must be positive" % (-uSize);
    assert uOffset < oSelf.__uSize, \
        "Offset 0x%X is outside of the virtual allocation of 0x%X bytes at 0x%08X" % \
        (uOffset, oSelf.__uSize, oSelf.__uStartAddress);
    assert uOffset + uSize <= oSelf.__uSize, \
        "Offset 0x%X + size 0x%X is outside of the vrtual allocation of 0x%X bytes at 0x%08X" % \
        (uOffset, uSize, oSelf.__uSize, oSelf.__uStartAddress);
    assert not bUnicode or uSize % 2 == 0, \
        "Cannot read a Unicode string that has an odd number of bytes (%d)" % uSize;
    if oSelf.__sData:
      return oSelf.__sData[uOffset: uOffset + uSize];
    # Modify protection to make sure the pages can be read.
    uOriginalProtection = oSelf.uProtection;
    if oSelf.uProtection == PAGE_NOACCESS:
      oSelf.uProtection = PAGE_READONLY;
    elif oSelf.uProtection == PAGE_EXECUTE:
      oSelf.uProtection = PAGE_EXECUTE_READ;
    # Open process to read memory
    hProcess = KERNEL32.OpenProcess(PROCESS_VM_READ, FALSE, oSelf.__uProcessId);
    assert hProcess, \
        "KERNEL32.OpenProcess(PROCESS_VM_READ, FALSE, %d/0x%X): 0x%X" % \
        (oSelf.__uProcessId, oSelf.__uProcessId, KERNEL32.GetLastError());
    try:
      sBuffer = bUnicode and WSTR(uSize / 2) or STR(uSize);
      uBytesRead = SIZE_T(0);
      assert KERNEL32.ReadProcessMemory(
        hProcess,
        LPVOID(oSelf.__uStartAddress + uOffset), # lpBaseAddress
        POINTER(sBuffer), # lpBuffer
        SIZE_T(uSize), # nSize
        POINTER(uBytesRead), # lpNumberOfBytesRead
      ), \
          "KERNEL32.ReadProcessMemory(%d/0x%X, 0x%08X, ..., 0x%X, *0x%X): 0x%X" % \
           (oSelf.__uProcessId, oSelf.__uProcessId, lpBaseAddress.value, nSize.value, uBytesRead.value, KERNEL32.GetLastError());
      # Return read data as a string.
      if bUnicode:
        return sBuffer.value;
      return sBuffer.raw;
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
      # Restore original protection if needed
      if uOriginalProtection in [PAGE_NOACCESS, PAGE_EXECUTE]:
        oSelf.uProtection = uOriginalProtection;
  
  def fauReadDataForOffsetAndSize(oSelf, uOffset, uSize):
    sBytes = oSelf.fsReadDataForOffsetAndSize(uOffset, uSize);
    return [ord(sByte) for sByte in sBytes];
  
  def fuReadValueForOffsetAndSize(oSelf, uOffset, uSize):
    uValue = 0;
    for uByte in reversed(oSelf.fauReadDataForOffsetAndSize(uOffset, uSize)):
      uValue = (uValue << 8) + uByte;
    return uValue;
  
  def foReadStructure(oSelf, cStructure, uOffset = 0):
    return cStructure.foFromString(oSelf.fsReadDataForOffsetAndSize(uOffset, SIZEOF(cStructure)));
  
  def fDump(oSelf, sName = None):
    sName = sName or oStructureOrUnion.__class__.__name__;
    print (",--- %s " % sName).ljust(80, "-");
    print "| uAllocationBaseAddress = 0x%X" % oSelf.uAllocationBaseAddress;
    print "| uAllocationProtection  = 0x%X (%s)" % (oSelf.uAllocationProtection, oSelf.sAllocationProtection);
    print "| uStartAddress          = 0x%X" % oSelf.uStartAddress;
    print "| uSize                  = 0x%X" % oSelf.uSize;
    print "| uEndAddress            = 0x%X" % oSelf.uEndAddress;
    print "| uState                 = 0x%X (%s)" % (oSelf.uState, oSelf.sState);
    print "| uProtection            = 0x%X (%s)" % (oSelf.uProtection, oSelf.sProtection);
    print "| uType                  = 0x%X (%s)" % (oSelf.uType, oSelf.sType);
    print "'".ljust(80, "-");
  
  def fFree(oSelf):
    # Try to open the process...
    hProcess = KERNEL32.OpenProcess(PROCESS_VM_OPERATION, FALSE, oSelf.__uProcessId);
    assert hProcess, \
        "OpenProcess(PROCESS_VM_OPERATION, FALSE, 0x%08X) => Error 0x%08X" % (oSelf.__uProcessId, KERNEL32.GetLastError());
    try:
      assert KERNEL32.VirtualFreeEx(
          hProcess,
          CAST(LPVOID, oSelf.__uStartAddress), # lpAddress
          0, # dwSize
          MEM_RELEASE, # dwFreeType
      ), "VirtualFreeEx(0x%08X, 0x%08X, 0, MEM_RELEASE) => Error 0x%08X" % (oSelf.__uProcessId, uAddress, KERNEL32.GetLastError());
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
    # Mark this virtual allocation as freed
    oSelf.__uAllocationBaseAddress = None;
    oSelf.__uAllocationProtection = PAGE_NOACCESS;
    oSelf.__uStartAddress = None;
    oSelf.__uSize = None;
    oSelf.__uState = MEM_FREE;
    oSelf.__uProtection = PAGE_NOACCESS;
    oSelf.__uType = 0;
    oSelf.__sData = None;
    oSelf.__bFreed = True;