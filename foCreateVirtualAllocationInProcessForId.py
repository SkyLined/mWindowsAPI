from mWindowsAPI import *;

dflProtect_by_sRWE = {
  "NO ACCESS": PAGE_NOACCESS,
  "R": PAGE_READONLY,
  "RW": PAGE_READWRITE,
  "RE": PAGE_EXECUTE_READ,
  "RWE": PAGE_EXECUTE_READWRITE,
  "E": PAGE_EXECUTE,
};

def foCreateVirtualAllocationInProcessForId(uProcessId, uSize, uAddress = None, bReserved = False, bReadable = False, bWritable = False, bExecutable = False):
  sRWE = "".join([
    bReadable and "R" or "",
    bWritable and "W" or "",
    bExecutable and "E" or "",
  ]) or "NO ACCESS";
  flProtect = dflProtect_by_sRWE.get(sRWE);
  assert flProtect is not None, \
      "The combination of read/write/execute rights requested (%s) is not possible" % sRWE;
  # Try to open the process...
  hProcess = KERNEL32.OpenProcess(PROCESS_VM_OPERATION, FALSE, uProcessId);
  assert hProcess, \
      "OpenProcess(PROCESS_VM_OPERATION, FALSE, 0x%08X) => Error 0x%08X" % (uProcessId, KERNEL32.GetLastError());
  try:
    uBaseAddress = KERNEL32.VirtualAllocEx(
        hProcess,
        CAST(LPVOID, uAddress or 0), # lpAddress
        uSize, # dwSize
        bReserved and MEM_RESERVE or MEM_COMMIT, # flAllocationType
        flProtect,
    );
    if not uBaseAddress:
      uLastError = KERNEL32.GetLastError();
      # If this failed because there is not enough memory available, return None. Otherwise throw an exception.
      assert uLastError in [WIN32_FROM_HRESULT(ERROR_NOT_ENOUGH_MEMORY), WIN32_FROM_HRESULT(ERROR_COMMITMENT_LIMIT)], \
          "VirtualAllocEx(0x%08X, 0x%08X, 0x%X, MEM_COMMIT, %s) => Error 0x%08X" % (uProcessId, uAddress or 0, uSize, sRWE, uLastError);
      return None;
    # Return a cVirtualAllocation object that represents the newly allocated memory.
    return cVirtualAllocation.foGetForProcessIdAndAddress(uProcessId, uBaseAddress);
  finally:
    assert KERNEL32.CloseHandle(hProcess), \
        "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
