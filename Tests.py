import os, sys, subprocess;

sModuleFolderPath = os.path.dirname(os.path.abspath(__file__));
sBaseFolderPath = os.path.dirname(sModuleFolderPath);
sys.path.extend([
  sBaseFolderPath,
  sModuleFolderPath,
  os.path.join(sModuleFolderPath, "modules"),
]);

from mWindowsAPI import *;

if __name__ == "__main__":
  # Test console functions
  print "* Testing KERNEL32 console functions...";
  hStdOut = KERNEL32.GetStdHandle(STD_OUTPUT_HANDLE);
  oConsoleScreenBufferInfo = CONSOLE_SCREEN_BUFFER_INFO();
  assert KERNEL32.GetConsoleScreenBufferInfo(hStdOut, PCONSOLE_SCREEN_BUFFER_INFO(oConsoleScreenBufferInfo)), \
      "GetConsoleScreenBufferInfo(0x%08X, ...) => Error 0x%08X" % \
      (hStdOut, KERNEL32.GetLastError());
  uOriginalColor = oConsoleScreenBufferInfo.wAttributes & 0xFF;
  uTestColor = (uOriginalColor & 0xF0) | 0x0A; # Bright green foreground, keep same background.
  assert KERNEL32.SetConsoleTextAttribute(hStdOut, uTestColor), \
      "SetConsoleTextAttribute(0x%08X, 0x%02X) => Error 0x%08X" % \
      (hStdOut, uTestColor, KERNEL32.GetLastError());
  print "  * This should be green.";
  assert KERNEL32.SetConsoleTextAttribute(hStdOut, uOriginalColor), \
      "SetConsoleTextAttribute(0x%08X, 0x%02X) => Error 0x%08X" % \
      (hStdOut, uOriginalColor, KERNEL32.GetLastError());
  
  print "* Testing process functions...";
  # Test process functions
  oNotepadProcess = subprocess.Popen("notepad.exe");
  print "  + Started notepad process %d..." % oNotepadProcess.pid;
  try:
    # cProcessInformation
    print "  * Testing cProcessInformation...";
    oProcessInformation = cProcessInformation.foGetForId(oNotepadProcess.pid);
    print "    + ISA = %s" % repr(oProcessInformation.sISA);
    print "    + Binary start address = 0x%08X" % oProcessInformation.uBinaryStartAddress;
    print "    + Binary Path = %s" % repr(oProcessInformation.sBinaryPath);
    print "    + Command line = %s" % repr(oProcessInformation.sCommandLine);
    # cVirtualAllocation
    oBinaryVirtualAllocation = cVirtualAllocation.foGetForProcessIdAndAddress( \
        oNotepadProcess.pid, oProcessInformation.uBinaryStartAddress);
    assert oBinaryVirtualAllocation.bAllocated, \
        "Expected memory to be allocated at address 0x%08X" % oProcessInformation.uBinaryStartAddress;
    assert oBinaryVirtualAllocation.uStartAddress == oProcessInformation.uBinaryStartAddress, \
        "Expected binary virtual allocation to start at address 0x%08X, not 0x%08X" % \
          (oProcessInformation.uBinaryStartAddress, oBinaryVirtualAllocation.uStartAddress);
    print "    + There are 0x%X bytes of memory allocated at address 0x%08X." % \
        (oBinaryVirtualAllocation.uSize, oBinaryVirtualAllocation.uStartAddress);
    
    # fdsProcessesExecutableName_by_uId (make sure notepad.exe is included)
    print "  * Testing fdsProcessesExecutableName_by_uId...";
    dsProcessesExecutableName_by_uId = fdsProcessesExecutableName_by_uId();
    sProcessesExecutableName = dsProcessesExecutableName_by_uId.get(oNotepadProcess.pid);
    assert sProcessesExecutableName, \
        "Notepad.exe process %d not found in process list!" % oNotepadProcess.pid;
    assert sProcessesExecutableName == "notepad.exe", \
        "Notepad.exe process %d is reported to run %s" % sProcessesExecutableName;
    # fuGetProcessIntegrityLevelForId
    print "  * Testing fuGetProcessIntegrityLevelForId...";
    uProcessIntegrityLevel = fuGetProcessIntegrityLevelForId(oNotepadProcess.pid);
    assert uProcessIntegrityLevel is not None, \
        "Notepad.exe process %d integrity level could not be determined!" % oNotepadProcess.pid;
    print "    + IntegrityLevel = 0x%X." % uProcessIntegrityLevel;
    # fuGetProcessMemoryUsage
    # foCreateVirtualAllocationInProcessForId
    # cVirtualAllocation
    print "  * Testing Memory management functions...";
    uProcessMemoryUsage = fuGetProcessMemoryUsage(oNotepadProcess.pid);
    print "    + Memory usage = 0x%X." % uProcessMemoryUsage;
    uMemoryAllocationSize = 0x1234000;
    oVirtualAllocation = foCreateVirtualAllocationInProcessForId(oNotepadProcess.pid, uMemoryAllocationSize);
    assert oVirtualAllocation is not None, \
        "Attempt to allocate 0x%X bytes failed" % uMemoryAllocationSize;
    assert oVirtualAllocation.uSize == uMemoryAllocationSize, \
        "Attempted to allocate 0x%X bytes, but got 0x%X" % (uMemoryAllocationSize, oVirtualAllocation.uSize);
    uProcessMemoryUsageAfterAllocation = fuGetProcessMemoryUsage(oNotepadProcess.pid);
    print "    + Memory usage after allocating 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterAllocation);
    assert uProcessMemoryUsageAfterAllocation >= uProcessMemoryUsage + uMemoryAllocationSize, \
        "Process memory usage was expected to be at least 0x%X after allocation, but is 0x%X" % \
        (uProcessMemoryUsage + uMemoryAllocationSize, uProcessMemoryUsageAfterAllocation);
    oVirtualAllocation.fFree();
    uProcessMemoryUsageAfterFree = fuGetProcessMemoryUsage(oNotepadProcess.pid);
    print "    + Memory usage after freeing memory = 0x%X." % uProcessMemoryUsageAfterFree;
    assert uProcessMemoryUsageAfterFree >= uProcessMemoryUsage, \
        "Process memory usage was expected to be at least 0x%X after free, but is 0x%X" % \
        (uProcessMemoryUsage, uProcessMemoryUsageAfterFree);

    # cJobObject
    print "  * Testing cJobObject...";
    oJobObject = cJobObject(oNotepadProcess.pid);
    oJobObject.fSetMaxTotalMemoryUse(uProcessMemoryUsageAfterFree + uMemoryAllocationSize / 2);
    oVirtualAllocation = foCreateVirtualAllocationInProcessForId(oNotepadProcess.pid, uMemoryAllocationSize);
    assert oVirtualAllocation is None, \
        "Attempt to allocate 0x%X bytes succeeded despite JobObject memory allocation limits" % uMemoryAllocationSize;
    print "    + JobObject memory limits applied correctly.";
    
    # fbTerminateProcessForId
    print "  * Testing fbTerminateProcessForId...";
    fbTerminateProcessForId(oNotepadProcess.pid);
  except:
    oNotepadProcess.terminate();
    oNotepadProcess.wait();
    raise;
  assert oNotepadProcess.poll() != None, \
      "Notepad.exe was not terminated!";
  # fdsProcessesExecutableName_by_uId (make sure notepad.exe is removed)
  assert oNotepadProcess.pid not in fdsProcessesExecutableName_by_uId(), \
      "Notepad.exe is still reported to exist after being terminated!?";
  print "  + Notepad was terminated.";

  print "* Testing windows version/registry functions...";
  print "  + %s" % oWindowsVersion;
