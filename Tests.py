import os, re, sys, subprocess, threading, time;

sMainFolderPath = os.path.dirname(os.path.abspath(__file__));
sParentFolderPath = os.path.dirname(sMainFolderPath);
sModulesFolderPath = os.path.join(sMainFolderPath, "modules");
asOriginalSysPath = sys.path[:];
sys.path = [sMainFolderPath, sParentFolderPath, sModulesFolderPath] + sys.path;
# Save the list of names of loaded modules:
asOriginalModuleNames = sys.modules.keys();

from mWindowsAPI import *;
from mWindowsAPI.mDLLs import *;
from mWindowsAPI.mDefines import *;
from mWindowsAPI.mTypes import *;
from mWindowsAPI.mRegistry import *;
from mWindowsAPI import mDbgHelp;

# Sub-packages should load all modules relative, or they will end up in the global namespace, which means they may get
# loaded by the script importing it if it tries to load a differnt module with the same name. Obviously, that script
# will probably not function when the wrong module is loaded, so we need to check that we did this correctly.
for sModuleName in sys.modules.keys():
  assert (
    sModuleName in asOriginalModuleNames # This was loaded before cBugId was loaded
    or sModuleName.lstrip("_").split(".", 1)[0] in [
      "mWindowsAPI", # This was loaded as part of the mWindowsAPI package
      # These built-in modules are loaded by mWindowsAPI:
      "base64", "binascii", "contextlib", "cStringIO", "ctypes", "encodings", "json", "nturl2path", "platform",
      "socket", "ssl", "string", "strop", "struct", "textwrap", "urllib", "urlparse", "winreg",
    ]
  ), \
      "Module %s was unexpectedly loaded outside of the mWindowsAPI package!" % sModuleName;
# Restore the search path
sys.path = asOriginalSysPath;

if __name__ == "__main__":
  # Test registry access
  print "* Testing Registry access...";
  oTestRegistryValue = cRegistryValue(
    sTypeName = "SZ",
    xValue = "Test value",
  );
  oRegistryHiveKeyNamedValue = cRegistryHiveKeyNamedValue(
    sHiveName = "HKCU",
    sKeyName = r"Software\SkyLined\mWindowsAPI",
    sValueName = "Test value name",
  );
  assert oRegistryHiveKeyNamedValue.foSet(oTestRegistryValue), \
      "Could not set named registry value!";
  assert oRegistryHiveKeyNamedValue.foGet() == oTestRegistryValue, \
      "Could not get named registry value!";
  assert oRegistryHiveKeyNamedValue.fbDelete(), \
      "Could not delete named registry value";
  assert oRegistryHiveKeyNamedValue.foGet() is None, \
      "Deleting named registry value failed!";
  
  # Test system info
  print "* Testing system info...";
  print "  * fsGetPythonISA() = %s" % fsGetPythonISA();
  print "  * oSystemInfo...";
  print "    | OS version: %s" %  oSystemInfo.sOSVersion;
  print "    | Processors:      %d" % oSystemInfo.uNumberOfProcessors;
  print "    | Address range:   0x%08X - 0x%08X" % (oSystemInfo.uMinimumApplicationAddress, oSystemInfo.uMaximumApplicationAddress);
  print "    | Page size:       0x%X" % oSystemInfo.uPageSize;
  print "    | Allocation granularity: 0x%X" % oSystemInfo.uAllocationAddressGranularity;
  print "    | System name: %s" % oSystemInfo.sSystemName;
  print "    | System id: %s" % oSystemInfo.sUniqueSystemId;
  
  # Test console functions
  print "* Testing KERNEL32 console functions...";
  hStdOut = KERNEL32.GetStdHandle(STD_OUTPUT_HANDLE);
  oConsoleScreenBufferInfo = CONSOLE_SCREEN_BUFFER_INFO();
  assert KERNEL32.GetConsoleScreenBufferInfo(hStdOut, PCONSOLE_SCREEN_BUFFER_INFO(oConsoleScreenBufferInfo)), \
      "GetConsoleScreenBufferInfo(0x%08X, ...) => Error 0x%08X" % \
      (hStdOut, KERNEL32.GetLastError());
  print "  Console buffer size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwSize.X, oConsoleScreenBufferInfo.dwSize.Y);
  print "  Console window size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwMaximumWindowSize.X, oConsoleScreenBufferInfo.dwMaximumWindowSize.Y);
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
  sTestApplicationPath = os.getenv("ComSpec");
  oTestProcess = subprocess.Popen(sTestApplicationPath, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE);
  print "  + Started test process %d..." % oTestProcess.pid;
  try:
    # cProcess
    print "  * Testing cProcess...";
    oProcess = cProcess(oTestProcess.pid);
    print "    + ISA = %s" % repr(oProcess.sISA);
    print "    + Binary start address = 0x%08X" % oProcess.uBinaryStartAddress;
    print "    + Binary Path = %s" % repr(oProcess.sBinaryPath);
    print "    + Command line = %s" % repr(oProcess.sCommandLine);
    print "  * Testing cProcess.fSuspend()...";
    oProcess.fSuspend();
    print "  * Testing cProcess.oPEB...";
    for sLine in oProcess.oPEB.fasDump("Process %d/0x%X PEB" % (oProcess.uId, oProcess.uId)):
      print "    | " + sLine;
    # Threads
    print "  * Testing cProcess.faoGetThreads...";
    aoThreads = oProcess.faoGetThreads();
    print "    + Thread ids: %s" % repr([oThread.uId for oThread in aoThreads]);
    print "  * Testing cProcess.foGetThreadForId(%d)..." % aoThreads[0].uId;
    oThread = oProcess.foGetThreadForId(aoThreads[0].uId);
    for oThread in aoThreads:
      print "  * Testing cThread.fSuspend() for thread %d..." % oThread.uId;
      oThread.fSuspend();
      print "  * Testing cThread.oTEB for thread %d..." % oThread.uId;
      for sLine in oThread.oTEB.fasDump("Thread %d/0x%X TEB" % (oThread.uId, oThread.uId)):
        print "    | " + sLine;
      print "  * Stack: 0x%X - 0x%X" % (oThread.uStackBottomAddress, oThread.uStackTopAddress);
      print "  * Registers:";
      duRegisterValue_by_sName = oThread.fduGetRegisterValueByName();
      for sRegisterName in sorted(duRegisterValue_by_sName.keys()):
        if "rip" in duRegisterValue_by_sName:
          if re.match(r"^r([a-z]+|\d+)$", sRegisterName):
            print "    | %s = 0x%X" % (sRegisterName, duRegisterValue_by_sName[sRegisterName]);
        elif re.match(r"^e[a-z]+$", sRegisterName):
          print "    | %s = 0x%X" % (sRegisterName, duRegisterValue_by_sName[sRegisterName]);
# This may crash the application
#      oThread.fSetRegisters({
#        "rax": 0xAAAAAAAAAAAAAAAA,
#        "rbx": 0xBBBBBBBBBBBBBBBB,
#        "rcx": 0xCCCCCCCCCCCCCCCC,
#        "rdx": 0xDDDDDDDDDDDDDDDD,
#        "rsi": 0x5555555555555555,
#        "rdi": 0xDDDDDDDDDDDDDDDD,
#        "rsp": 0x5555555555555555,
#        "rbp": 0xBBBBBBBBBBBBBBBB,
#        "rip": 0x1111111111111111,
#      });
#      oThread.fbResume();
#      assert oThread.fbResume(), \
#        "Still suspended";
    # cVirtualAllocation
    oBinaryVirtualAllocation = cVirtualAllocation(oProcess.uId, oProcess.uBinaryStartAddress);
    assert oBinaryVirtualAllocation.bAllocated, \
        "Expected memory to be allocated at address 0x%08X" % oProcess.uBinaryStartAddress;
    assert oBinaryVirtualAllocation.uStartAddress == oProcess.uBinaryStartAddress, \
        "Expected binary virtual allocation to start at address 0x%08X, not 0x%08X" % \
          (oProcess.uBinaryStartAddress, oBinaryVirtualAllocation.uStartAddress);
    print "    + There are 0x%X bytes of memory allocated at address 0x%08X." % \
        (oBinaryVirtualAllocation.uSize, oBinaryVirtualAllocation.uStartAddress);
    
    # fdsProcessesExecutableName_by_uId (make sure test process binary is included)
    print "  * Testing fdsProcessesExecutableName_by_uId...";
    dsProcessesExecutableName_by_uId = fdsProcessesExecutableName_by_uId();
    sProcessesExecutableName = dsProcessesExecutableName_by_uId.get(oProcess.uId);
    assert sProcessesExecutableName, \
        "Test process id %d/0x%X not found in process list!" % (oProcess.uId, oProcess.uId);
    assert sProcessesExecutableName.lower() == os.path.basename(sTestApplicationPath).lower(), \
        "Text process %d/0x%X is reported to run %s" % (oProcess.uId, sProcessesExecutableName);
    # fuGetProcessIntegrityLevelForId
    print "  * Testing fuGetProcessIntegrityLevelForId...";
    uProcessIntegrityLevel = fuGetProcessIntegrityLevelForId(oProcess.uId);
    assert uProcessIntegrityLevel is not None, \
        "Test process %d/0x%X integrity level could not be determined!" % (oProcess.uId, oProcess.uId);
    print "    + IntegrityLevel = 0x%X." % uProcessIntegrityLevel;
    # fuGetProcessMemoryUsage
    # cVirtualAllocation.foCreateInProcessForId()
    # cVirtualAllocation.fAllocate()
    # cVirtualAllocation.fFree()
    print "  * Testing Memory management functions...";
    uProcessMemoryUsage = fuGetProcessMemoryUsage(oProcess.uId);
    print "    + Memory usage = 0x%X." % uProcessMemoryUsage;
    uMemoryAllocationSize = 0x1230000;
    oVirtualAllocation = cVirtualAllocation.foCreateInProcessForId(oProcess.uId, uMemoryAllocationSize, bReserved = True);
    print ",".ljust(80, "-");
    for sLine in oVirtualAllocation.fasDump():
      print "| %s" % sLine;
    print "`".ljust(80, "-");
    assert oVirtualAllocation is not None, \
        "Attempt to reserve 0x%X bytes failed" % uMemoryAllocationSize;
    assert oVirtualAllocation.uSize == uMemoryAllocationSize, \
        "Attempted to reserve 0x%X bytes, but got 0x%X" % (uMemoryAllocationSize, oVirtualAllocation.uSize);
    uProcessMemoryUsageAfterReservation = fuGetProcessMemoryUsage(oProcess.uId);
    print "    + Memory usage after reserving 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterReservation);
# For unknown reasons, the memory usage can drop after reserving memory !?
#    assert uProcessMemoryUsageAfterReservation >= uProcessMemoryUsage, \
#        "Process memory usage was expected to be at least 0x%X after reservation, but is 0x%X" % \
#        (uProcessMemoryUsage, uProcessMemoryUsageAfterReservation);
    oVirtualAllocation.fAllocate();
    print ",".ljust(80, "-");
    for sLine in oVirtualAllocation.fasDump():
      print "| %s" % sLine;
    print "`".ljust(80, "-");
    uProcessMemoryUsageAfterAllocation = fuGetProcessMemoryUsage(oProcess.uId);
    print "    + Memory usage after allocating 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterAllocation);
    assert uProcessMemoryUsageAfterAllocation >= uProcessMemoryUsageAfterReservation + uMemoryAllocationSize, \
        "Process memory usage was expected to be 0x%X after allocation, but is 0x%X" % \
        (uProcessMemoryUsage + uMemoryAllocationSize, uProcessMemoryUsageAfterAllocation);
    oVirtualAllocation.fFree();
    print ",".ljust(80, "-");
    for sLine in oVirtualAllocation.fasDump():
      print "| %s" % sLine;
    print "`".ljust(80, "-");
    uProcessMemoryUsageAfterFree = fuGetProcessMemoryUsage(oProcess.uId);
    print "    + Memory usage after freeing memory = 0x%X." % uProcessMemoryUsageAfterFree;
    assert uProcessMemoryUsageAfterFree >= uProcessMemoryUsage, \
        "Process memory usage was expected to be at least 0x%X after free, but is 0x%X" % \
        (uProcessMemoryUsage, uProcessMemoryUsageAfterFree);

    # cJobObject
    # Also test if OOM error codes cause a Python MemoryError exception to be thrown.
    print "  * Testing cJobObject...";
    oJobObject = cJobObject(oProcess.uId);
    oJobObject.fSetMaxTotalMemoryUse(uProcessMemoryUsageAfterFree + uMemoryAllocationSize / 2);
    try:
      cVirtualAllocation.foCreateInProcessForId(oProcess.uId, uMemoryAllocationSize);
    except MemoryError, oMemoryError:
      pass;
    else:
      print ",".ljust(80, "-");
      for sLine in oVirtualAllocation.fasDump():
        print "| %s" % sLine;
      print "`".ljust(80, "-");
      raise AssertionError("Attempt to allocate 0x%X bytes succeeded despite JobObject memory allocation limits" % \
          uMemoryAllocationSize);
    print "    + JobObject memory limits applied correctly.";
    
    # fbTerminateProcessForId
    print "  * Testing fbTerminateProcessForId...";
    fbTerminateProcessForId(oProcess.uId);
    assert oTestProcess.poll() != None, \
        "Test process was not terminated!";
    # fdsProcessesExecutableName_by_uId (make sure test process is removed)
    assert oProcess.uId not in fdsProcessesExecutableName_by_uId(), \
        "Test process is still reported to exist after being terminated!?";
    print "  + Test process was terminated.";
    
    # TODO: add test for fbTerminateThreadForId, fDebugBreakProcessForId, fSuspendProcessForId, \
    # fuCreateThreadInProcessForIdAndAddress and fSendCtrlCToProcessForId.
    # This will require attaching a debugger to the process to determine a thread id, resume the application, or catch
    # the exceptions these functions throw.
    
    # cPipe
    print "* Testing cPipe...";
    def fTestPipe(oPipe):
      sWrittenBytes = "test\0test\x7f\x80\xff";
      oPipe.fWriteBytes(sWrittenBytes + "\n");
      sReadBytes = oPipe.fsReadLine();
      assert sReadBytes == sWrittenBytes, \
          "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
      oPipe.fWriteBytes(sWrittenBytes + "\r\n");
      sReadBytes = oPipe.fsReadLine();
      assert sReadBytes == sWrittenBytes, \
          "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
      oPipe.fWriteBytes(sWrittenBytes);
      oPipe.fClose(bInput = True);
      sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
      assert sReadBytes == sWrittenBytes, \
          "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
      sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
      assert sReadBytes == "", \
          "Read %s after closing pipe for write" % repr(sReadBytes);
      oPipe.fClose();
      sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
      assert sReadBytes == "", \
          "Read %s from a completely closed pipe" % repr(sReadBytes);
      try:
        oPipe.fWriteBytes("test");
      except IOError:
        pass;
      else:
        raise AssertionError("Should not be able to write to a closed pipe!");
    fTestPipe(cPipe());
    print "  * Testing cPipe with non-inheritable handles...";
    fTestPipe(cPipe(bInheritableInput = False, bInheritableOutput = False));
    # cConsoleProcess, fSuspendProcessForId
    print "* Testing cConsoleProcess...";
    sExpectedOutput = "Test";
    oConsoleProcess = cConsoleProcess.foCreateForBinaryPathAndArguments(
      os.environ.get("ComSpec"),
      ["/K", "ECHO %s&ECHO OFF" % sExpectedOutput],
    );
    sExpectedOutput += "\r\n";
    print "  * Reading process output...";
    sActualOutput = oConsoleProcess.oStdOutPipe.fsReadBytes(len(sExpectedOutput));
    assert sActualOutput == sExpectedOutput, \
        "Expected %s, got %s" % (repr(sExpectedOutput), repr(sActualOutput));
    # Suspend the process to test for a known issue: attempting to close handles on a
    # suspended process will hang until the process is resumed or killed.
    fSuspendProcessForId(oConsoleProcess.uId);
    def fPipeReadingThread():
      print "  * Reading end of console process output in thread...";
      sBytesRead = oConsoleProcess.oStdOutPipe.fsReadBytes();
      assert sBytesRead == "", \
          "Expected %s, got %s" % (repr(""), repr(sBytesRead));
    oReadThread = threading.Thread(target = fPipeReadingThread);
    oReadThread.start();
    def fKillProcessThread():
      time.sleep(1);
      print "  * Terminating console process...";
      fbTerminateProcessForId(oConsoleProcess.uId);
    oKillProcessThread = threading.Thread(target = fKillProcessThread);
    oKillProcessThread.start();
    print "  * Closing pipes...";
    # This will hang until the process is killed...
    oConsoleProcess.fClose();
    print "  * Waiting for kill process thread...";
    oKillProcessThread.join();
    print "  * Waiting for end of console process output in thread...";
    oReadThread.join();
    print "  * Reading end of output...";
    sReadBytes = oConsoleProcess.oStdOutPipe.fsReadBytes(1);
    assert sReadBytes == "", \
        "Read %s from a completely closed pipe" % repr(sReadBytes);
    # mDbgHelp.fsUndecorateSymbolName
    print "* Testing mDbgHelp...";
    print "  * fsUndecorateSymbolName...";
    for (sDecoratedSymbolName, tsExpectedResults) in {
      "?function@@YAHD@Z":                    ["int __cdecl function(char)", "function"],
      "?function@namespace@@AAGXM@Z":         ["private: void __stdcall namespace::function(float)", "namespace::function"],
      "?method@class@namespace@@AAEXH@Z":     ["private: void __thiscall namespace::class::method(int)", "namespace::class::method"],
      ".?AVSafeIntException@utilities@msl@@": [" ?? msl::utilities::SafeIntException", "msl::utilities::SafeIntException"],
      "Not a decorated name":                 [None, None],
    }.items():
      sExpectedFullSymbolName, sExpectedSymbolName = tsExpectedResults;
      sUndecoratedFullSymbolName = mDbgHelp.fsUndecorateSymbolName(sDecoratedSymbolName);
      assert sUndecoratedFullSymbolName == sExpectedFullSymbolName, \
          "mDbgHelp.fsUndecorateSymbolName(%s) => %s instead of %s" % \
          (repr(sDecoratedSymbolName), repr(sUndecoratedFullSymbolName), repr(sExpectedFullSymbolName));
      sUndecoratedSymbolName = mDbgHelp.fsUndecorateSymbolName(sDecoratedSymbolName, bNameOnly = True);
      assert sUndecoratedSymbolName == sExpectedSymbolName, \
          "mDbgHelp.fsUndecorateSymbolName(%s) => %s instead of %s" % \
          (repr(sDecoratedSymbolName), repr(sUndecoratedSymbolName), repr(sExpectedSymbolName));
      print "    + %s => %s / %s" % (sDecoratedSymbolName, sUndecoratedSymbolName, sUndecoratedFullSymbolName);
  except:
    oTestProcess.terminate();
    oTestProcess.wait();
    raise;
