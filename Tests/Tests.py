import os, re, sys, subprocess, threading, time;
sTestsFolderPath = os.path.dirname(os.path.abspath(__file__));
sMainFolderPath = os.path.dirname(sTestsFolderPath);
sParentFolderPath = os.path.dirname(sMainFolderPath);
sModulesFolderPath = os.path.join(sMainFolderPath, "modules");
asOriginalSysPath = sys.path[:];
sys.path = [sMainFolderPath, sParentFolderPath, sModulesFolderPath] + sys.path;
# Save the list of names of loaded modules:
asOriginalModuleNames = sys.modules.keys();

from mWindowsAPI import *;
from mWindowsSDK import *;
oKernel32 = foLoadKernel32DLL();
from mWindowsAPI.mRegistry import *;
from mWindowsAPI import mDbgHelp;

# Sub-packages should load all modules relative, or they will end up in the global namespace, which means they may get
# loaded by the script importing it if it tries to load a differnt module with the same name. Obviously, that script
# will probably not function when the wrong module is loaded, so we need to check that we did this correctly.
for sModuleName in sys.modules.keys():
  assert (
    sModuleName in asOriginalModuleNames # This was loaded before cBugId was loaded
    or sModuleName.lstrip("_").split(".", 1)[0] in [
      "mWindowsAPI", "mWindowsSDK", # This was loaded as part of the mWindowsAPI package
      # These built-in modules are loaded by mWindowsAPI:
      "base64", "binascii", "contextlib", "cStringIO", "ctypes", "encodings", "json", "nturl2path", "platform",
      "socket", "ssl", "string", "strop", "struct", "textwrap", "urllib", "urlparse", "winreg",
    ]
  ), \
      "Module %s was unexpectedly loaded outside of the mWindowsAPI package!" % sModuleName;
# Restore the search path
sys.path = asOriginalSysPath;

from mWindowsAPI.fThrowLastError import fThrowLastError;

if __name__ == "__main__":
  # Test registry access
  print "* Testing Registry access...";sys.stdout.flush();
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
  print "* Testing system info...";sys.stdout.flush();
  print "  * fsGetPythonISA() = %s" % fsGetPythonISA();sys.stdout.flush();
  print "  * oSystemInfo...";sys.stdout.flush();
  print "    | OS:                      %s" %  oSystemInfo.sOSFullDetails;sys.stdout.flush();
  print "    | Processors:              %d" % oSystemInfo.uNumberOfProcessors;sys.stdout.flush();
  print "    | Address range:           0x%08X - 0x%08X" % (oSystemInfo.uMinimumApplicationAddress, oSystemInfo.uMaximumApplicationAddress);sys.stdout.flush();
  print "    | Page size:               0x%X" % oSystemInfo.uPageSize;sys.stdout.flush();
  print "    | Allocation granularity:  0x%X" % oSystemInfo.uAllocationAddressGranularity;sys.stdout.flush();
  print "    | System name:             %s" % oSystemInfo.sSystemName;sys.stdout.flush();
  print "    | System id:               %s" % oSystemInfo.sUniqueSystemId;sys.stdout.flush();
  
  # Test console functions
  print "* Testing oKernel32 console functions...";sys.stdout.flush();
  ohStdOut = oKernel32.GetStdHandle(STD_OUTPUT_HANDLE);
  oConsoleScreenBufferInfo = CONSOLE_SCREEN_BUFFER_INFO();
  if not oKernel32.GetConsoleScreenBufferInfo(ohStdOut, oConsoleScreenBufferInfo.foCreatePointer()):
    fThrowLastError("GetConsoleScreenBufferInfo(0x%08X, 0x%X)" % (ohStdOut.value, oConsoleScreenBufferInfo.fuGetAddress()));
  print "  Console buffer size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwSize.X, oConsoleScreenBufferInfo.dwSize.Y);sys.stdout.flush();
  print "  Console window size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwMaximumWindowSize.X, oConsoleScreenBufferInfo.dwMaximumWindowSize.Y);sys.stdout.flush();
  uOriginalColor = oConsoleScreenBufferInfo.wAttributes & 0xFF;
  uTestColor = (uOriginalColor & 0xF0) | 0x0A; # Bright green foreground, keep same background.
  if not oKernel32.SetConsoleTextAttribute(ohStdOut, uTestColor):
    fThrowLastError("SetConsoleTextAttribute(0x%08X, 0x%02X)" % (ohStdOut.value, uTestColor));
  print "  * This should be green.";sys.stdout.flush();
  if not oKernel32.SetConsoleTextAttribute(ohStdOut, uOriginalColor):
    fThrowLastError("SetConsoleTextAttribute(0x%08X, 0x%02X)" % (ohStdOut.value, uOriginalColor));
  
  print "* Testing process functions...";sys.stdout.flush();
  # Test process functions
  sTestApplicationPath = os.getenv("ComSpec");
  oTestProcess = subprocess.Popen(sTestApplicationPath, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE);
  print "  + Started test process %d..." % oTestProcess.pid;sys.stdout.flush();
  try:
    # cProcess
    print "  * Testing cProcess...";sys.stdout.flush();
    oProcess = cProcess(oTestProcess.pid);
    sISAFromId = fsGetISAForProcessId(oProcess.uId);
    assert sISAFromId == oProcess.sISA, \
        "%s != %s" % (sISAFromId, oProcess.sISA);
    print "    + ISA = %s" % repr(oProcess.sISA);sys.stdout.flush();
    print "    + Binary start address = 0x%08X" % oProcess.uBinaryStartAddress;sys.stdout.flush();
    print "    + Binary Path = %s" % repr(oProcess.sBinaryPath);sys.stdout.flush();
    print "    + Command line = %s" % repr(oProcess.sCommandLine);sys.stdout.flush();
    print "  * Testing cProcess.fSuspend()...";sys.stdout.flush();
    oProcess.fSuspend();
    print "  * Testing cProcess.oPEB...";sys.stdout.flush();
    for sLine in oProcess.oPEB.fasDump("Process %d/0x%X PEB" % (oProcess.uId, oProcess.uId)):
      print "    | " + sLine;sys.stdout.flush();
    # Threads
    print "  * Testing cProcess.fuCreateThreadForAddress...";sys.stdout.flush();
    uThreadId = oProcess.fuCreateThreadForAddress(0, bSuspended = True);
    print "  * Testing fbTerminateForThreadId...";sys.stdout.flush();
    assert fbTerminateForThreadId(uThreadId), \
        "Expected true";
    print "  * Testing cProcess.faoGetThreads...";sys.stdout.flush();
    aoThreads = oProcess.faoGetThreads();
    print "    + Thread ids: %s" % repr([oThread.uId for oThread in aoThreads]);sys.stdout.flush();
    print "  * Testing cProcess.foGetThreadForId(%d)..." % aoThreads[0].uId;sys.stdout.flush();
    oThread = oProcess.foGetThreadForId(aoThreads[0].uId);
    for oThread in aoThreads:
      print "  * Testing cThread for thread %d..." % oThread.uId;sys.stdout.flush();
      print "    * cThread.fSuspend()";sys.stdout.flush();
      oThread.fSuspend();
      print "    * Description: %s" % (oThread.sDescription,);sys.stdout.flush();
      print "    * Stack: 0x%X - 0x%X" % (oThread.uStackBottomAddress, oThread.uStackTopAddress);sys.stdout.flush();
      print "    * TEB:";sys.stdout.flush();
      for sLine in oThread.oTEB.fasDump("Thread %d/0x%X TEB" % (oThread.uId, oThread.uId)):
        print "    | " + sLine;sys.stdout.flush();
      print "    * Registers:";sys.stdout.flush();
      duRegisterValue_by_sName = oThread.fduGetRegisterValueByName();
      for sRegisterName in sorted(duRegisterValue_by_sName.keys()):
        if "rip" in duRegisterValue_by_sName:
          if re.match(r"^r([a-z]+|\d+)$", sRegisterName):
            print "    | %s = 0x%X" % (sRegisterName, duRegisterValue_by_sName[sRegisterName]);sys.stdout.flush();
        elif re.match(r"^e[a-z]+$", sRegisterName):
          print "    | %s = 0x%X" % (sRegisterName, duRegisterValue_by_sName[sRegisterName]);sys.stdout.flush();
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
        (oBinaryVirtualAllocation.uSize, oBinaryVirtualAllocation.uStartAddress);sys.stdout.flush();
    
    # fdsProcessesExecutableName_by_uId (make sure test process binary is included)
    print "  * Testing fdsProcessesExecutableName_by_uId...";sys.stdout.flush();
    dsProcessesExecutableName_by_uId = fdsProcessesExecutableName_by_uId();
    sProcessesExecutableName = dsProcessesExecutableName_by_uId.get(oProcess.uId);
    assert sProcessesExecutableName, \
        "Test process id %d/0x%X not found in process list!" % (oProcess.uId, oProcess.uId);
    assert sProcessesExecutableName.lower() == os.path.basename(sTestApplicationPath).lower(), \
        "Text process %d/0x%X is reported to run %s" % (oProcess.uId, sProcessesExecutableName);
    # fuGetIntegrityLevelForProcessId
    print "  * Testing oProcess.uIntegrityLevel...";sys.stdout.flush();
    uProcessIntegrityLevel = oProcess.uIntegrityLevel;
    assert uProcessIntegrityLevel is not None, \
        "Test process %d/0x%X integrity level could not be determined!" % (oProcess.uId, oProcess.uId);
    print "    + IntegrityLevel = 0x%X." % uProcessIntegrityLevel;sys.stdout.flush();
    # fuGetMemoryUsageForProcessId
    # cVirtualAllocation.foCreateForProcessId()
    # cVirtualAllocation.fAllocate()
    # cVirtualAllocation.fFree()
    print "  * Testing Memory management functions...";sys.stdout.flush();
    uProcessMemoryUsage = fuGetMemoryUsageForProcessId(oProcess.uId);
    print "    + Memory usage = 0x%X." % uProcessMemoryUsage;sys.stdout.flush();
    uMemoryAllocationSize = 0x1230000;
    oVirtualAllocation = cVirtualAllocation.foCreateForProcessId(oProcess.uId, uMemoryAllocationSize, bReserved = True);
    assert oVirtualAllocation is not None, \
        "Attempt to reserve 0x%X bytes failed" % uMemoryAllocationSize;
    assert oVirtualAllocation.uSize == uMemoryAllocationSize, \
        "Attempted to reserve 0x%X bytes, but got 0x%X" % (uMemoryAllocationSize, oVirtualAllocation.uSize);
    uProcessMemoryUsageAfterReservation = oProcess.uMemoryUsage;
    print "    + Memory usage after reserving 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterReservation);sys.stdout.flush();
# For unknown reasons, the memory usage can drop after reserving memory !?
#    assert uProcessMemoryUsageAfterReservation >= uProcessMemoryUsage, \
#        "Process memory usage was expected to be at least 0x%X after reservation, but is 0x%X" % \
#        (uProcessMemoryUsage, uProcessMemoryUsageAfterReservation);
    oVirtualAllocation.fAllocate();
    uProcessMemoryUsageAfterAllocation = oProcess.uMemoryUsage;
    print "    + Memory usage after allocating 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterAllocation);sys.stdout.flush();
    assert uProcessMemoryUsageAfterAllocation >= uProcessMemoryUsageAfterReservation + uMemoryAllocationSize, \
        "Process memory usage was expected to be 0x%X after allocation, but is 0x%X" % \
        (uProcessMemoryUsage + uMemoryAllocationSize, uProcessMemoryUsageAfterAllocation);
    oVirtualAllocation.fFree();
    uProcessMemoryUsageAfterFree = oProcess.uMemoryUsage;
    print "    + Memory usage after freeing memory = 0x%X." % uProcessMemoryUsageAfterFree;sys.stdout.flush();
    assert uProcessMemoryUsageAfterFree >= uProcessMemoryUsage, \
        "Process memory usage was expected to be at least 0x%X after free, but is 0x%X" % \
        (uProcessMemoryUsage, uProcessMemoryUsageAfterFree);

    # cJobObject
    # Also test if OOM error codes cause a Python MemoryError exception to be thrown.
    print "  * Testing cJobObject...";sys.stdout.flush();
    oJobObject = cJobObject(oProcess.uId);
    oJobObject.fSetMaxTotalMemoryUse(uProcessMemoryUsageAfterFree + uMemoryAllocationSize / 2);
    try:
      cVirtualAllocation.foCreateForProcessId(oProcess.uId, uMemoryAllocationSize);
    except MemoryError, oMemoryError:
      pass;
    else:
      print ",".ljust(80, "-");sys.stdout.flush();
      for sLine in oVirtualAllocation.fasDump():
        print "| %s" % sLine;sys.stdout.flush();
      print "`".ljust(80, "-");sys.stdout.flush();
      raise AssertionError("Attempt to allocate 0x%X bytes succeeded despite JobObject memory allocation limits" % \
          uMemoryAllocationSize);
    print "    + JobObject memory limits applied correctly.";sys.stdout.flush();
    
    # fbTerminateForProcessId
    print "  * Testing fbTerminateForProcessId...";sys.stdout.flush();
    fbTerminateForProcessId(oProcess.uId);
    assert oTestProcess.poll() != None, \
        "Test process was not terminated!";
    # fdsProcessesExecutableName_by_uId (make sure test process is removed)
    assert oProcess.uId not in fdsProcessesExecutableName_by_uId(), \
        "Test process is still reported to exist after being terminated!?";
    print "  + Test process was terminated.";sys.stdout.flush();
    
    # TODO: add test for fbTerminateForThreadId, fDebugBreakForProcessId, fSuspendForProcessId, \
    # fuCreateThreadForProcessIdAndAddress and fSendCtrlCForProcessId.
    # This will require attaching a debugger to the process to determine a thread id, resume the application, or catch
    # the exceptions these functions throw.
    
    # cPipe
    print "* Testing cPipe...";sys.stdout.flush();
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
    fTestPipe(cPipe.foCreate());
    print "  * Testing cPipe with non-inheritable handles...";sys.stdout.flush();
    fTestPipe(cPipe.foCreate(bInheritableInput = False, bInheritableOutput = False));
    # cConsoleProcess, fSuspendForProcessId
    print "* Testing cConsoleProcess...";sys.stdout.flush();
    sExpectedOutput = "Test";
    oConsoleProcess = cConsoleProcess.foCreateForBinaryPathAndArguments(
      os.environ.get("ComSpec"),
      ["/K", "ECHO %s&ECHO OFF" % sExpectedOutput],
    );
    sExpectedOutput += "\r\n";
    print "  * Reading process output...";sys.stdout.flush();
    sActualOutput = oConsoleProcess.oStdOutPipe.fsReadBytes(len(sExpectedOutput));
    assert sActualOutput == sExpectedOutput, \
        "Expected %s, got %s" % (repr(sExpectedOutput), repr(sActualOutput));
    # Suspend the process to test for a known issue: attempting to close handles on a
    # suspended process will hang until the process is resumed or killed.
    fSuspendForProcessId(oConsoleProcess.uId);
    def fPipeReadingThread():
      print "  * Reading end of console process output in thread...";sys.stdout.flush();
      sBytesRead = oConsoleProcess.oStdOutPipe.fsReadBytes();
      assert sBytesRead == "", \
          "Expected %s, got %s" % (repr(""), repr(sBytesRead));
    oReadThread = threading.Thread(target = fPipeReadingThread);
    oReadThread.start();
    def fKillProcessThread():
      time.sleep(1);
      print "  * Terminating console process...";sys.stdout.flush();
      fbTerminateForProcessId(oConsoleProcess.uId);
    oKillProcessThread = threading.Thread(target = fKillProcessThread);
    oKillProcessThread.start();
    print "  * Closing pipes...";sys.stdout.flush();
    # This will hang until the process is killed...
    oConsoleProcess.fClose();
    print "  * Waiting for kill process thread...";sys.stdout.flush();
    oKillProcessThread.join();
    print "  * Waiting for end of console process output in thread...";sys.stdout.flush();
    oReadThread.join();
    print "  * Reading end of output...";sys.stdout.flush();
    sReadBytes = oConsoleProcess.oStdOutPipe.fsReadBytes(1);
    assert sReadBytes == "", \
        "Read %s from a completely closed pipe" % repr(sReadBytes);
    # mDbgHelp.fsUndecorateSymbolName
    print "* Testing mDbgHelp...";sys.stdout.flush();
    print "  * fsUndecorateSymbolName...";sys.stdout.flush();
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
      print "    + %s => %s / %s" % (sDecoratedSymbolName, sUndecoratedSymbolName, sUndecoratedFullSymbolName);sys.stdout.flush();
  except:
    oTestProcess.terminate();
    oTestProcess.wait();
    raise;
