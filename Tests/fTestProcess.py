import os, re, sys, threading, time;
from mWindowsAPI import *;
from mWindowsSDK import SECURITY_MANDATORY_MEDIUM_RID;

def fTestProcess(sComSpec, sExpectedISA = None):
  uExitCode = 1234;
  # Start cmd.exe and have it exit with a specific error code.
  oTestProcess = cProcess.foCreateForBinaryPathAndArguments(sComSpec, ["/K", "EXIT %s" % uExitCode]);
  try:
    oTestProcess.fbWait();
    assert not oTestProcess.bIsRunning, \
        "Expected process not to be running.";
    assert oTestProcess.uExitCode == uExitCode, \
        "Expected exit code %d, got %d" % (uExitCode, oTestProcess.uExitCode);
    # Restart cmd.exe and let it wait for input.
    oTestProcess = cProcess.foCreateForBinaryPath(sComSpec);
    time.sleep(1); # Allow process to start
    print "  + Started test process %d..." % oTestProcess.uId;sys.stdout.flush();
    # cProcess
    print "  * Testing cProcess...";sys.stdout.flush();
    time.sleep(1); # Allow process to start
    assert oTestProcess.bIsRunning, \
        "Expected process to be running.";
    sISAFromId = fsGetISAForProcessId(oTestProcess.uId);
    assert sISAFromId == oTestProcess.sISA, \
        "Process ISA %s != %s" % (sISAFromId, oTestProcess.sISA);
    assert sExpectedISA is None or sISAFromId == sExpectedISA, \
        "Process ISA %s != %s" % (sISAFromId, sExpectedISA);
    print "    + ISA = %s" % repr(oTestProcess.sISA);sys.stdout.flush();
    print "    + Binary start address = 0x%08X" % oTestProcess.uBinaryStartAddress;sys.stdout.flush();
    assert oTestProcess.sBinaryPath.lower() == sComSpec.lower(), \
        "Expected binary path %s, got %s" % (sComSpec, oTestProcess.sBinaryPath);
    assert oTestProcess.sBinaryName.lower() == os.path.basename(sComSpec).lower(), \
        "Expected binary name %s, got %s" % (os.path.basename(sComSpec), oTestProcess.sBinaryName);
    print "    + Binary Path = %s" % repr(oTestProcess.sBinaryPath);sys.stdout.flush();
    print "    + Command line = %s" % repr(oTestProcess.sCommandLine);sys.stdout.flush();
    assert oTestProcess.uIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID, \
        "Expected process integrity level 0, got %d" % oTestProcess.uIntegrityLevel;
    print "    + Integrity level = 0x%X" % oTestProcess.uIntegrityLevel;sys.stdout.flush();
    print "  * Testing cProcess.fSuspend()...";sys.stdout.flush();
    oTestProcess.fSuspend();
    print "  * Testing cProcess.foGetPEB()...";sys.stdout.flush();
    for sLine in oTestProcess.foGetPEB().fasDump("Process %d/0x%X PEB" % (oTestProcess.uId, oTestProcess.uId)):
      print "    | " + sLine;sys.stdout.flush();
    print "  * Testing cProcess.foGetProcessParameters()...";sys.stdout.flush();
    for sLine in oTestProcess.foGetProcessParameters().fasDump("Process %d/0x%X ProcessParameters" % (oTestProcess.uId, oTestProcess.uId)):
      print "    | " + sLine;sys.stdout.flush();

    # Threads
    print "  * Testing cProcess.fuCreateThreadForAddress...";sys.stdout.flush();
    uThreadId = oTestProcess.fuCreateThreadForAddress(0, bSuspended = True);
    print "  * Testing fbTerminateForThreadId...";sys.stdout.flush();
    assert fbTerminateForThreadId(uThreadId), \
        "Expected true";
    print "  * Testing cProcess.faoGetThreads...";sys.stdout.flush();
    aoThreads = oTestProcess.faoGetThreads();
    print "    + Thread ids: %s" % repr([oThread.uId for oThread in aoThreads]);sys.stdout.flush();
    print "  * Testing cProcess.foGetThreadForId(%d)..." % aoThreads[0].uId;sys.stdout.flush();
    oThread = oTestProcess.foGetThreadForId(aoThreads[0].uId);
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
  #    oThread.fSetRegisters({
  #      "rax": 0xAAAAAAAAAAAAAAAA,
  #      "rbx": 0xBBBBBBBBBBBBBBBB,
  #      "rcx": 0xCCCCCCCCCCCCCCCC,
  #      "rdx": 0xDDDDDDDDDDDDDDDD,
  #      "rsi": 0x5555555555555555,
  #      "rdi": 0xDDDDDDDDDDDDDDDD,
  #      "rsp": 0x5555555555555555,
  #      "rbp": 0xBBBBBBBBBBBBBBBB,
  #      "rip": 0x1111111111111111,
  #    });
  #    oThread.fbResume();
  #    assert oThread.fbResume(), \
  #      "Still suspended";
    # cVirtualAllocation
    oBinaryVirtualAllocation = cVirtualAllocation(oTestProcess.uId, oTestProcess.uBinaryStartAddress);
    assert oBinaryVirtualAllocation.bAllocated, \
        "Expected memory to be allocated at address 0x%08X" % oTestProcess.uBinaryStartAddress;
    assert oBinaryVirtualAllocation.uStartAddress == oTestProcess.uBinaryStartAddress, \
        "Expected binary virtual allocation to start at address 0x%08X, not 0x%08X" % \
          (oTestProcess.uBinaryStartAddress, oBinaryVirtualAllocation.uStartAddress);
    print "    + There are 0x%X bytes of memory allocated at address 0x%08X." % \
        (oBinaryVirtualAllocation.uSize, oBinaryVirtualAllocation.uStartAddress);sys.stdout.flush();
    
    # fdsProcessesExecutableName_by_uId (make sure test process binary is included)
    print "  * Testing fdsProcessesExecutableName_by_uId...";sys.stdout.flush();
    dsProcessesExecutableName_by_uId = fdsProcessesExecutableName_by_uId();
    sProcessesExecutableName = dsProcessesExecutableName_by_uId.get(oTestProcess.uId);
    assert sProcessesExecutableName, \
        "Test process id %d/0x%X not found in process list (%s)!" % \
        (oTestProcess.uId, oTestProcess.uId, ", ".join(["0x%X" % uId for uId in dsProcessesExecutableName_by_uId]));
    assert sProcessesExecutableName.lower() == os.path.basename(sComSpec).lower(), \
        "Text process %d/0x%X is reported to run %s" % (oTestProcess.uId, sProcessesExecutableName);
    # fuGetIntegrityLevelForProcessId
    print "  * Testing oTestProcess.uIntegrityLevel...";sys.stdout.flush();
    uProcessIntegrityLevel = oTestProcess.uIntegrityLevel;
    assert uProcessIntegrityLevel is not None, \
        "Test process %d/0x%X integrity level could not be determined!" % (oTestProcess.uId, oTestProcess.uId);
    print "    + IntegrityLevel = 0x%X." % uProcessIntegrityLevel;sys.stdout.flush();
    # fuGetMemoryUsageForProcessId
    # cVirtualAllocation.foCreateForProcessId()
    # cVirtualAllocation.fAllocate()
    # cVirtualAllocation.fFree()
    print "  * Testing Memory management functions...";sys.stdout.flush();
    uProcessMemoryUsage = fuGetMemoryUsageForProcessId(oTestProcess.uId);
    print "    + Memory usage = 0x%X." % uProcessMemoryUsage;sys.stdout.flush();
    uMemoryAllocationSize = 0x1230000;
    oVirtualAllocation = cVirtualAllocation.foCreateForProcessId(oTestProcess.uId, uMemoryAllocationSize, bReserved = True);
    assert oVirtualAllocation is not None, \
        "Attempt to reserve 0x%X bytes failed" % uMemoryAllocationSize;
    assert oVirtualAllocation.uSize == uMemoryAllocationSize, \
        "Attempted to reserve 0x%X bytes, but got 0x%X" % (uMemoryAllocationSize, oVirtualAllocation.uSize);
    uProcessMemoryUsageAfterReservation = oTestProcess.uMemoryUsage;
    print "    + Memory usage after reserving 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterReservation);sys.stdout.flush();
  # For unknown reasons, the memory usage can drop after reserving memory !?
  #    assert uProcessMemoryUsageAfterReservation >= uProcessMemoryUsage, \
  #        "Process memory usage was expected to be at least 0x%X after reservation, but is 0x%X" % \
  #        (uProcessMemoryUsage, uProcessMemoryUsageAfterReservation);
    oVirtualAllocation.fAllocate();
    uProcessMemoryUsageAfterAllocation = oTestProcess.uMemoryUsage;
    print "    + Memory usage after allocating 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterAllocation);sys.stdout.flush();
    assert uProcessMemoryUsageAfterAllocation >= uProcessMemoryUsageAfterReservation + uMemoryAllocationSize, \
        "Process memory usage was expected to be 0x%X after allocation, but is 0x%X" % \
        (uProcessMemoryUsage + uMemoryAllocationSize, uProcessMemoryUsageAfterAllocation);
    oVirtualAllocation.fFree();
    uProcessMemoryUsageAfterFree = oTestProcess.uMemoryUsage;
    print "    + Memory usage after freeing memory = 0x%X." % uProcessMemoryUsageAfterFree;sys.stdout.flush();
    assert uProcessMemoryUsageAfterFree >= uProcessMemoryUsage, \
        "Process memory usage was expected to be at least 0x%X after free, but is 0x%X" % \
        (uProcessMemoryUsage, uProcessMemoryUsageAfterFree);

    # cJobObject
    # Also test if OOM error codes cause a Python MemoryError exception to be thrown.
    print "  * Testing cJobObject...";sys.stdout.flush();
    oJobObject = cJobObject(oTestProcess.uId);
    oJobObject.fSetMaxTotalMemoryUse(uProcessMemoryUsageAfterFree + uMemoryAllocationSize / 2);
    try:
      cVirtualAllocation.foCreateForProcessId(oTestProcess.uId, uMemoryAllocationSize);
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
    fbTerminateForProcessId(oTestProcess.uId);
    assert oTestProcess.bIsTerminated, \
        "Test process was not terminated!";
    # fdsProcessesExecutableName_by_uId (make sure test process is removed)
    assert oTestProcess.uId not in fdsProcessesExecutableName_by_uId(), \
        "Test process is still reported to exist after being terminated!?";
    print "  + Test process was terminated.";sys.stdout.flush();
    
    # TODO: add test for fbTerminateForThreadId, fDebugBreakForProcessId, fSuspendForProcessId, \
    # fuCreateThreadForProcessIdAndAddress and fSendCtrlCForProcessId.
    # This will require attaching a debugger to the process to determine a thread id, resume the application, or catch
    # the exceptions these functions throw.
    
    # cConsoleProcess, fSuspendForProcessId
    print "* Testing cConsoleProcess...";sys.stdout.flush();
    sExpectedOutput = "Test";
    oConsoleProcess = cConsoleProcess.foCreateForBinaryPathAndArguments(
      sComSpec,
      ["/K", "ECHO %s&ECHO OFF" % sExpectedOutput],
    );
    sExpectedOutput += "\r\n";
    time.sleep(1); # Allow process to start
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
  finally:
    if oTestProcess.bIsRunning:
      oTestProcess.fbTerminate();