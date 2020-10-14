import os, re, sys, threading, time;
from mWindowsAPI import *;
from mWindowsSDK import SECURITY_MANDATORY_MEDIUM_RID;
from oConsole import oConsole;

def fTestProcess(sComSpec, sExpectedISA = None):
  oConsole.fPrint("=== Testing process related functions ", sPadding = "=");
  uExitCode = 1234;
  # Start cmd.exe and have it exit with a specific error code.
  oConsole.fStatus("  * Calling cProcess.foCreateForBinaryPath(%s, [\"/K\", \"EXIT %s\"], bHidden = True)..." % (repr(sComSpec), uExitCode));
  oTestProcess = cProcess.foCreateForBinaryPathAndArguments(sComSpec, ["/K", "EXIT %s" % uExitCode], bHidden = True);
  try:
    oConsole.fPrint("  + cProcess.foCreateForBinaryPath(%s, [\"/K\", \"EXIT %s\"], bHidden = True) = <cProcess #%X>" % (repr(sComSpec), uExitCode, oTestProcess.uId));
    oTestProcess.fbWait();
    assert not oTestProcess.bIsRunning, \
        "Expected process not to be running.";
    assert oTestProcess.uExitCode == uExitCode, \
        "Expected exit code %d, got %d" % (uExitCode, oTestProcess.uExitCode);
    # Restart cmd.exe and let it wait for input.
    oTestProcess = cProcess.foCreateForBinaryPath(sComSpec, bMinimized = True);
    time.sleep(1); # Allow process to start
    oConsole.fPrint("  + Started test process %d..." % oTestProcess.uId);
    # cProcess
    oConsole.fPrint("  * Testing cProcess...");
    time.sleep(1); # Allow process to start
    assert oTestProcess.bIsRunning, \
        "Expected process to be running.";
    sISAFromId = fsGetISAForProcessId(oTestProcess.uId);
    assert sISAFromId == oTestProcess.sISA, \
        "Process ISA %s != %s" % (sISAFromId, oTestProcess.sISA);
    assert sExpectedISA is None or sISAFromId == sExpectedISA, \
        "Process ISA %s != %s" % (sISAFromId, sExpectedISA);
    oConsole.fPrint("    + ISA = %s" % repr(oTestProcess.sISA));
    oConsole.fPrint("    + Binary start address = 0x%08X" % oTestProcess.uBinaryStartAddress);
    assert oTestProcess.sBinaryPath.lower() == sComSpec.lower(), \
        "Expected binary path %s, got %s" % (sComSpec, oTestProcess.sBinaryPath);
    assert oTestProcess.sBinaryName.lower() == os.path.basename(sComSpec).lower(), \
        "Expected binary name %s, got %s" % (os.path.basename(sComSpec), oTestProcess.sBinaryName);
    oConsole.fPrint("    + Binary Path = %s" % repr(oTestProcess.sBinaryPath));
    oConsole.fPrint("    + Command line = %s" % repr(oTestProcess.sCommandLine));
    assert oTestProcess.uIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID, \
        "Expected process integrity level 0, got %d" % oTestProcess.uIntegrityLevel;
    oConsole.fPrint("    + Integrity level = 0x%X" % oTestProcess.uIntegrityLevel);
    oConsole.fPrint("  * Testing cProcess.fbSuspendThreads()...");
    assert oTestProcess.fbSuspendThreads(), \
        "Cannot suspend threads";
    oConsole.fPrint("  * Testing cProcess.fbResumeThreads()...");
    assert oTestProcess.fbResumeThreads(), \
        "Cannot resume threads";
    oConsole.fPrint("  * Testing cProcess.foGetPEB()...");
    for sLine in oTestProcess.foGetPEB().fasDump("Process %d/0x%X PEB" % (oTestProcess.uId, oTestProcess.uId)):
      oConsole.fPrint("    | " + sLine);
    oConsole.fPrint("  * Testing cProcess.foGetProcessParameters()...");
    for sLine in oTestProcess.foGetProcessParameters().fasDump("Process %d/0x%X ProcessParameters" % (oTestProcess.uId, oTestProcess.uId)):
      oConsole.fPrint("    | " + sLine);

    # cVirtualAllocation
    oBinaryVirtualAllocation = cVirtualAllocation(oTestProcess.uId, oTestProcess.uBinaryStartAddress);
    assert oBinaryVirtualAllocation.bAllocated, \
        "Expected memory to be allocated at address 0x%08X" % oTestProcess.uBinaryStartAddress;
    assert oBinaryVirtualAllocation.uStartAddress == oTestProcess.uBinaryStartAddress, \
        "Expected binary virtual allocation to start at address 0x%08X, not 0x%08X" % \
          (oTestProcess.uBinaryStartAddress, oBinaryVirtualAllocation.uStartAddress);
    oConsole.fPrint("    + There are 0x%X bytes of memory allocated at address 0x%08X." % \
        (oBinaryVirtualAllocation.uSize, oBinaryVirtualAllocation.uStartAddress));
    
    # fdsProcessesExecutableName_by_uId (make sure test process binary is included)
    oConsole.fPrint("  * Testing fdsProcessesExecutableName_by_uId...");
    dsProcessesExecutableName_by_uId = fdsProcessesExecutableName_by_uId();
    sProcessesExecutableName = dsProcessesExecutableName_by_uId.get(oTestProcess.uId);
    assert sProcessesExecutableName, \
        "Test process id %d/0x%X not found in process list (%s)!" % \
        (oTestProcess.uId, oTestProcess.uId, ", ".join(["0x%X" % uId for uId in dsProcessesExecutableName_by_uId]));
    assert sProcessesExecutableName.lower() == os.path.basename(sComSpec).lower(), \
        "Text process %d/0x%X is reported to run %s" % (oTestProcess.uId, sProcessesExecutableName);
    # fuGetIntegrityLevelForProcessId
    oConsole.fPrint("  * Testing oTestProcess.uIntegrityLevel...");
    uProcessIntegrityLevel = oTestProcess.uIntegrityLevel;
    assert uProcessIntegrityLevel is not None, \
        "Test process %d/0x%X integrity level could not be determined!" % (oTestProcess.uId, oTestProcess.uId);
    oConsole.fPrint("    + IntegrityLevel = 0x%X." % uProcessIntegrityLevel);
    # fuGetMemoryUsageForProcessId
    # cVirtualAllocation.foCreateForProcessId()
    # cVirtualAllocation.fAllocate()
    # cVirtualAllocation.fFree()
    oConsole.fPrint("  * Testing Memory management functions...");
    uProcessMemoryUsage = fuGetMemoryUsageForProcessId(oTestProcess.uId);
    oConsole.fPrint("    + Memory usage = 0x%X." % uProcessMemoryUsage);
    uMemoryAllocationSize = 0x1230000;
    oVirtualAllocation = cVirtualAllocation.foCreateForProcessId(oTestProcess.uId, uMemoryAllocationSize, bReserved = True);
    assert oVirtualAllocation is not None, \
        "Attempt to reserve 0x%X bytes failed" % uMemoryAllocationSize;
    assert oVirtualAllocation.uSize == uMemoryAllocationSize, \
        "Attempted to reserve 0x%X bytes, but got 0x%X" % (uMemoryAllocationSize, oVirtualAllocation.uSize);
    uProcessMemoryUsageAfterReservation = oTestProcess.uMemoryUsage;
    oConsole.fPrint("    + Memory usage after reserving 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterReservation));
  # For unknown reasons, the memory usage can drop after reserving memory !?
  #    assert uProcessMemoryUsageAfterReservation >= uProcessMemoryUsage, \
  #        "Process memory usage was expected to be at least 0x%X after reservation, but is 0x%X" % \
  #        (uProcessMemoryUsage, uProcessMemoryUsageAfterReservation);
    oVirtualAllocation.fAllocate();
    uProcessMemoryUsageAfterAllocation = oTestProcess.uMemoryUsage;
    oConsole.fPrint("    + Memory usage after allocating 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterAllocation));
    assert uProcessMemoryUsageAfterAllocation >= uProcessMemoryUsageAfterReservation + uMemoryAllocationSize, \
        "Process memory usage was expected to be 0x%X after allocation, but is 0x%X" % \
        (uProcessMemoryUsage + uMemoryAllocationSize, uProcessMemoryUsageAfterAllocation);
    oVirtualAllocation.fFree();
    uProcessMemoryUsageAfterFree = oTestProcess.uMemoryUsage;
    oConsole.fPrint("    + Memory usage after freeing memory = 0x%X." % uProcessMemoryUsageAfterFree);
    assert uProcessMemoryUsageAfterFree >= uProcessMemoryUsage, \
        "Process memory usage was expected to be at least 0x%X after free, but is 0x%X" % \
        (uProcessMemoryUsage, uProcessMemoryUsageAfterFree);

    # cJobObject
    # Also test if OOM error codes cause a Python MemoryError exception to be thrown.
    oConsole.fPrint("  * Testing cJobObject...");
    oJobObject = cJobObject(oTestProcess.uId);
    oJobObject.fSetMaxTotalMemoryUse(uProcessMemoryUsageAfterFree + uMemoryAllocationSize / 2);
    try:
      cVirtualAllocation.foCreateForProcessId(oTestProcess.uId, uMemoryAllocationSize);
    except MemoryError, oMemoryError:
      pass;
    else:
      oConsole.fPrint(",".ljust(80, "-"));
      for sLine in oVirtualAllocation.fasDump():
        oConsole.fPrint("| %s" % sLine);
      oConsole.fPrint("`".ljust(80, "-"));
      raise AssertionError("Attempt to allocate 0x%X bytes succeeded despite JobObject memory allocation limits" % \
          uMemoryAllocationSize);
    oConsole.fPrint("    + JobObject memory limits applied correctly.");
    
    # fbTerminateForProcessId
    oConsole.fPrint("  * Testing fbTerminateForProcessId...");
    fbTerminateForProcessId(oTestProcess.uId);
    assert oTestProcess.bIsTerminated, \
        "Test process was not terminated!";
    # fdsProcessesExecutableName_by_uId (make sure test process is removed)
    assert oTestProcess.uId not in fdsProcessesExecutableName_by_uId(), \
        "Test process is still reported to exist after being terminated!?";
    oConsole.fPrint("  + Test process was terminated.");
    
    # TODO: add test for fDebugBreakForProcessId, fuCreateThreadForProcessIdAndAddress and fSendCtrlCForProcessId.
    # This will require attaching a debugger to the process to determine a thread id, resume the application, or catch
    # the exceptions these functions throw.
    
    # cConsoleProcess, fSuspendForProcessId
    oConsole.fPrint("* Testing cConsoleProcess...");
    sExpectedOutput = "Test";
    oConsoleProcess = cConsoleProcess.foCreateForBinaryPathAndArguments(
      sComSpec,
      ["/K", "ECHO %s&ECHO OFF" % sExpectedOutput],
    );
    sExpectedOutput += "\r\n";
    time.sleep(1); # Allow process to start
    oConsole.fPrint("  * Reading process output...");
    sActualOutput = oConsoleProcess.oStdOutPipe.fsReadBytes(len(sExpectedOutput));
    assert sActualOutput == sExpectedOutput, \
        "Expected %s, got %s" % (repr(sExpectedOutput), repr(sActualOutput));
    # Suspend the process to test for a known issue: attempting to close handles on a
    # suspended process will hang until the process is resumed or killed.
    fSuspendForProcessId(oConsoleProcess.uId);
    def fPipeReadingThread():
      oConsole.fPrint("  * Reading end of console process output in thread...");
      sBytesRead = oConsoleProcess.oStdOutPipe.fsReadBytes();
      assert sBytesRead == "", \
          "Expected %s, got %s" % (repr(""), repr(sBytesRead));
    oReadThread = threading.Thread(target = fPipeReadingThread);
    oReadThread.start();
    def fKillProcessThread():
      time.sleep(1);
      oConsole.fPrint("  * Terminating console process...");
      fbTerminateForProcessId(oConsoleProcess.uId);
    oKillProcessThread = threading.Thread(target = fKillProcessThread);
    oKillProcessThread.start();
    oConsole.fPrint("  * Closing pipes...");
    # This will hang until the process is killed...
    oConsoleProcess.fClose();
    oConsole.fPrint("  * Waiting for kill process thread...");
    oKillProcessThread.join();
    oConsole.fPrint("  * Waiting for end of console process output in thread...");
    oReadThread.join();
    oConsole.fPrint("  * Reading end of output...");
    sReadBytes = oConsoleProcess.oStdOutPipe.fsReadBytes(1);
    assert sReadBytes == "", \
        "Read %s from a completely closed pipe" % repr(sReadBytes);
  finally:
    if oTestProcess.bIsRunning:
      oTestProcess.fbTerminate();