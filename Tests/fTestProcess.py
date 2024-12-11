import os, time;
from mConsole import oConsole;
from mWindowsAPI import \
    cJobObject, \
    cModule, \
    cProcess, \
    cVirtualAllocation, \
    fbTerminateForProcessId, \
    fds0GetProcessesExecutableName_by_uId, \
    fsGetISAForProcessId, \
    fsHexNumber, \
    fuGetMemoryUsageForProcessId;
from mWindowsSDK import \
    SECURITY_MANDATORY_MEDIUM_RID;

def fTestProcess(sComSpec, sThisProcessISA, sExpectedChildProcessISA):
  oConsole.fOutput("=== Testing process related functions ", sPadding = "=");
  oConsole.fOutput("* This process ISA: %s, child process ISA: %s" % (sThisProcessISA, sExpectedChildProcessISA));
  uExitCode = 1234;
  # Start cmd.exe and have it exit with a specific error code.
  oConsole.fStatus("  * Calling cProcess.foCreateForBinaryPath(%s, [\"/K\", \"EXIT %s\"], bHidden = True)..." % (repr(sComSpec), uExitCode));
  oTestProcess = cProcess.foCreateForBinaryPathAndArguments(sComSpec, ["/K", "EXIT %s" % uExitCode], bHidden = True);
  try:
    oConsole.fOutput("  + cProcess.foCreateForBinaryPath(%s, [\"/K\", \"EXIT %s\"], bHidden = True) = %s" % (repr(sComSpec), uExitCode, repr(oTestProcess)));
    oTestProcess.fbWait();
    assert not oTestProcess.bIsRunning, \
        "Expected process not to be running.";
    assert oTestProcess.uExitCode == uExitCode, \
        "Expected exit code %d, got %d" % (uExitCode, oTestProcess.uExitCode);
    # Restart cmd.exe and let it wait for input.
    oTestProcess = cProcess.foCreateForBinaryPath(sComSpec, bMinimizedWindow = True);
    time.sleep(1); # Allow process to start
    oConsole.fOutput("  + Started test process %s" % (repr(oTestProcess),));
    # cProcess
    assert oTestProcess.sISA == sExpectedChildProcessISA, \
        "cProcess.sISA == %s instead of %s" % (oTestProcess.sISA, sExpectedChildProcessISA);
    oConsole.fOutput("  * Testing cProcess...");
    time.sleep(1); # Allow process to start
    assert oTestProcess.bIsRunning, \
        "Expected process to be running.";
    sISAFromId = fsGetISAForProcessId(oTestProcess.uId);
    assert sISAFromId == oTestProcess.sISA, \
        "Process ISA %s != %s" % (sISAFromId, oTestProcess.sISA);
    oConsole.fOutput("    + ISA = %s" % repr(oTestProcess.sISA));
    oConsole.fOutput("    + Binary start address = 0x%08X" % oTestProcess.uBinaryStartAddress);
    assert oTestProcess.sBinaryPath.lower() == sComSpec.lower(), \
        "Expected binary path %s, got %s" % (repr(sComSpec), repr(oTestProcess.sBinaryPath));
    assert oTestProcess.sBinaryName.lower() == os.path.basename(sComSpec).lower(), \
        "Expected binary name %s, got %s" % (os.path.basename(sComSpec), oTestProcess.sBinaryName);
    oConsole.fOutput("    + Binary Path = %s" % repr(oTestProcess.sBinaryPath));
    oConsole.fOutput("    + Command line = %s" % repr(oTestProcess.sCommandLine));
    s0IntegrityLevel = {
      0x00000000: "SECURITY_MANDATORY_UNTRUSTED_RID",
      0x00001000: "SECURITY_MANDATORY_LOW_RID",
      0x00002000: "SECURITY_MANDATORY_MEDIUM_RID",
      0x00002100: "SECURITY_MANDATORY_MEDIUM_PLUS_RID",
      0X00003000: "SECURITY_MANDATORY_HIGH_RID",
      0x00004000: "SECURITY_MANDATORY_SYSTEM_RID",
      0x00005000: "SECURITY_MANDATORY_PROTECTED_PROCESS_RID",
    }.get(oTestProcess.uIntegrityLevel);
    assert s0IntegrityLevel is not None, \
        "Invalid/unknown process integrity level %d" % oTestProcess.uIntegrityLevel;
    oConsole.fOutput("    + Integrity level = 0x%X (%s)" % (oTestProcess.uIntegrityLevel, s0IntegrityLevel));
    
    oConsole.fOutput("  * Testing cProcess.fbSuspendThreads()...");
    assert oTestProcess.fbSuspendThreads(), \
        "Cannot suspend threads";
    
    oConsole.fOutput("  * Testing cModule.faoGetForProcessId...");
    aoModules = cModule.faoGetForProcessId(oTestProcess.uId);
    oConsole.fOutput("    | Found %d modules:" % len(aoModules));
    for oModule in aoModules:
      oConsole.fOutput("    |   %s @ %s (%s)" % (
        repr(oModule.s0Name),
        fsHexNumber(oModule.uStartAddress),
        repr(oModule.s0BinaryPath),
      ));
    
    oConsole.fOutput("  * Testing cProcess.foGetPEB()...");
    for sLine in oTestProcess.foGetPEB().fasDump("Process %d/0x%X PEB" % (oTestProcess.uId, oTestProcess.uId)):
      oConsole.fOutput("    | " + sLine);
    
    oConsole.fOutput("  * Testing cProcess.fbResumeThreads()...");
    assert oTestProcess.fbResumeThreads(), \
        "Cannot resume threads";
    
    oConsole.fOutput("  * Testing cProcess.foGetProcessParameters()...");
    for sLine in oTestProcess.foGetProcessParameters().fasDump("Process %d/0x%X ProcessParameters" % (oTestProcess.uId, oTestProcess.uId)):
      oConsole.fOutput("    | " + sLine);
    
    # cVirtualAllocation
    oBinaryVirtualAllocation = cVirtualAllocation(oTestProcess.uId, oTestProcess.uBinaryStartAddress);
    assert oBinaryVirtualAllocation.bAllocated, \
        "Expected memory to be allocated at address 0x%08X" % oTestProcess.uBinaryStartAddress;
    assert oBinaryVirtualAllocation.uStartAddress == oTestProcess.uBinaryStartAddress, \
        "Expected binary virtual allocation to start at address 0x%08X, not 0x%08X" % \
          (oTestProcess.uBinaryStartAddress, oBinaryVirtualAllocation.uStartAddress);
    oConsole.fOutput("    + There are 0x%X bytes of memory allocated at address 0x%08X." % \
        (oBinaryVirtualAllocation.uSize, oBinaryVirtualAllocation.uStartAddress));
    
    # fds0GetProcessesExecutableName_by_uId (make sure test process binary is included)
    oConsole.fOutput("  * Testing fds0GetProcessesExecutableName_by_uId...");
    ds0ProcessesExecutableName_by_uId = fds0GetProcessesExecutableName_by_uId();
    for uId in sorted(ds0ProcessesExecutableName_by_uId.keys()):
      s0ProcessesExecutableName = ds0ProcessesExecutableName_by_uId[uId];
      print("%5d/0x%04X: %s" % (uId, uId, repr(s0ProcessesExecutableName) if s0ProcessesExecutableName is not None else "?"));
      if uId == oTestProcess.uId:
        assert s0ProcessesExecutableName is not None, \
            "Text process %d/0x%X (%s) executable name could not be determined in process list" % (
              oTestProcess.uId, oTestProcess.uId, repr(s0ProcessesExecutableName),
            );
        sTestExecutableName = os.path.basename(sComSpec);
        assert s0ProcessesExecutableName.lower() == sTestExecutableName.lower(), \
            "Text process %d/0x%X (%s) executable name in process list is %s" % (
              oTestProcess.uId, oTestProcess.uId, repr(s0ProcessesExecutableName),
              repr(s0ProcessesExecutableName)
            );
    assert oTestProcess.uId in ds0ProcessesExecutableName_by_uId, \
        "Test process %d/0x%X (%s) not found in process list!" % (
          oTestProcess.uId, oTestProcess.uId, repr(s0ProcessesExecutableName),
        );
    # fuGetIntegrityLevelForProcessId
    oConsole.fOutput("  * Testing oTestProcess.uIntegrityLevel...");
    uProcessIntegrityLevel = oTestProcess.uIntegrityLevel;
    assert uProcessIntegrityLevel is not None, \
        "Test process %d/0x%X integrity level could not be determined!" % (oTestProcess.uId, oTestProcess.uId);
    oConsole.fOutput("    + IntegrityLevel = 0x%X." % uProcessIntegrityLevel);
    # fuGetMemoryUsageForProcessId
    # cVirtualAllocation.fo0CreateForProcessId()
    # cVirtualAllocation.fCommit()
    # cVirtualAllocation.fFree()
    oConsole.fOutput("  * Testing Memory management functions...");
    uProcessMemoryUsage = fuGetMemoryUsageForProcessId(oTestProcess.uId);
    oConsole.fOutput("    + Memory usage = 0x%X." % uProcessMemoryUsage);
    uMemoryAllocationSize = 0x1230000;
    oVirtualAllocation = cVirtualAllocation.fo0CreateForProcessId(oTestProcess.uId, uMemoryAllocationSize, bReserved = True);
    assert oVirtualAllocation is not None, \
        "Attempt to reserve 0x%X bytes failed" % uMemoryAllocationSize;
    assert oVirtualAllocation.uSize == uMemoryAllocationSize, \
        "Attempted to reserve 0x%X bytes, but got 0x%X" % (uMemoryAllocationSize, oVirtualAllocation.uSize);
    uProcessMemoryUsageAfterReservation = oTestProcess.uMemoryUsage;
    oConsole.fOutput("    + Memory usage after reserving 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterReservation));
  # For unknown reasons, the memory usage can drop after reserving memory !?
  #    assert uProcessMemoryUsageAfterReservation >= uProcessMemoryUsage, \
  #        "Process memory usage was expected to be at least 0x%X after reservation, but is 0x%X" % \
  #        (uProcessMemoryUsage, uProcessMemoryUsageAfterReservation);
    oVirtualAllocation.fCommit();
    uProcessMemoryUsageAfterAllocation = oTestProcess.uMemoryUsage;
    oConsole.fOutput("    + Memory usage after allocating 0x%X bytes = 0x%X." % \
        (oVirtualAllocation.uSize, uProcessMemoryUsageAfterAllocation));
    assert uProcessMemoryUsageAfterAllocation >= uProcessMemoryUsageAfterReservation + uMemoryAllocationSize, \
        "Process memory usage was expected to be 0x%X after allocation, but is 0x%X" % \
        (uProcessMemoryUsage + uMemoryAllocationSize, uProcessMemoryUsageAfterAllocation);
    oVirtualAllocation.fFree();
    uProcessMemoryUsageAfterFree = oTestProcess.uMemoryUsage;
    oConsole.fOutput("    + Memory usage after freeing memory = 0x%X." % uProcessMemoryUsageAfterFree);
    assert uProcessMemoryUsageAfterFree >= uProcessMemoryUsage, \
        "Process memory usage was expected to be at least 0x%X after free, but is 0x%X" % \
        (uProcessMemoryUsage, uProcessMemoryUsageAfterFree);
    
    # cJobObject
    # Also test if OOM error codes cause a Python MemoryError exception to be thrown.
    oConsole.fOutput("  * Testing cJobObject...");
    oJobObject = cJobObject(oTestProcess.uId);
    oJobObject.fSetMaxTotalMemoryUse(uProcessMemoryUsageAfterFree + uMemoryAllocationSize / 2);
    try:
      cVirtualAllocation.fo0CreateForProcessId(oTestProcess.uId, uMemoryAllocationSize);
    except MemoryError as oMemoryError:
      pass;
    else:
      oConsole.fOutput(",".ljust(80, "-"));
      for sLine in oVirtualAllocation.fasDump():
        oConsole.fOutput("| %s" % sLine);
      oConsole.fOutput("`".ljust(80, "-"));
      raise AssertionError("Attempt to allocate 0x%X bytes succeeded despite JobObject memory allocation limits" % \
          uMemoryAllocationSize);
    oConsole.fOutput("    + JobObject memory limits applied correctly.");
    
    # fbTerminateForProcessId
    oConsole.fOutput("  * Testing fbTerminateForProcessId...");
    fbTerminateForProcessId(oTestProcess.uId);
    assert oTestProcess.bIsTerminated, \
        "Test process was not terminated!";
    # fdsGetProcessesExecutableName_by_uId (make sure test process is removed)
    assert oTestProcess.uId not in fds0GetProcessesExecutableName_by_uId(), \
        "Test process is still reported to exist after being terminated!?";
    oConsole.fOutput("  + Test process was terminated.");
    
    # TODO: add test for fDebugBreakForProcessId, fuCreateThreadForProcessIdAndAddress and fSendCtrlCForProcessId.
    # This will require attaching a debugger to the process to determine a thread id, resume the application, or catch
    # the exceptions these functions throw.
    
  finally:
    if oTestProcess.bIsRunning:
      oTestProcess.fbTerminate();