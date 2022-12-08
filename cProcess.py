import os;

from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;

from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fbTerminateForProcessHandle import fbTerminateForProcessHandle;
from .fbTerminateForProcessId import fbTerminateForProcessId;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fuCreateThreadForProcessIdAndAddress import fuCreateThreadForProcessIdAndAddress;
from .fs0GetBinaryPathForProcessAndModuleHandle import fs0GetBinaryPathForProcessAndModuleHandle;
from .fsGetPythonISA import fsGetPythonISA;
from .fsGetISAForProcessHandle import fsGetISAForProcessHandle;
from .fSuspendForProcessId import fSuspendForProcessId;
from .fThrowLastError import fThrowLastError;
from .fuGetExitCodeForProcessHandle import fuGetExitCodeForProcessHandle;
from .fuGetIntegrityLevelForProcessId import fuGetIntegrityLevelForProcessId;
from .fuGetMemoryUsageForProcessId import fuGetMemoryUsageForProcessId;
from .cThread import cThread;
from .cVirtualAllocation import cVirtualAllocation;

gbDebugOutput = False;

dsProcessAccessRightName_by_uFlag = {
  DELETE: "DELETE",
  PROCESS_CREATE_PROCESS: "PROCESS_CREATE_PROCESS",
  PROCESS_CREATE_THREAD: "PROCESS_CREATE_THREAD",
  PROCESS_DUP_HANDLE: "PROCESS_DUP_HANDLE",
  PROCESS_QUERY_INFORMATION: "PROCESS_QUERY_INFORMATION",
  PROCESS_QUERY_LIMITED_INFORMATION: "PROCESS_QUERY_LIMITED_INFORMATION",
  PROCESS_SET_INFORMATION: "PROCESS_SET_INFORMATION",
  PROCESS_SET_QUOTA: "PROCESS_SET_QUOTA",
  PROCESS_SUSPEND_RESUME: "PROCESS_SUSPEND_RESUME",
  PROCESS_TERMINATE: "PROCESS_TERMINATE",
  PROCESS_VM_OPERATION: "PROCESS_VM_OPERATION",
  PROCESS_VM_READ: "PROCESS_VM_READ",
  PROCESS_VM_WRITE: "PROCESS_VM_WRITE",
  READ_CONTROL: "READ_CONTROL",
  SYNCHRONIZE: "SYNCHRONIZE",
  WRITE_DAC: "WRITE_DAC",
  WRITE_OWNER: "WRITE_OWNER",
};

class cProcess(object):
  @classmethod
  def foCreateForBinaryPath(cClass, sBinaryPath, **dxArguments):
    return cClass.foCreateForBinaryPathAndArguments(sBinaryPath, [], **dxArguments);
  @classmethod
  def foCreateForBinaryPathAndArguments(
    cClass,
    sBinaryPath,
    asArguments,
    sWorkingDirectory = None,
    bSuspended = False,
    bDebug = False,
    bHidden = False,
    bMinimizedWindow = False,
    bNormalWindow = False,
    bMaximizedWindow = False,
    bTerminateAutomatically = True,
  ):
    # Default to hidden of no visibility flags are provided.
    asWindowSpecificFlags = [sFlagName for (bValue, sFlagName) in {
      bHidden: "bHidden",
      bMinimizedWindow: "bMinimizedWindow",
      bNormalWindow: "bNormalWindow",
      bMaximizedWindow: "bMaximizedWindow",
    }.items() if bValue];
    bSeparateWindow = len(asWindowSpecificFlags) != 0;
    assert not bSeparateWindow or len(asWindowSpecificFlags) == 1, \
        "Cannot set the following arguments to True at the same time: %s" % (", ".join(asWindowSpecificFlags),);
    # The output of oStdInPipe is inherited so the application can read from it when we write to the input.
    # The output of oStdInPipe is closed by us after the application is started, as we do not use it and
    # want Windows to clean it up when the application terminates.
    # The input of oStdOutPipe and oStdErrPipe are inherited so the the application can write to them.
    # The input of oStdOutPipe and oStdErrPipe are closed by us after the application is started, as we do
    # not use them and want Windows to clean them up when the application terminates.
    sCommandLine = " ".join([
      (s and (s[0] == '"' or s.find(" ") == -1)) and s or '"%s"' % s.replace('"', '\\"')
      for s in [sBinaryPath] + asArguments
    ]);
    opBinaryPath = PCWSTR(sBinaryPath);
    opCommandLine = PWSTR(sCommandLine);
    olpCurrentDirectory = PCWSTR(sWorkingDirectory if sWorkingDirectory else NULL);
    odwCreationFlags = DWORD(sum([
      CREATE_NEW_CONSOLE if bSeparateWindow else 0,
      CREATE_SUSPENDED if bSuspended else 0,
      DEBUG_PROCESS if bDebug else 0,
    ]));
    oStartupInfo = STARTUPINFOW();
    oStartupInfo.cb = oStartupInfo.fuGetSize();
    oStartupInfo.lpDesktop = NULL;
    oStartupInfo.lpDesktop = NULL;
    oStartupInfo.dwFlags = STARTF_USESTDHANDLES | (STARTF_USESHOWWINDOW if bSeparateWindow else 0);
    oStartupInfo.wShowWindow = SW_HIDE if bHidden else SW_SHOWMINNOACTIVE if bMinimizedWindow else SW_SHOWMAXIMIZED if bMaximizedWindow else SW_SHOW;
    oStartupInfo.hStdInput = oKernel32DLL.GetStdHandle(STD_INPUT_HANDLE);
    oStartupInfo.hStdOutput = oKernel32DLL.GetStdHandle(STD_OUTPUT_HANDLE);
    oStartupInfo.hStdError = oKernel32DLL.GetStdHandle(STD_ERROR_HANDLE);
    oProcessInformation = PROCESS_INFORMATION();
    if not oKernel32DLL.CreateProcessW(
      opBinaryPath, # lpApplicationName,
      opCommandLine, # lpCommandLine,
      NULL, # lpProcessAttributes
      NULL, # lpThreadAttributes
      TRUE, # bInheritHandles
      odwCreationFlags, # dwCreationFlags
      NULL, # lpEnvironment
      olpCurrentDirectory,
      oStartupInfo.foCreatePointer(), # lpStartupInfo
      oProcessInformation.foCreatePointer(), # lpProcessInformation
    ):
      fThrowLastError("CreateProcessW(%s, %s, NULL, NULL, FALSE, %s, NULL, %s, ..., ...)" % \
          (repr(opBinaryPath), repr(opCommandLine), repr(odwCreationFlags), repr(olpCurrentDirectory)));
    # Close all handles that we no longer need:
    if not oKernel32DLL.CloseHandle(oProcessInformation.hThread):
      fThrowLastError("CloseHandle(%s)" % (repr(oProcessInformation.hThread),));
    return cClass(
      oProcessInformation.dwProcessId.fuGetValue(),
      ohProcess = oProcessInformation.hProcess,
      uProcessHandleFlags = PROCESS_ALL_ACCESS,
      bTerminateAutomatically = bTerminateAutomatically,
    );
  
  def __init__(oSelf, uId, ohProcess = None, uProcessHandleFlags = None, bTerminateAutomatically = True):
    assert isinstance(uId, int), \
        "uId must be an integer not %s" % repr(uId);
    oSelf.uId = uId;
    if ohProcess is None:
      assert uProcessHandleFlags is None, \
          "You cannot provide uProcessHandleFlags without ohProcess";
      uProcessHandleFlags = 0;
      ohProcess = HANDLE(INVALID_HANDLE_VALUE);
    else:
      assert isinstance(ohProcess, HANDLE), \
          "ohProcess (%s) is not a valid handle" % repr(ohProcess);
      assert uProcessHandleFlags is not None, \
          "You must provide uProcessHandleFlags when you provide ohProcess";
    oSelf.__ohProcess = ohProcess;
    oSelf.__uProcessHandleFlags = uProcessHandleFlags;
    oSelf.bTerminateAutomatically = bTerminateAutomatically;
    # If we are running in 64-bit Python, NtQueryInformationProcess will return a pointer to the 64-bit PEB of
    # another process in the PROCESS_BASIC_INFORMATION struct. If we are running in 32-bit Python, we cannot get
    # information on a 64-bit process unless we start doing some dirty hacks, which I'd rather not. To find out if
    # the PEB is 32- or 64-bit, we will need to find out the bitness of Python, the OS and the target process:
    oSelf.sISA = fsGetISAForProcessHandle(oSelf.fohOpenWithFlags(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ));
    assert oSelf.sISA == "x86" or fsGetPythonISA() == "x64", \
        "You cannot get information on a 64-bit process from 32-bit Python";
    oSelf.uPointerSize = {"x86": 4, "x64": 8}[oSelf.sISA];
    # Cache for dynamically retrieved properties:
    oSelf.__s0BinaryPath = None;
    oSelf.__sCommandLine = None;
    oSelf.__n0RunDurationInSeconds = None;
  
  def fohOpenWithFlags(oSelf, uRequiredFlags):
    # See if we have an open handle
    if oSelf.__ohProcess != INVALID_HANDLE_VALUE:
      # if it already has the required flags, return it:
      if oSelf.__uProcessHandleFlags & uRequiredFlags == uRequiredFlags:
        return oSelf.__ohProcess;
    ohOldProcessHandle = oSelf.__ohProcess;
    # Open a new handle with the required flags and all other flags we've used before.
    # This allows the new handle to be used for anything it was used for before as well
    # as anything new the caller wants to do:
    uFlags = oSelf.__uProcessHandleFlags | uRequiredFlags;
    ohProcess = oSelf.__ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.uId, uFlags);
    oSelf.__uProcessHandleFlags = uFlags if ohProcess != INVALID_HANDLE_VALUE else 0;
    if ohOldProcessHandle != INVALID_HANDLE_VALUE:
      # Close the old process handle:
      if not oKernel32DLL.CloseHandle(ohOldProcessHandle):
        fThrowLastError("CloseHandle(%s)" % (repr(ohOldProcessHandle),));
    return ohProcess;
  
  def fs0GetAccessRightsFlagsDescription(oSelf):
    if oSelf.__ohProcess == INVALID_HANDLE_VALUE:
      return None;
    if oSelf.__uProcessHandleFlags == PROCESS_ALL_ACCESS:
      return "PROCESS_ALL_ACCESS";
    return " | ".join([s for s in [
      sFlagName if oSelf.__uProcessHandleFlags & uFlag != 0 else None
      for (uFlag, sFlagName) in dsProcessAccessRightName_by_uFlag.items()
    ] if s]);
  
  def foGetPEB(oSelf):
    # The type of PROCESS_BASIC_INFORMATION returned by NtQueryInformationProcess depends on the ISA of the process
    # calling it, in this case it's the Python process we're running in:
    cProcessBasicInformation = {"x86": PROCESS_BASIC_INFORMATION32, "x64": PROCESS_BASIC_INFORMATION64}[fsGetPythonISA()];
    oProcessBasicInformation = cProcessBasicInformation();
    poProcessBasicInformation = PVOID(oProcessBasicInformation, bCast = True);
    ouReturnLength = ULONG();
    oNTDLL = foLoadNTDLL();
    oNTStatus = oNTDLL.NtQueryInformationProcess(
      oSelf.fohOpenWithFlags(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ),# ProcessHandle
      ProcessBasicInformation, # ProcessInformationClass
      PVOID(oProcessBasicInformation, bCast = True), # ProcessInformation
      oProcessBasicInformation.fuGetSize(), # ProcessInformationLength
      ouReturnLength.foCreatePointer(), # ReturnLength
    );
    if NT_ERROR(oNTStatus):
      fThrowNTStatusError(
        "NtQueryInformationProcess(ProcessHandle=0x%X, ProcessInformationClass=0x%X, " \
            "ProcessInformation=0x%X, ProcessInformationLength=0x%X, ReturnLength=0x%X)" % \
            (repr(oSelf.__ohProcess), ProcessBasicInformation, oProcessBasicInformation.fuGetAddress(), \
            oProcessBasicInformation.fuGetSize(), ouReturnLength.fuGetAddress()),
        oNTStatus.fuGetValue()
      );
    assert ouReturnLength == oProcessBasicInformation.fuGetSize(), \
        "NtQueryInformationProcess(%s, 0x%08X, ..., 0x%X, ...) wrote 0x%X bytes" % \
        (repr(oSelf.__ohProcess), ProcessBasicInformation, oProcessBasicInformation.fuGetSize(), ouReturnLength.fuGetValue());
    if gbDebugOutput:
      for sLine in oProcessBasicInformation.fasDump():
        print(sLine);
    # Read the PEB from the remote process
    # The type of PEB (32- or 64-bit) depends on the type of PROCESS_BASIC_INFORMATION (see above)
    o0PEB = oSelf.fo0ReadStructureUsingPointer(
      oProcessBasicInformation.PebBaseAddress,
    );
    assert o0PEB, \
        "Unable to read the PEB from process %d / 0x%X at address 0x%X!" % \
        (oSelf.uId, oSelf.uId, oProcessBasicInformation.PebBaseAddress.fuGetValue());
    if gbDebugOutput:
      for sLine in o0PEB.fasDump():
        print(sLine);
    return o0PEB;
  
  @property
  def uBinaryStartAddress(oSelf):
    return oSelf.foGetPEB().ImageBaseAddress.fuGetValue();
  
  def foGetProcessParameters(oSelf):
    # Read Process Parameters from the remote process
    oPEB = oSelf.foGetPEB();
    o0ProcessParameters = oSelf.fo0ReadStructureUsingPointer(
      oPEB.ProcessParameters,
    );
    assert o0ProcessParameters, \
        "Unable to read the ProcessParameters from process %d / 0x%X at address 0x%X!" % \
        (oSelf.uId, oSelf.uId, oPEB.ProcessParameters.fuGetValue());
    return o0ProcessParameters;
  
  @property
  def sBinaryPath(oSelf):
    if oSelf.__s0BinaryPath is None:
      # Read Image Path Name
      oProcessParameters = oSelf.foGetProcessParameters();
      s0BinaryPath = oSelf.fs0ReadStringForAddressAndLength(
        oProcessParameters.ImagePathName.Buffer.fuGetValue(),
        oProcessParameters.ImagePathName.Length.fuGetValue() >> 1,
        bUnicode = True,
      );
      assert s0BinaryPath, \
          "Unable to read the ImagePathName from process %d / 0x%X at address 0x%X and with size 0x%X!" % \
          (oSelf.uId, oSelf.uId, ProcessParameters.ImagePathName.Buffer, oProcessParameters.ImagePathName.Length);
      oSelf.__s0BinaryPath = s0BinaryPath; # Never None!
    return oSelf.__s0BinaryPath;
  
  @property
  def sBinaryName(oSelf):
    return os.path.basename(oSelf.sBinaryPath);
  
  @property
  def sCommandLine(oSelf):
    if oSelf.__sCommandLine is None:
      # Read Command Line
      oProcessParameters = oSelf.foGetProcessParameters();
      s0CommandLine = oSelf.fs0ReadStringForAddressAndLength(
        oProcessParameters.CommandLine.Buffer.fuGetValue(),
        oProcessParameters.CommandLine.Length.fuGetValue() >> 1,
        bUnicode = True,
      );
      assert s0CommandLine, \
          "Unable to read the CommandLine from process %d / 0x%X at address 0x%X and with size 0x%X!" % \
          (oSelf.uId, oSelf.uId, ProcessParameters.CommandLine.Buffer, oProcessParameters.CommandLine.Length);
      oSelf.__sCommandLine = s0CommandLine;
    return oSelf.__sCommandLine;
  
  def __del__(oSelf):
    try:
      # attrbutes may no longer be available when we terminate.
      # We will try to make a copy. If this succeeds, we can try
      # to clean up. If it does not, we will simply return.
      bTerminateAutomatically = oSelf.bTerminateAutomatically;
      ohProcess = oSelf.__ohProcess;
      uProcessHandleFlags = oSelf.__uProcessHandleFlags;
      uId = oSelf.uId;
    except AttributeError:
      return;
    if bTerminateAutomatically:
      try:
        # See if we have an open handle with PROCESS_TERMINATE rights and use that to terminate.
        # Otherwise terminate by process id.
        if (
          ohProcess != INVALID_HANDLE_VALUE
          and uProcessHandleFlags & PROCESS_TERMINATE == PROCESS_TERMINATE
        ):
          fbTerminateForProcessHandle(ohProcess);
        else:
          fbTerminateForProcessId(uId);
      except WindowsError as oError:
        pass;
    if ohProcess != INVALID_HANDLE_VALUE and not oKernel32DLL.CloseHandle(ohProcess):
      # If the process is already terminated we can see a ERROR_INVALID_HANDLE error, which we'll ignore.
      # Any other, unexpected errors are reported:
      if not fbLastErrorIs(ERROR_INVALID_HANDLE):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  
  @property
  def bIsRunning(oSelf):
    return fbIsRunningForProcessHandle(oSelf.fohOpenWithFlags(SYNCHRONIZE));
  
  @property
  def bIsTerminated(oSelf):
    return not oSelf.bIsRunning;
  
  def fbTerminate(oSelf, uTimeout = None):
    return fbTerminateForProcessHandle(oSelf.fohOpenWithFlags(PROCESS_TERMINATE), uTimeout);
  
  def fWait(oSelf):
    oSelf.fbWait();
  def fbWait(oSelf, uTimeout = None):
    return fbWaitForTerminationForProcessHandle(oSelf.fohOpenWithFlags(SYNCHRONIZE), uTimeout);
  
  def fSuspend(oSelf): # No return value; undocumented and unreliable: use fbSuspendThreads instead.
    return fSuspendForProcessHandle(oSelf.fohOpenWithFlags(PROCESS_SUSPEND_RESUME));
  
  def fbSuspendThreads(oSelf): # Returns true if any threads were running but are now suspended.
    bSuspended = False;
    for oThread in oSelf.faoGetThreads():
      if oThread.fbSuspend():
        bSuspended = True;
    return bSuspended;
  
  def fbResumeThreads(oSelf): # Returns true if any threads were suspend but are now running.
    bResumed = False;
    for oThread in oSelf.faoGetThreads():
      if oThread.fbResume():
        bResumed = True;
    return bResumed;
  
  @property
  def uExitCode(oSelf):
    return fuGetExitCodeForProcessHandle(oSelf.fohOpenWithFlags(PROCESS_QUERY_LIMITED_INFORMATION));
  
  @property
  def n0RunDurationInSeconds(oSelf):
    if not oSelf.bIsTerminated:
      return None;
    if oSelf.__n0RunDurationInSeconds is None:
      oSelf.__fGetProcessTimes();
    return oSelf.__n0RunDurationInSeconds;
  
  def __fGetProcessTimes(oSelf):
    ohProcess = oSelf.fohOpenWithFlags(PROCESS_QUERY_LIMITED_INFORMATION);
    # FILETIME has two 32-bit values that represent to lower and higher parts of a 64-bit count of 100 nanosecond
    # intervals.
    oCreationTime = FILETIME();
    oExitTime = FILETIME();
    oKernelTime = FILETIME();
    oUserTime = FILETIME();
    if not oKernel32DLL.GetProcessTimes(
      ohProcess, 
      oCreationTime.foCreatePointer(),
      oExitTime.foCreatePointer(),
      oKernelTime.foCreatePointer(),
      oUserTime.foCreatePointer(),
    ):
      fThrowLastError("GetProcessTimes(%s, &(%s), &(%s), &(%s), &(%s))" % (
        repr(ohProcess),
        repr(oCreationTime),
        repr(oExitTime),
        repr(oKernelTime),
        repr(oUserTime),
      ));
    # The difference between oExitTime and oExitTime is the run duration in 100 nanosecond intervals.
    uStartTime = (oCreationTime.dwHighDateTime << 32) + oCreationTime.dwLowDateTime;
    uEndTime = (oExitTime.dwHighDateTime << 32) + oExitTime.dwLowDateTime;
    oSelf.__n0RunDurationInSeconds = (uEndTime - uStartTime) * 0.0000001;
  
  def fo0CreateVirtualAllocation(oSelf, uSize, uAddress = None, bReserved = False, uProtection = None):
    return cVirtualAllocation.fo0CreateForProcessId(
      oSelf.uId,
      uSize,
      uAddress,
      bReserved,
      uProtection
    );
  
  def fo0GetVirtualAllocationForAddress(oSelf, uAddress):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    return oVirtualAllocation if oVirtualAllocation.bIsValid else None;
  
  def fo0GetAllocatedVirtualAllocationWithSizeCheck(oSelf, uAddress, uSize, sNameInError):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    # Make sure it is allocated
    assert oVirtualAllocation.bIsValid, \
        "Allocation for %s (0x%X bytes) at invalid address 0x%08X." % \
        (sNameInError, uSize, uAddress);
    assert oVirtualAllocation.bAllocated, \
        "Allocation for %s (0x%X bytes) at address 0x%08X not found:\r\n%s" % \
        (sNameInError, uSize, uAddress, "\r\n".join(oVirtualAllocation.fasDump()));
    assert uAddress + uSize < oVirtualAllocation.uEndAddress, \
        "Allocation for %s (0x%X bytes) at address 0x%08X is too small to contain expected value:\r\n%s" % \
        (sNameInError, uSize, uAddress, "\r\n".join(oVirtualAllocation.fasDump()));
    return oVirtualAllocation;
  
  def fs0ReadBytesForAddressAndSize(oSelf, uAddress, uSize):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return None; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fsReadBytesForAddressAndSize(uOffset, uSize);  
  
  def fs0ReadStringForAddressAndLength(oSelf, uAddress, uLength, bUnicode = False):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return None; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fsReadStringForOffsetAndLength(uOffset, uLength, bUnicode = bUnicode);  
  
  def fs0ReadNullTerminatedStringForAddress(oSelf, uAddress, bUnicode = False):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return None; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fs0ReadNullTerminatedStringForOffset(uOffset, bUnicode);  
  
  def fu0ReadValueForAddressAndSize(oSelf, uAddress, uSize):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return None; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fuReadValueForOffsetAndSize(uOffset, uSize);  
  
  def fa0uReadValuesForOffsetSizeAndCount(oSelf, uOffset, uSize, uCount):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return None; # TOCTOU
    return oVirtualAllocation.fauReadValuesForOffsetSizeAndCount(uOffset, uSize, uCount);  
  
  def fu0ReadPointerForAddress(oSelf, uAddress):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return None; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fuReadPointerForOffset(uOffset);  
  
  def fa0uReadPointersForAddressAndCount(oSelf, uAddress, uCount):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return None; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fauReadPointersForOffsetAndCount(uOffset, uCount);  
  
  def fo0ReadStructureUsingPointer(oSelf, oStructurePointer):
    return oSelf.fo0ReadStructureForAddress(
      oStructurePointer.c0TargetClass,
      oStructurePointer.fuGetValue(),
    );
  def fo0ReadStructureForAddress(oSelf, cStructure, uAddress):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return None; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    if gbDebugOutput:
      print(
        "Reading %s @ 0x%X, which is at offset 0x%X from start address in this virtual allocation:" % \
        (cStructure.__name__, uAddress, uOffset)
      );
      for sLine in oVirtualAllocation.fasDump():
        print("  " + sLine);
    return oVirtualAllocation.foReadStructureForOffset(cStructure, uOffset);  
  
  def fbWriteBytesForAddress(oSelf, sData, uAddress):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return False; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    oVirtualAllocation.fWriteBytesForOffset(sData, uOffset);  
    return True;
  
  def fbWriteStringForAddress(oSelf, sData, uAddress, bUnicode = False):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    if not oVirtualAllocation.bIsValid or not oVirtualAllocation.bAllocated:
      return False; # TOCTOU
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    oVirtualAllocation.fWriteStringForOffset(sData, uOffset, bUnicode);  
    return True;
  
  @property
  def uIntegrityLevel(oSelf):
    return fuGetIntegrityLevelForProcessId(oSelf.uId);
  
  @property
  def uMemoryUsage(oSelf):
    return fuGetMemoryUsageForProcessId(oSelf.uId);
  
  def faoGetThreads(oSelf):
    ohThreadsSnapshot = oKernel32DLL.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if not fbIsValidHandle(ohThreadsSnapshot):
      fThrowLastError("CreateToolhelp32Snapshot(0x%08X, 0)", TH32CS_SNAPTHREAD);
    
    oThreadEntry32 = THREADENTRY32();
    oThreadEntry32.dwSize = oThreadEntry32.fuGetSize();
    opoThreadEntry32 = oThreadEntry32.foCreatePointer();
    bGotThread = oKernel32DLL.Thread32First(ohThreadsSnapshot, opoThreadEntry32)
    bFirstThread = True;
    aoThreads = [];
    while bGotThread:
      bFirstThread = False;
      if oThreadEntry32.th32OwnerProcessID == oSelf.uId:
        aoThreads.append(cThread(oSelf, oThreadEntry32.th32ThreadID.fuGetValue()));
      bGotThread = oKernel32DLL.Thread32Next(ohThreadsSnapshot, opoThreadEntry32);
    if not fbLastErrorIs(ERROR_NO_MORE_FILES):
      sFunctionName = "Thread32%s" % ("First" if bFirstThread else "Next",);
      fThrowLastError("%s(%s, %s)" % (sFunctionName, repr(ohThreadsSnapshot), repr(opoThreadEntry32)));
    if not oKernel32DLL.CloseHandle(ohThreadsSnapshot):
      fThrowLastError("CloseHandle(%s)" % (repr(ohThreadsSnapshot),));
    return aoThreads;
  
  def foGetThreadForId(oSelf, uId):
    return cThread(oSelf, uId);
  
  def fuCreateThreadForAddress(oSelf, uAddress, **dxArguments):
    return fuCreateThreadForProcessIdAndAddress(oSelf.uId, uAddress, **dxArguments);
  
  def fs0GetBinaryPathForModuleAddress(oSelf, uAddress):
    return fs0GetBinaryPathForProcessAndModuleHandle(
      oSelf.fohOpenWithFlags(PROCESS_QUERY_LIMITED_INFORMATION),
      HMODULE(uAddress), # conveniently, an HMODULE's value is the address where the module is loaded.
    );
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    sAccessRightsFlagsDescription = oSelf.fs0GetAccessRightsFlagsDescription();
    return [s for s in [
      "pid = 0x%X" % (oSelf.uId,),
      "ISA = %s" % (oSelf.sISA,),
      "command = %s" % (oSelf.__sCommandLine,) if oSelf.__sCommandLine else
        "binary = %s" % (oSelf.__s0BinaryPath,) if oSelf.__s0BinaryPath else
        None,
      "access = %s" % (sAccessRightsFlagsDescription,) if sAccessRightsFlagsDescription else "no access",
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));

