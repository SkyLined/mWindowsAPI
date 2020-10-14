import os;

from mWindowsSDK import *;
from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fbTerminateForProcessHandle import fbTerminateForProcessHandle;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fuCreateThreadForProcessIdAndAddress import fuCreateThreadForProcessIdAndAddress;
from .fsGetPythonISA import fsGetPythonISA;
from .fsGetISAForProcessHandle import fsGetISAForProcessHandle;
from .fSuspendForProcessId import fSuspendForProcessId;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;
from .fuGetExitCodeForProcessHandle import fuGetExitCodeForProcessHandle;
from .fuGetIntegrityLevelForProcessId import fuGetIntegrityLevelForProcessId;
from .fuGetMemoryUsageForProcessId import fuGetMemoryUsageForProcessId;
from .cThread import cThread;
from .cVirtualAllocation import cVirtualAllocation;

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
    oKernel32 = foLoadKernel32DLL();
    sCommandLine = " ".join([
      (s and (s[0] == '"' or s.find(" ") == -1)) and s or '"%s"' % s.replace('"', '\\"')
      for s in [sBinaryPath] + asArguments
    ]);
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
    oStartupInfo.wShowWindow = SW_HIDE if bHidden else SW_SHOWMINNOACTIVE if bMinimizedWindow else SW_SHOWMAXIMIZED if bMaximizedWindow else 0;
    oStartupInfo.hStdInput = oKernel32.GetStdHandle(STD_INPUT_HANDLE);
    oStartupInfo.hStdOutput = oKernel32.GetStdHandle(STD_OUTPUT_HANDLE);
    oStartupInfo.hStdError = oKernel32.GetStdHandle(STD_ERROR_HANDLE);
    oProcessInformation = PROCESS_INFORMATION();
    if not oKernel32.CreateProcessW(
      foCreateBuffer(sBinaryPath, bUnicode = True).foCreatePointer(PCWSTR), # lpApplicationName
      foCreateBuffer(sCommandLine, bUnicode = True).foCreatePointer(PWSTR), # lpCommandLine
      NULL, # lpProcessAttributes
      NULL, # lpThreadAttributes
      TRUE, # bInheritHandles
      odwCreationFlags, # dwCreationFlags
      NULL, # lpEnvironment
      foCreateBuffer(sWorkingDirectory, bUnicode = True).foCreatePointer(PCWSTR) if sWorkingDirectory else NULL, # lpCurrentDirectory
      oStartupInfo.foCreatePointer(), # lpStartupInfo
      oProcessInformation.foCreatePointer(), # lpProcessInformation
    ):
      if not fbLastErrorIs(ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_INVALID_NAME):
        fThrowLastError("CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...)" % \
            (repr(sBinaryPath), repr(sCommandLine), odwCreationFlags.value, repr(sWorkingDirectory)));
      return None;
    # Close all handles that we no longer need:
    if not oKernel32.CloseHandle(oProcessInformation.hThread):
      fThrowLastError("CloseHandle(0x%X)" % (oProcessInformation.hThread.value,));
    return cClass(oProcessInformation.dwProcessId.value, ohProcess = oProcessInformation.hProcess, uProcessHandleFlags = PROCESS_ALL_ACCESS);
  
  def __init__(oSelf, uId, ohProcess = None, uProcessHandleFlags = None):
    assert isinstance(uId, (int, long)), \
        "uId must be an integer not %s" % repr(uId);
    oSelf.uId = uId;
    if ohProcess:
      assert isinstance(ohProcess, HANDLE), \
          "ohProcess (%s) is not a valid handle" % repr(ohProcess);
      assert uProcessHandleFlags is not None, \
          "You must provide uProcessHandleFlags when you provide ohProcess";
      # Try to open the process if no handle is provided...
      oSelf.__ohProcess = ohProcess;
      oSelf.__uProcessHandleFlags = uProcessHandleFlags;
    else:
      oSelf.__uProcessHandleFlags = 0;
      oSelf.__ohProcess = None;
    # If we are running in 64-bit Python, NtQueryInformationProcess will return a pointer to the 64-bit PEB of
    # another process in the PROCESS_BASIC_INFORMATION struct. If we are running in 32-bit Python, we cannot get
    # information on a 64-bit process unless we start doing some dirty hacks, which I'd rather not. To find out if
    # the PEB is 32- or 64-bit, we will need to find out the bitness of Python, the OS and the target process:
    oSelf.sISA = fsGetISAForProcessHandle(oSelf.fohOpenWithFlags(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ));
    assert oSelf.sISA == "x86" or fsGetPythonISA() == "x64", \
        "You cannot get information on a 64-bit process from 32-bit Python";
    oSelf.uPointerSize = {"x86": 4, "x64": 8}[oSelf.sISA];
    # Cache for dynamically retreieved properties:
    oSelf.__sBinaryPath = None;
    oSelf.__sCommandLine = None;
  
  def fohOpenWithFlags(oSelf, uRequiredFlags):
    # See if we have an open handle
    if oSelf.__ohProcess and oSelf.__ohProcess.value != INVALID_HANDLE_VALUE:
      # if it already has the required flags, return it:
      if oSelf.__uProcessHandleFlags & uRequiredFlags == uRequiredFlags:
        return oSelf.__ohProcess;
      ohOldProcessHandle = oSelf.__ohProcess;
    else:
      ohOldProcessHandle = None;
    # Open a new handle with the required flags and all other flags we've used before.
    # This allows the new handle to be used for anything it was used for before as well
    # as anything new the caller wants to do:
    uFlags = oSelf.__uProcessHandleFlags | uRequiredFlags;
    ohProcess = fohOpenForProcessIdAndDesiredAccess(oSelf.uId, uFlags);
    oSelf.__ohProcess = ohProcess;
    oSelf.__uProcessHandleFlags = uFlags if ohProcess.value != INVALID_HANDLE_VALUE else 0;
    if ohOldProcessHandle:
      # If it does not have the required flags, close it:
      oKernel32 = foLoadKernel32DLL();
      if not oKernel32.CloseHandle(oSelf.__ohProcess):
        fThrowLastError("CloseHandle(0x%X)" % (oSelf.__ohProcess.value,));
    return ohProcess;
  
  def fs0GetAccessRightsFlagsDescription(oSelf):
    if oSelf.__ohProcess is None or oSelf.__ohProcess.value == INVALID_HANDLE_VALUE:
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
    ouReturnLength = ULONG();
    oNTDLL = foLoadNTDLL();
    oNTStatus = oNTDLL.NtQueryInformationProcess(
      oSelf.fohOpenWithFlags(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ),# ProcessHandle
      ProcessBasicInformation, # ProcessInformationClass
      oProcessBasicInformation.foCreatePointer(PVOID), # ProcessInformation
      oProcessBasicInformation.fuGetSize(), # ProcessInformationLength
      ouReturnLength.foCreatePointer(), # ReturnLength
    );
    if NT_ERROR(oNTStatus):
      fThrowError("NtQueryInformationProcess(ProcessHandle=0x%X, ProcessInformationClass=0x%X, ProcessInformation=0x%X, ProcessInformationLength=0x%X, ReturnLength=0x%X)" % \
            (oSelf.__ohProcess.value, ProcessBasicInformation, oProcessBasicInformation.fuGetAddress(),
            oProcessBasicInformation.fuGetSize(), ouReturnLength.fuGetAddress()), oNTStatus.value);
    assert ouReturnLength.value == oProcessBasicInformation.fuGetSize(), \
        "NtQueryInformationProcess(0x%X, 0x%08X, ..., 0x%X, ...) wrote 0x%X bytes" % \
        (oSelf.__ohProcess.value, ProcessBasicInformation, oProcessBasicInformation.fuGetSize(), ouReturnLength.value);
    # Read PEB
    uPEBAddress = oProcessBasicInformation.PebBaseAddress.value;
    # The type of PEB (32- or 64-bit) depends on the type of PROCESS_BASIC_INFORMATION (see above)
    cPEB = oProcessBasicInformation.PebBaseAddress.cTargetType;
    oVirtualAllocation = oSelf.foGetAllocatedVirtualAllocationWithSizeCheck(uPEBAddress, cPEB.fuGetSize(), "PEB");
    oPEB = oVirtualAllocation.foReadStructureForOffset(
      cStructure = cPEB,
      uOffset = uPEBAddress - oVirtualAllocation.uStartAddress,
    );
    return oPEB;
  
  @property
  def uBinaryStartAddress(oSelf):
    return oSelf.foGetPEB().ImageBaseAddress.value;
  
  def foGetProcessParameters(oSelf):
    # Read Process Parameters
    uProcessParametersAddress = oSelf.foGetPEB().ProcessParameters.value;
    # The type of RTL_USER_PROCESS_PARAMETERS (32- or 64-bit) depends on the type of PROCESS_BASIC_INFORMATION (see above)
    cRtlUserProcessParameters = {"x86": RTL_USER_PROCESS_PARAMETERS32, "x64": RTL_USER_PROCESS_PARAMETERS64}[fsGetPythonISA()];
    oVirtualAllocation = oSelf.foGetAllocatedVirtualAllocationWithSizeCheck(uProcessParametersAddress, cRtlUserProcessParameters.fuGetSize(), "Process Parameters");
    oProcessParameters = oVirtualAllocation.foReadStructureForOffset(
      cStructure = cRtlUserProcessParameters,
      uOffset = uProcessParametersAddress - oVirtualAllocation.uStartAddress,
    );
    return oProcessParameters;
  
  @property
  def sBinaryPath(oSelf):
    if oSelf.__sBinaryPath is None:
      # Read Image Path Name
      oProcessParameters = oSelf.foGetProcessParameters();
      uImagePathNameAddress = oProcessParameters.ImagePathName.Buffer.value;
      uImagePathNameSize = oProcessParameters.ImagePathName.Length.value;
      oVirtualAllocation = oSelf.foGetAllocatedVirtualAllocationWithSizeCheck(uImagePathNameAddress, uImagePathNameSize, "Image Path Name");
      oSelf.__sBinaryPath = oVirtualAllocation.fsReadStringForOffsetAndSize(
        uOffset = uImagePathNameAddress - oVirtualAllocation.uStartAddress,
        uSize = uImagePathNameSize,
        bUnicode = True,
      );
    return oSelf.__sBinaryPath;
  
  @property
  def sBinaryName(oSelf):
    return oSelf.sBinaryPath and os.path.basename(oSelf.sBinaryPath) or None;
  
  @property
  def sCommandLine(oSelf):
    if oSelf.__sCommandLine is None:
      # Read Command Line
      oProcessParameters = oSelf.foGetProcessParameters();
      uCommandLineAddress = oProcessParameters.CommandLine.Buffer.value;
      uCommandLineSize = oProcessParameters.CommandLine.Length.value;
      oVirtualAllocation = oSelf.foGetAllocatedVirtualAllocationWithSizeCheck(
        uCommandLineAddress,
        uCommandLineSize,
        "Command Line"
      );
      oSelf.__sCommandLine = oVirtualAllocation.fsReadStringForOffsetAndSize(
        uOffset = uCommandLineAddress - oVirtualAllocation.uStartAddress,
        uSize = uCommandLineSize,
        bUnicode = True,
      );
    return oSelf.__sCommandLine;
  
  def __del__(oSelf):
    try:
      ohProcess = oSelf.__ohProcess;
    except AttributeError:
      return;
    oKernel32 = foLoadKernel32DLL();
    if not oKernel32.CloseHandle(ohProcess):
      fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
  
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
    return fSuspendForProcessHandle(oSelf.fohOpenWithFlags(PROCESS_SUSPEND_RESUME ));
  
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
  
  def foCreateVirtualAllocation(oSelf, uSize, uAddress = None, bReserved = False, uProtection = None):
    return cVirtualAllocation.foCreateForProcessId(
      oSelf.uId,
      uSize,
      uAddress,
      bReserved,
      uProtection
    );
  
  def foGetVirtualAllocationForAddress(oSelf, uAddress):
    return cVirtualAllocation(oSelf.uId, uAddress);

  def foGetAllocatedVirtualAllocationWithSizeCheck(oSelf, uAddress, uSize, sNameInError):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    # Make sure it is allocated
    assert oVirtualAllocation.bAllocated, \
        "Allocation for %s (0x%X bytes) at address 0x%08X not found:\r\n%s" % \
        (sNameInError, uSize, uAddress, "\r\n".join(oVirtualAllocation.fasDump()));
    assert uAddress + uSize < oVirtualAllocation.uEndAddress, \
        "Allocation for %s (0x%X bytes) at address 0x%08X is too small to contain expected value:\r\n%s" % \
        (sNameInError, uSize, uAddress, "\r\n".join(oVirtualAllocation.fasDump()));
    return oVirtualAllocation;
  
  def fsReadBytesForAddressAndSize(oSelf, uAddress, uSize):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fsReadBytesForAddressAndSize(uOffset, uSize);  
  
  def fsReadStringForAddressAndSize(oSelf, uAddress, uSize):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fsReadStringForOffsetAndSize(uOffset, uSize);  

  def fsReadNullTerminatedStringForAddress(oSelf, uAddress, bUnicode = False):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fsReadNullTerminatedStringForOffset(uOffset, bUnicode);  
  
  def fauReadDataForAddressAndSize(oSelf, uAddress, uSize):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fauReadDataForOffsetAndSize(uOffset, uSize);  

  def fuReadValueForAddressAndSize(oSelf, uAddress, uSize):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fuReadValueForOffsetAndSize(uOffset, uSize);  
  
  def fauReadValuesForOffsetSizeAndCount(oSelf, uAddress, uSize, uCount):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fauReadValuesForOffsetSizeAndCount(uOffset, uSize, uCount);  
  
  def fuReadPointerForAddress(oSelf, uAddress):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fuReadPointerForOffset(uOffset);  

  def fauReadPointersForAddressAndCount(oSelf, uAddress, uCount):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fauReadPointersForOffsetAndCount(uOffset, uCount);  
  
  def foReadStructureForAddress(oSelf, cStructure, uAddress):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.foReadStructureForOffset(cStructure, uOffset);  
  
  def fWriteBytesForAddress(oSelf, sData, uAddress):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fWriteBytesForOffset(sData, uOffset);  
  
  def fWriteStringForAddress(oSelf, sData, uAddress, bUnicode = False):
    oVirtualAllocation = cVirtualAllocation(oSelf.uId, uAddress);
    uOffset = uAddress - oVirtualAllocation.uStartAddress;
    return oVirtualAllocation.fWriteStringForOffset(sData, uOffset, bUnicode);  
  
  @property
  def uIntegrityLevel(oSelf):
    return fuGetIntegrityLevelForProcessId(oSelf.uId);
  
  @property
  def uMemoryUsage(oSelf):
    return fuGetMemoryUsageForProcessId(oSelf.uId);
  
  def faoGetThreads(oSelf):
    oKernel32 = foLoadKernel32DLL();
    ohThreadsSnapshot = oKernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if not fbIsValidHandle(ohThreadsSnapshot):
      fThrowLastError("CreateToolhelp32Snapshot(0x%08X, 0)", TH32CS_SNAPTHREAD);
    
    oThreadEntry32 = THREADENTRY32();
    oThreadEntry32.dwSize = oThreadEntry32.fuGetSize();
    opoThreadEntry32 = oThreadEntry32.foCreatePointer();
    bGotThread = oKernel32.Thread32First(ohThreadsSnapshot, opoThreadEntry32)
    bFirstThread = True;
    aoThreads = [];
    while bGotThread:
      bFirstThread = False;
      if oThreadEntry32.th32OwnerProcessID.value == oSelf.uId:
        aoThreads.append(cThread(oSelf, oThreadEntry32.th32ThreadID.value));
      bGotThread = oKernel32.Thread32Next(ohThreadsSnapshot, opoThreadEntry32);
    if not fbLastErrorIs(ERROR_NO_MORE_FILES):
      fThrowLastError("Thread32%s(0x%08X, ...)" % (bFirstThread and "First" or "Next", ohThreadsSnapshot.value,));
    if not oKernel32.CloseHandle(ohThreadsSnapshot):
      fThrowLastError("CloseHandle(0x%08X)" % (ohThreadsSnapshot.value,));
    return aoThreads;
  
  def foGetThreadForId(oSelf, uId):
    return cThread(oSelf, uId);
  
  def fuCreateThreadForAddress(oSelf, uAddress, **dxArguments):
    return fuCreateThreadForProcessIdAndAddress(oSelf.uId, uAddress, **dxArguments);

  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    sAccessRightsFlagsDescription = oSelf.fs0GetAccessRightsFlagsDescription();
    return [s for s in [
      "pid = 0x%X" % (oSelf.uId,),
      "ISA = %s" % (oSelf.sISA,),
      "command = %s" % (oSelf.__sCommandLine,) if oSelf.__sCommandLine else
        "binary = %s" % (oSelf.__sBinaryPath,) if oSelf.__sBinaryPath else
        None,
      "access = %s" % (sAccessRightsFlagsDescription,) if sAccessRightsFlagsDescription else "no access",
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));

