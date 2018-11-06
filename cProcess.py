import os;

from .fbIsRunningForProcessHandle import fbIsRunningForProcessHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fbTerminateForProcessHandle import fbTerminateForProcessHandle;
from .fbWaitForTerminationForProcessHandle import fbWaitForTerminationForProcessHandle;
from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
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
from .mDefines import *;
from .mDLLs import KERNEL32, NTDLL;
from .mFunctions import *;
from .mTypes import *;

class cProcess(object):
  def __init__(oSelf, uId, hProcess = None):
    oSelf.uId = uId;
    if hProcess is None:
      # Try to open the process if no handle is provided...
      hProcess = fhOpenForProcessIdAndDesiredAccess(uId, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ);
    oSelf.__hProcess = hProcess;
    # If we are running in 64-bit Python, NtQueryInformationProcess will return a pointer to the 64-bit PEB of
    # another process in the PROCESS_BASIC_INFORMATION struct. If we are running in 32-bit Python, we cannot get
    # information on a 64-bit process unless we start doing some dirty hacks, which I'd rather not. To find out if
    # the PEB is 32- or 64-bit, we will need to find out the bitness of Python, the OS and the target process:
    oSelf.sISA = fsGetISAForProcessHandle(oSelf.__hProcess);
    assert oSelf.sISA == "x86" or fsGetPythonISA() == "x64", \
        "You cannot get information on a 64-bit process from 32-bit Python";
    oSelf.uPointerSize = {"x86": 4, "x64": 8}[oSelf.sISA];
    # Cahce for dynamically retreieved properties:
    oSelf.__oPEB = None;
    oSelf.__oProcessParameters = None;
    oSelf.__sBinaryPath = None;
    oSelf.__sCommandLine = None;
    oSelf.__doThread_by_uId = {};
  
  @property
  def oPEB(oSelf):
    if oSelf.__oPEB is None:
      # The type of PROCESS_BASIC_INFORMATION returned by NtQueryInformationProcess depends on the ISA of the process
      # calling it, in this case it's the Python process we're running in:
      cProcessBasicInformation = {"x86": PROCESS_BASIC_INFORMATION_32, "x64": PROCESS_BASIC_INFORMATION_64}[fsGetPythonISA()];
      oProcessBasicInformation = cProcessBasicInformation();
      uReturnLength = ULONG();
      oNTStatus = NTDLL.NtQueryInformationProcess(
        oSelf.__hProcess,# ProcessHandle
        ProcessBasicInformation, # ProcessInformationClass
        fxCast(PVOID, POINTER(oProcessBasicInformation)), # ProcessInformation
        fuSizeOf(oProcessBasicInformation), # ProcessInformationLength
        POINTER(uReturnLength), # ReturnLength
      );
      if not SUCCEEDED(oNTStatus):
        fThrowError("NtQueryInformationProcess(0x%X, ProcessBasicInformation, ..., 0x%X, ...)" % \
              (oSelf.__hProcess.value, fuSizeOf(oProcessBasicInformation)), oNTStatus.value);
      assert uReturnLength.value == fuSizeOf(oProcessBasicInformation), \
          "NtQueryInformationProcess(0x%X, 0x%08X, ..., 0x%X, ...) wrote 0x%X bytes" % \
          (oSelf.__hProcess.value, ProcessBasicInformation, fuSizeOf(oProcessBasicInformation), uReturnLength.value);
      # Read PEB
      uPEBAddress = fuPointerValue(oProcessBasicInformation.PebBaseAddress);
      # The type of PEB (32- or 64-bit) depends on the type of PROCESS_BASIC_INFORMATION (see above)
      cPEB = {"x86": PEB_32, "x64": PEB_64}[fsGetPythonISA()];
      oVirtualAllocation = oSelf.foGetAllocatedVirtualAllocationWithSizeCheck(uPEBAddress, fuSizeOf(cPEB), "PEB");
      oSelf.__oPEB = oVirtualAllocation.foReadStructureForOffset(
        cStructure = cPEB,
        uOffset = uPEBAddress - oVirtualAllocation.uStartAddress,
      );
    return oSelf.__oPEB;
  
  @property
  def uBinaryStartAddress(oSelf):
    return fuPointerValue(oSelf.oPEB.ImageBaseAddress);
  
  @property
  def oProcessParameters(oSelf):
    if oSelf.__oProcessParameters is None:
      # Read Process Parameters
      uProcessParametersAddress = fuPointerValue(oSelf.oPEB.ProcessParameters);
      # The type of RTL_USER_PROCESS_PARAMETERS (32- or 64-bit) depends on the type of PROCESS_BASIC_INFORMATION (see above)
      cRtlUserProcessParameters = {"x86": RTL_USER_PROCESS_PARAMETERS_32, "x64": RTL_USER_PROCESS_PARAMETERS_64}[fsGetPythonISA()];
      oVirtualAllocation = oSelf.foGetAllocatedVirtualAllocationWithSizeCheck(uProcessParametersAddress, fuSizeOf(cRtlUserProcessParameters), "Process Parameters");
      oSelf.__oProcessParameters = oVirtualAllocation.foReadStructureForOffset(
        cStructure = cRtlUserProcessParameters,
        uOffset = uProcessParametersAddress - oVirtualAllocation.uStartAddress,
      );
    return oSelf.__oProcessParameters;
  
  @property
  def sBinaryPath(oSelf):
    if oSelf.__sBinaryPath is None:
      # Read Image Path Name
      uImagePathNameAddress = fuPointerValue(oSelf.oProcessParameters.ImagePathName.Buffer);
      uImagePathNameSize = oSelf.oProcessParameters.ImagePathName.Length;
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
      uCommandLineAddress = fuPointerValue(oSelf.oProcessParameters.CommandLine.Buffer);
      uCommandLineSize = oSelf.oProcessParameters.CommandLine.Length;
      oVirtualAllocation = oSelf.foGetAllocatedVirtualAllocationWithSizeCheck(uCommandLineAddress, uCommandLineSize, "Command Line");
      oSelf.__sCommandLine = oVirtualAllocation.fsReadStringForOffsetAndSize(
        uOffset = uCommandLineAddress - oVirtualAllocation.uStartAddress,
        uSize = uCommandLineSize,
        bUnicode = True,
      );
    return oSelf.__sCommandLine;
  
  def __del__(oSelf):
    try:
      oSelf.__hProcess;
    except AttributeError:
      return;
    if not KERNEL32.CloseHandle(oSelf.__hProcess):
      fThrowLastError("CloseHandle(0x%X)" % (oSelf.__hProcess.value,));
  
  @property
  def bIsRunning(oSelf):
    return fbIsRunningForProcessHandle(oSelf.__hProcess);
  
  def fbTerminate(oSelf, uTimeout = None):
    return fbTerminateForProcessHandle(oSelf.__hProcess, uTimeout);
  
  def fbWait(oSelf, uTimeout = None):
    return fbWaitForTerminationForProcessHandle(oSelf.__hProcess, uTimeout);
  
  def fSuspend(oSelf):
    return fSuspendForProcessId(oSelf.uId);
  
  def fSuspendThreads(oSelf):
    for oThread in oSelf.faoGetThreads():
      oThread.fSuspend();
  
  @property
  def uExitCode(oSelf):
    return fuGetExitCodeForProcessHandle(oSelf.__hProcess);
  
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
    hThreadsSnapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if not fbIsValidHandle(hThreadsSnapshot):
      fThrowLastError("CreateToolhelp32Snapshot(0x%08X, 0)", TH32CS_SNAPTHREAD);
    
    oThreadEntry32 = THREADENTRY32();
    oThreadEntry32.dwSize = fuSizeOf(oThreadEntry32);
    bGotThread = KERNEL32.Thread32First(hThreadsSnapshot, POINTER(oThreadEntry32))
    bFirstThread = True;
    aoThreads = [];
    while bGotThread:
      bFirstThread = False;
      if oThreadEntry32.th32OwnerProcessID == oSelf.uId:
        aoThreads.append(cThread(oSelf, oThreadEntry32.th32ThreadID));
      bGotThread = KERNEL32.Thread32Next(hThreadsSnapshot, POINTER(oThreadEntry32));
    if not fbLastErrorIs(ERROR_NO_MORE_FILES):
      fThrowLastError("Thread32%s(0x%08X, ...)" % (bFirstThread and "First" or "Next", hThreadsSnapshot.value,));
    if not KERNEL32.CloseHandle(hThreadsSnapshot):
      fThrowLastError("CloseHandle(0x%08X)" % (hThreadsSnapshot.value,));
    return aoThreads;
  
  def foGetThreadForId(oSelf, uId):
    return cThread(oSelf, uId);
  
  def fuCreateThreadForAddress(oSelf, uAddress, **dxArguments):
    return fuCreateThreadForProcessIdAndAddress(oSelf.uId, uAddress, **dxArguments);