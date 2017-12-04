import os;

from mDefines import *;
from mTypes import *;
from mDLLs import KERNEL32, NTDLL;
from cVirtualAllocation import cVirtualAllocation;
from fsGetPythonISA import fsGetPythonISA;
from fsGetProcessISAFor_ import fsGetProcessISAForHandle;
from fsGetErrorMessage import fsGetErrorMessage;

def foGetVirtualAllocationHelper(uProcessId, uAddress, sNameInError):
  oVirtualAllocation = cVirtualAllocation(uProcessId, uAddress);
  assert oVirtualAllocation.bAllocated, \
      "No allocation for %s at address 0x%08X%s" % (sNameInError, uAddress, oVirtualAllocation.fDump() or "");
  return oVirtualAllocation;

class cProcessInformation(object):
  @staticmethod
  def foGetForId(uProcessId):
    # Try to open the process...
    uFlags = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
    assert hProcess, \
        fsGetErrorMessage("OpenProcess(0x%08X, FALSE, 0x%08X)" % (uFlags, uProcessId,));
    try:
      return cProcessInformation.foGetForProcessIdAndHandle(uProcessId, hProcess);
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess.value,));
  
  @staticmethod
  def foGetForProcessIdAndHandle(uProcessId, hProcess):
    # If we are running in 64-bit Python, ZwQueryInformationProcess will return a pointer to the 64-bit PEB of
    # another process in the PROCESS_BASIC_INFORMATION struct. If we are running in 32-bit Python, we cannot get
    # information on a 64-bit process unless we start doing some dirty hacks, which I'd rather not. To find out if
    # the PEB is 32- or 64-bit, we will need to find out the bitness of Python, the OS and the target process:
    sPythonISA = fsGetPythonISA();
    sProcessISA = fsGetProcessISAForHandle(hProcess);
    if sPythonISA == "x86" and sProcessISA == "x64":
      # We cannot get information on a 64-bit process from 32-bit Python
      return cProcessInformation(sProcessISA, None, None, None);
    oProcessBasicInformation = PROCESS_BASIC_INFORMATION();
    uReturnLength = ULONG();
    uProcessInformationClass = ProcessBasicInformation;
    uNTStatus = NTDLL.ZwQueryInformationProcess(
      hProcess,# ProcessHandle
      uProcessInformationClass, # ProcessInformationClass
      CAST(PVOID, POINTER(oProcessBasicInformation)), # ProcessInformation
      SIZEOF(oProcessBasicInformation), # ProcessInformationLength
      POINTER(uReturnLength), # ReturnLength
    );
    assert uNTStatus == STATUS_SUCCESS, \
        "ZwQueryInformationProcess(0x%X, 0x%08X, ..., 0x%X, ...) = 0x%08X" % \
        (hProcess, uProcessInformationClass, SIZEOF(oProcessBasicInformation), uNTStatus);
    assert uReturnLength.value == SIZEOF(oProcessBasicInformation), \
        "ZwQueryInformationProcess(0x%X, 0x%08X, ..., 0x%X, ...) wrote 0x%X bytes" % \
        (hProcess, uProcessInformationClass, SIZEOF(oProcessBasicInformation), uReturnLength.value);
    
    # Read PEB
    uPEBAddress = oProcessBasicInformation.PebBaseAddress;
    oVirtualAllocation = foGetVirtualAllocationHelper(uProcessId, uPEBAddress, "PEB");
    oPEB = oVirtualAllocation.foReadStructure(
      cStructure = {"x86": PEB_32, "x64": PEB_64}[sPythonISA],
      uOffset = uPEBAddress - oVirtualAllocation.uStartAddress,
    );
#    oPEB.fDump();
    uImageBaseAddress = oPEB.ImageBaseAddress;
    # Read Process Parameters
    uProcessParametersAddress = oPEB.ProcessParameters;
    oVirtualAllocation = foGetVirtualAllocationHelper(uProcessId, uProcessParametersAddress, "Process Parameters");
    oProcessParameters = oVirtualAllocation.foReadStructure(
      cStructure = {"x86": RTL_USER_PROCESS_PARAMETERS_32, "x64": RTL_USER_PROCESS_PARAMETERS_64}[sPythonISA],
      uOffset = uProcessParametersAddress - oVirtualAllocation.uStartAddress,
    );
#      oProcessParameters.fDump();
    # Read Image Path Name
    uImagePathNameAddress = oProcessParameters.ImagePathName.Buffer;
    oVirtualAllocation = foGetVirtualAllocationHelper(uProcessId, uImagePathNameAddress, "Image Path Name");
    sImagePathName = oVirtualAllocation.fsReadDataForOffsetAndSize(
      uOffset = uImagePathNameAddress - oVirtualAllocation.uStartAddress,
      uSize = oProcessParameters.ImagePathName.Length,
      bUnicode = True,
    );
    # Read Command Line
    uCommandLineAddress = oProcessParameters.CommandLine.Buffer;
    oVirtualAllocation = foGetVirtualAllocationHelper(uProcessId, uCommandLineAddress, "Command Line");
    sCommandLine = oVirtualAllocation.fsReadDataForOffsetAndSize(
      uOffset = uCommandLineAddress - oVirtualAllocation.uStartAddress,
      uSize = oProcessParameters.CommandLine.Length,
      bUnicode = True,
    );
    return cProcessInformation(sProcessISA, uImageBaseAddress, sImagePathName, sCommandLine);
  
  def __init__(oSelf, sISA, uBinaryStartAddress, sBinaryPath, sCommandLine):
    oSelf.sISA = sISA;
    oSelf.uBinaryStartAddress = uBinaryStartAddress;
    oSelf.sBinaryPath = sBinaryPath;
    oSelf.sBinaryName = sBinaryPath and os.path.basename(sBinaryPath) or None;
    oSelf.sCommandLine = sCommandLine;
