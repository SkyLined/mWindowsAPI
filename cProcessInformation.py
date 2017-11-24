import os;

from mDefines import *;
from mTypes import *;
from mDLLs import KERNEL32, NTDLL;
from cVirtualAllocation import cVirtualAllocation;
from fsGetPythonISA import fsGetPythonISA;
from fsGetProcessISAFor_ import fsGetProcessISAForHandle;

def foGetVirtualAllocationHelper(uProcessId, uAddress, sNameInError):
  
  oVirtualAllocation = cVirtualAllocation.foGetForProcessIdAndAddress(uProcessId, uAddress);
  assert oVirtualAllocation, \
      "Cannot read virtual allocation for %s at address 0x%08X" % (sNameInError, uAddress);
  assert oVirtualAllocation.bAllocated, \
      "No allocation for %s at address 0x%08X" % (sNameInError, uAddress);
  return oVirtualAllocation;

class cProcessInformation(object):
  @staticmethod
  def foGetForId(uProcessId):
    # Try to open the process...
    hProcess = KERNEL32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, uProcessId);
    assert hProcess, \
        "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, 0x%08X) => Error 0x%08X" % (uProcessId, KERNEL32.GetLastError());
    try:
      return cProcessInformation.foGetForProcessIdAndHandle(uProcessId, hProcess);
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
  
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
    uNTStatus = NTDLL.ZwQueryInformationProcess(
      hProcess,# ProcessHandle
      ProcessBasicInformation, # ProcessInformationClass
      CAST(PVOID, POINTER(oProcessBasicInformation)), # ProcessInformation
      SIZEOF(oProcessBasicInformation), # ProcessInformationLength
      POINTER(uReturnLength), # ReturnLength
    );
    assert uNTStatus == STATUS_SUCCESS, \
        "ZwQueryInformationProcess(0x%X, ProcessBasicInformation, ..., 0x%X, ...) == 0x%08X" % \
        (hProcess, SIZEOF(oProcessBasicInformation), uNTStatus);
    assert uReturnLength.value == SIZEOF(oProcessBasicInformation), \
        "ZwQueryInformationProcess(0x%X, ProcessBasicInformation, ..., 0x%X, ...) wrote 0x%X bytes" % \
        (hProcess, SIZEOF(oProcessBasicInformation), uReturnLength.value);
    
    # Read PEB
    uPEBAddress = oProcessBasicInformation.PebBaseAddress;
    oVirtualAllocation = foGetVirtualAllocationHelper(uProcessId, uPEBAddress, "PEB");
    oPEB = oVirtualAllocation.foReadStructure(
      cStructure = {"x86": PEB_32, "x64": PEB_64}[sPythonISA],
      uOffset = uPEBAddress - oVirtualAllocation.uStartAddress,
    );
#      oPEB.fDump();
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
    oSelf.sBinaryName = os.path.basename(sBinaryPath);
    oSelf.sCommandLine = sCommandLine;
