from mWindowsAPI import *;

class cProcessInformation(object):
  @staticmethod
  def foGetForId(uProcessId):
    # Try to open the process...
    hProcess = KERNEL32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, uProcessId);
    assert hProcess, \
        "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, 0x%08X) => Error 0x%08X" % (uProcessId, KERNEL32.GetLastError());
    try:
      # If we are running in 64-bit Python, ZwQueryInformationProcess will return a pointer to the 64-bit PEB of
      # another process in the PROCESS_BASIC_INFORMATION struct. If we are running in 32-bit Python, we cannot get
      # information on a 64-bit process unless we start doing some dirty hacks, which I'd rather not. To find out if
      # the PEB is 32- or 64-bit, and assert if we cannot get the info because the target is 64-bit and we are 32, we
      # will need to find out the bitness of Python, the OS and the target process:
      from fsGetPythonISA import fsGetPythonISA;
      sPythonISA = fsGetPythonISA();
      from fsGetOSISA import fsGetOSISA;
      if fsGetOSISA() == "x64":
        bIsWow64Process = BOOL();
        assert KERNEL32.IsWow64Process(hProcess, POINTER(bIsWow64Process)), \
              "KERNEL32.IsWow64Process(%d/0x%X, ...): 0x%X" % \
              (uProcessId, uProcessId, uErrorCode);
        sProcessISA = bIsWow64Process and "x86" or "x64";
        if sPythonISA == "x86":
          # Finally we find out if the remote process is 64-bit and throw an error if this is the case:
          assert sProcessISA != "x64", \
              "Getting the command line of a 64-bit process from 32-bit Python process is not implemented";
      else:
        sProcessISA = "x86";
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
      
      def foGetVirtualAllocation(uAddress, sNameInError):
        oVirtualAllocation = cVirtualAllocation.foGetForProcessIdAndAddress(uProcessId, uAddress);
        assert oVirtualAllocation, \
            "Cannot read virtual allocation for %s at address 0x%08X" % (sNameInError, uAddress);
        assert oVirtualAllocation.bAllocated, \
            "No allocation for %s at address 0x%08X" % (sNameInError, uAddress);
        return oVirtualAllocation;
      
      # Read PEB
      uPEBAddress = oProcessBasicInformation.PebBaseAddress;
      oVirtualAllocation = foGetVirtualAllocation(uPEBAddress, "PEB");
      oPEB = oVirtualAllocation.foReadStructure(
        cStructure = {"x86": PEB_32, "x64": PEB_64}[sPythonISA],
        uOffset = uPEBAddress - oVirtualAllocation.uStartAddress,
      );
#      oPEB.fDump();
      uImageBaseAddress = oPEB.ImageBaseAddress;
      # Read Process Parameters
      uProcessParametersAddress = oPEB.ProcessParameters;
      oVirtualAllocation = foGetVirtualAllocation(uProcessParametersAddress, "Process Parameters");
      oProcessParameters = oVirtualAllocation.foReadStructure(
        cStructure = {"x86": RTL_USER_PROCESS_PARAMETERS_32, "x64": RTL_USER_PROCESS_PARAMETERS_64}[sPythonISA],
        uOffset = uProcessParametersAddress - oVirtualAllocation.uStartAddress,
      );
#      oProcessParameters.fDump();
      # Read Image Path Name
      uImagePathNameAddress = oProcessParameters.ImagePathName.Buffer;
      oVirtualAllocation = foGetVirtualAllocation(uImagePathNameAddress, "Image Path Name");
      sImagePathName = oVirtualAllocation.fsReadDataForOffsetAndSize(
        uOffset = uImagePathNameAddress - oVirtualAllocation.uStartAddress,
        uSize = oProcessParameters.ImagePathName.Length,
        bUnicode = True,
      );
      # Read Command Line
      uCommandLineAddress = oProcessParameters.CommandLine.Buffer;
      oVirtualAllocation = foGetVirtualAllocation(uCommandLineAddress, "Command Line");
      sCommandLine = oVirtualAllocation.fsReadDataForOffsetAndSize(
        uOffset = uCommandLineAddress - oVirtualAllocation.uStartAddress,
        uSize = oProcessParameters.CommandLine.Length,
        bUnicode = True,
      );
      return cProcessInformation(sProcessISA, uImageBaseAddress, sImagePathName, sCommandLine);
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
  
  def __init__(oSelf, sISA, uBinaryStartAddress, sBinaryPath, sCommandLine):
    oSelf.sISA = sISA;
    oSelf.uBinaryStartAddress = uBinaryStartAddress;
    oSelf.sBinaryPath = sBinaryPath;
    oSelf.sCommandLine = sCommandLine;
