from mWindowsSDK import \
    ERROR_BAD_LENGTH, ERROR_NO_MORE_FILES, ERROR_PARTIAL_COPY, \
    MODULEENTRY32W, \
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from mWindowsSDK.mPsapi import oPsapiDLL;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fsGetISAForProcessId import fsGetISAForProcessId;
from .fsGetPythonISA import fsGetPythonISA;
from .fThrowLastError import fThrowLastError;

class cModule(object):
  def __init__(oSelf, uStartAddress, s0Name, s0BinaryPath):
    oSelf.uStartAddress = uStartAddress;
    oSelf.s0Name = s0Name;
    oSelf.s0BinaryPath = s0BinaryPath;

  @classmethod
  def faoGetForProcessId(cClass, uProcessId):
    aoModuleInformation = [];
    for uRetryCount in range(10):
      ohProcessSnapshot = oKernel32DLL.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        uProcessId,
      );
      if fbIsValidHandle(ohProcessSnapshot):
        break;
      if fbLastErrorIs(ERROR_BAD_LENGTH):
        # https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
        # "If the function fails with ERROR_BAD_LENGTH, retry the function until it succeeds."
        # (We'll only retry 10 times as we do not want to end in an infinite loop because this API
        # is broken).
        continue;
      if fbLastErrorIs(ERROR_PARTIAL_COPY):
        assert fsGetISAForProcessId(uProcessId) == "x64", \
            "ERROR_PARTIAL_COPY should only happend if the target process is 64-bit!?";
        assert fsGetPythonISA() == "x86", \
            "ERROR_PARTIAL_COPY should only happend if the Python process is 32-bit!\n" \
            "You may be attempting to get information from a process that is not fully initialized.";
        raise AssertionError("You cannot use this function from a 32-bit process to query a 64-bit process.");
      fThrowLastError("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0x%X)" % (
        uProcessId,
      ));
    else:
      fThrowLastError("%d x CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0x%X)" % (
        uRetryCount, 
        uProcessId,
      ));
    oModuleEntry32 = MODULEENTRY32W();
    oModuleEntry32.dwSize = oModuleEntry32.fuGetSize();
    opoModuleEntry32 = oModuleEntry32.foCreatePointer();
    obGotModule = oKernel32DLL.Module32FirstW(ohProcessSnapshot, opoModuleEntry32)
    bFirstModule = True;
    while obGotModule.fbGetValue():
      bFirstModule = False;
      aoModuleInformation.append(cClass(
        uStartAddress = oModuleEntry32.modBaseAddr.fuGetValue(),
        s0Name = oModuleEntry32.szModule.fs0GetNullTerminatedString(),
        s0BinaryPath = oModuleEntry32.szExePath.fs0GetNullTerminatedString(),
      ));
      obGotModule = oKernel32DLL.Module32NextW(ohProcessSnapshot, opoModuleEntry32);
    if not fbLastErrorIs(ERROR_NO_MORE_FILES):
      sFunction = "Module32%sW" % ("First" if bFirstModule else "Next");
      fThrowLastError("%s(%s, %s)" % (sFunction, repr(ohProcessSnapshot), repr(opoModuleEntry32)));
    if not oKernel32DLL.CloseHandle(ohProcessSnapshot):
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcessSnapshot),));
    return aoModuleInformation;

  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    return [s for s in [
      "uStartAddress = 0x%X" % (oSelf.uStartAddress,),
      "s0Name = %s" % (oSelf.s0Name,) if oSelf.s0Name else "no name",
      "s0BinaryPath = %s" % (oSelf.s0BinaryPath,) if oSelf.s0BinaryPath else "no binary path",
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));

