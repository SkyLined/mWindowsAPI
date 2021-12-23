from mWindowsSDK import *;
from mWindowsSDK.mPsapi import oPsapiDLL;

from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

uMaxBufferSize = 0x10000; # Randomly chosen to be sane-ish.

def fs0GetBinaryPathForProcessAndModuleHandle(ohProcess, ohModule):
  assert isinstance(ohProcess, HANDLE), \
      "ohProcess (%s) is not a HANDLE" % repr(ohProcess);
  assert fbIsValidHandle(ohProcess), \
      "ohProcess (%s) is not a valid handle" % repr(ohProcess);
  assert isinstance(ohModule, HMODULE), \
      "ohProcess (%s) | ohModule (%s) is not an HMODULE" % (repr(ohProcess), repr(ohModule));
  assert fbIsValidHandle(ohModule), \
      "ohModule (%s) is not a valid handle" % repr(ohModule);
  uBufferSize = 256;
  while uBufferSize <= uMaxBufferSize:
    oBuffer = WCHAR[uBufferSize]();
    odwResult = oPsapiDLL.GetModuleFileNameExW(
      ohProcess,        # hProcess
      ohModule,         # hModule
      LPWSTR(oBuffer),  # lpFileName
      uBufferSize,      # nSize
    );
    uBinaryPathLength = odwResult.fuGetValue();
    if uBinaryPathLength != uBufferSize:
      sBinaryPath = oBuffer.fsGetValue(u0Length = uBinaryPathLength);
      return sBinaryPath;
    uBufferSize *= 2;
  return None;
