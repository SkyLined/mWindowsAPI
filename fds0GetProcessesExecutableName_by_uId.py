from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

def fds0GetProcessesExecutableName_by_uId():
  ds0ProcessExecutableName_by_uIds = {};
  ohProcessesSnapshot = oKernel32DLL.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if not fbIsValidHandle(ohProcessesSnapshot):
    fThrowLastError("CreateToolhelp32Snapshot(0x%08X, 0)", TH32CS_SNAPPROCESS);
  oProcessEntry32 = PROCESSENTRY32W();
  oProcessEntry32.dwSize = oProcessEntry32.fuGetSize();
  opoProcessEntry32 = oProcessEntry32.foCreatePointer();
  obGotProcess = oKernel32DLL.Process32FirstW(ohProcessesSnapshot, opoProcessEntry32)
  bFirstProcess = True;
  while obGotProcess.fbGetValue():
    bFirstProcess = False;
    s0ProcessExecutableName = oProcessEntry32.szExeFile.fs0GetNullTerminatedString();
    uProcessId = oProcessEntry32.th32ProcessID.fuGetValue();
    ds0ProcessExecutableName_by_uIds[uProcessId] = s0ProcessExecutableName;
    obGotProcess = oKernel32DLL.Process32NextW(ohProcessesSnapshot, opoProcessEntry32);
  if not fbLastErrorIs(ERROR_NO_MORE_FILES):
    sFunction = "Process32%sW" % ("First" if bFirstProcess else "Next");
    fThrowLastError("%s(%s, %s)" % (sFunction, repr(ohProcessesSnapshot), repr(opoProcessEntry32)));
  if not oKernel32DLL.CloseHandle(ohProcessesSnapshot):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcessesSnapshot),));
  return ds0ProcessExecutableName_by_uIds;

