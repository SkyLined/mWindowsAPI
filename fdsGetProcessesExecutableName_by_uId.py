from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

def fdsGetProcessesExecutableName_by_uId():
  dsProcessExecutableName_by_uIds = {};
  oKernel32 = foLoadKernel32DLL();
  ohProcessesSnapshot = oKernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if not fbIsValidHandle(ohProcessesSnapshot):
    fThrowLastError("CreateToolhelp32Snapshot(0x%08X, 0)", TH32CS_SNAPPROCESS);
  oProcessEntry32 = PROCESSENTRY32W();
  oProcessEntry32.dwSize = oProcessEntry32.fuGetSize();
  opoProcessEntry32 = oProcessEntry32.foCreatePointer();
  obGotProcess = oKernel32.Process32FirstW(ohProcessesSnapshot, opoProcessEntry32)
  bFirstProcess = True;
  while obGotProcess.fbGetValue():
    bFirstProcess = False;
    dsProcessExecutableName_by_uIds[oProcessEntry32.th32ProcessID.fuGetValue()] = oProcessEntry32.szExeFile.fsGetNullTerminatedString();
    obGotProcess = oKernel32.Process32NextW(ohProcessesSnapshot, opoProcessEntry32);
  if not fbLastErrorIs(ERROR_NO_MORE_FILES):
    sFunction = "Process32%sW" % ("First" if bFirstProcess else "Next");
    fThrowLastError("%s(%s, %s)" % (sFunction, repr(ohProcessesSnapshot), repr(opoProcessEntry32)));
  if not oKernel32.CloseHandle(ohProcessesSnapshot):
    fThrowLastError("CloseHandle(%s)" % (repr(ohProcessesSnapshot),));
  return dsProcessExecutableName_by_uIds;

