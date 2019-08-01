from mWindowsSDK import *;
from .mDLLs import oKernel32;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

def fdsProcessesExecutableName_by_uId():
  dsProcessExecutableName_by_uIds = {};
  ohProcessesSnapshot = oKernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if not fbIsValidHandle(ohProcessesSnapshot):
    fThrowLastError("CreateToolhelp32Snapshot(0x%08X, 0)", TH32CS_SNAPPROCESS);
  oProcessEntry32 = PROCESSENTRY32W();
  oProcessEntry32.dwSize = oProcessEntry32.fuGetSize();
  opoProcessEntry32 = oProcessEntry32.foCreatePointer();
  obGotProcess = oKernel32.Process32FirstW(ohProcessesSnapshot, opoProcessEntry32)
  bFirstProcess = True;
  while obGotProcess.value:
    bFirstProcess = False;
    dsProcessExecutableName_by_uIds[oProcessEntry32.th32ProcessID] = oProcessEntry32.szExeFile;
    obGotProcess = oKernel32.Process32NextW(ohProcessesSnapshot, opoProcessEntry32);
  if not fbLastErrorIs(ERROR_NO_MORE_FILES):
    fThrowLastError("Process32%sW(0x%08X, ...)" % (bFirstProcess and "First" or "Next", ohProcessesSnapshot.value,), uLastError);
  if not oKernel32.CloseHandle(ohProcessesSnapshot):
    fThrowLastError("CloseHandle(0x%08X)" % (ohProcessesSnapshot.value,));
  return dsProcessExecutableName_by_uIds;

