from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fdsProcessesExecutableName_by_uId():
  dsProcessExecutableName_by_uIds = {};
  hProcessesSnapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if not fbIsValidHandle(hProcessesSnapshot):
    fThrowLastError("CreateToolhelp32Snapshot(0x%08X, 0)", TH32CS_SNAPPROCESS);
  oProcessEntry32 = PROCESSENTRY32W();
  oProcessEntry32.dwSize = fuSizeOf(oProcessEntry32);
  bGotProcess = KERNEL32.Process32FirstW(hProcessesSnapshot, POINTER(oProcessEntry32))
  bFirstProcess = True;
  while bGotProcess:
    bFirstProcess = False;
    dsProcessExecutableName_by_uIds[oProcessEntry32.th32ProcessID] = oProcessEntry32.szExeFile;
    bGotProcess = KERNEL32.Process32NextW(hProcessesSnapshot, POINTER(oProcessEntry32));
  if not fbLastErrorIs(ERROR_NO_MORE_FILES):
    fThrowLastError("Process32%sW(0x%08X, ...)" % (bFirstProcess and "First" or "Next", hProcessesSnapshot.value,), uLastError);
  if not KERNEL32.CloseHandle(hProcessesSnapshot):
    fThrowLastError("CloseHandle(0x%08X)" % (hProcessesSnapshot.value,));
  return dsProcessExecutableName_by_uIds;

