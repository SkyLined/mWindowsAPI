from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fdsProcessesExecutableName_by_uId():
  dsProcessExecutableName_by_uIds = {};
  hProcessesSnapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  (hProcessesSnapshot != INVALID_HANDLE_VALUE) \
      or fThrowError("CreateToolhelp32Snapshot(0x%08X, 0)", TH32CS_SNAPPROCESS);
  oProcessEntry32 = PROCESSENTRY32W();
  oProcessEntry32.dwSize = SIZEOF(oProcessEntry32);
  bGotProcess = KERNEL32.Process32FirstW(hProcessesSnapshot, POINTER(oProcessEntry32))
  bFirstProcess = True;
  while bGotProcess:
    bFirstProcess = False;
    dsProcessExecutableName_by_uIds[oProcessEntry32.th32ProcessID] = oProcessEntry32.szExeFile;
    bGotProcess = KERNEL32.Process32NextW(hProcessesSnapshot, POINTER(oProcessEntry32));
  uLastError = KERNEL32.GetLastError();
  (HRESULT_FROM_WIN32(uLastError) == ERROR_NO_MORE_FILES) \
      or fThrowError("Process32%sW(0x%08X, ...)" % \
          (bFirstProcess and "First" or "Next", hProcessesSnapshot.value,), uLastError);
  KERNEL32.CloseHandle(hProcessesSnapshot) \
      or fThrowError("CloseHandle(0x%08X)" % (hProcessesSnapshot.value,));
  return dsProcessExecutableName_by_uIds;

