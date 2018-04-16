from .mDefines import CREATE_SUSPENDED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME, FALSE, NULL;
from .mFunctions import HRESULT_FROM_WIN32, POINTER, SIZEOF;
from .mTypes import PROCESS_INFORMATION, STARTUPINFOW;
from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fuCreateProcessForBinaryPathAndArguments(sBinaryPath, asArguments, sWorkingDirectory = None, bSuspended = False):
  sCommandLine = " ".join([
    (s and (s[0] == '"' or s.find(" ") == -1)) and s or '"%s"' % s.replace('"', '\\"')
    for s in [sBinaryPath] + asArguments
  ]);
  uFlags = (bSuspended and CREATE_SUSPENDED or 0);
  oStartupInfo = STARTUPINFOW();
  oStartupInfo.cb = SIZEOF(oStartupInfo);
  oStartupInfo.lpDesktop = NULL;
  oStartupInfo.lpDesktop = NULL;
  oStartupInfo.dwFlags = 0;
  oProcessInformation = PROCESS_INFORMATION();
  if not KERNEL32.CreateProcessW(
    sBinaryPath, # lpApplicationName
    sCommandLine, # lpCommandLine
    NULL, # lpProcessAttributes
    NULL, # lpThreadAttributes
    FALSE, # bInheritHandles
    uFlags, # dwCreationFlags
    NULL, # lpEnvironment
    sWorkingDirectory, # lpCurrentDirectory
    POINTER(oStartupInfo), # lpStartupInfo
    POINTER(oProcessInformation), # lpProcessInformation
  ):
    uCreateProcessError = KERNEL32.GetLastError();
    (HRESULT_FROM_WIN32(uCreateProcessError) in [ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME]) \
        or fThrowError("CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...)" % \
        (repr(sBinaryPath), repr(sCommandLine), uFlags, repr(sWorkingDirectory)), uCreateProcessError);
    return None;
  try:
    return oProcessInformation.dwProcessId;
  finally:
    KERNEL32.CloseHandle(oProcessInformation.hProcess) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess,));
    KERNEL32.CloseHandle(oProcessInformation.hThread) \
        or fThrowError("CloseHandle(0x%X)" % (hProcess,));
