from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

def ftohuohuCreateProcessAndThreadForBinaryPathAndArguments(sBinaryPath, asArguments, sWorkingDirectory = None, bSuspended = False):
  sCommandLine = " ".join([
    (s and (s[0] == '"' or s.find(" ") == -1)) and s or '"%s"' % s.replace('"', '\\"')
    for s in [sBinaryPath] + asArguments
  ]);
  oStartupInfo = STARTUPINFOW();
  oStartupInfo.cb = oStartupInfo.fuGetSize();
  oStartupInfo.lpDesktop = NULL;
  oStartupInfo.lpDesktop = NULL;
  oStartupInfo.dwFlags = 0;
  oProcessInformation = PROCESS_INFORMATION();
  if not oKernel32DLL.CreateProcessW(
    PCWSTR(sBinaryPath), # lpApplicationName
    PWSTR(sCommandLine), # lpCommandLine
    NULL, # lpProcessAttributes
    NULL, # lpThreadAttributes
    FALSE, # bInheritHandles
    bSuspended and CREATE_SUSPENDED or 0, # dwCreationFlags
    NULL, # lpEnvironment
    PCWSTR(sWorkingDirectory) if sWorkingDirectory else NULL, # lpCurrentDirectory
    oStartupInfo.foCreatePointer(), # lpStartupInfo
    oProcessInformation.foCreatePointer(), # lpProcessInformation
  ):
    if not fbLastErrorIs(ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME):
      fThrowLastError("CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...)" % \
          (repr(sBinaryPath), repr(sCommandLine), uFlags, repr(sWorkingDirectory)));
    return (None, None, None, None);
  return (
    oProcessInformation.hProcess,
    oProcessInformation.dwProcessId.fuGetValue(),
    oProcessInformation.hThread,
    oProcessInformation.dwThreadId.fuGetValue()
  );
