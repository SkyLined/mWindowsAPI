from mWindowsSDK import *;
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
  oKernel32 = foLoadKernel32DLL();
  if not oKernel32.CreateProcessW(
    foCreateBuffer(sBinaryPath, bUnicode = True).foCreatePointer(PCWSTR), # lpApplicationName
    foCreateBuffer(sCommandLine, bUnicode = True).foCreatePointer(PWSTR), # lpCommandLine
    NULL, # lpProcessAttributes
    NULL, # lpThreadAttributes
    FALSE, # bInheritHandles
    bSuspended and CREATE_SUSPENDED or 0, # dwCreationFlags
    NULL, # lpEnvironment
    foCreateBuffer(sWorkingDirectory, bUnicode = True).foCreatePointer(PCWSTR) if sWorkingDirectory else NULL, # lpCurrentDirectory
    oStartupInfo.foCreatePointer(), # lpStartupInfo
    oProcessInformation.foCreatePointer(), # lpProcessInformation
  ):
    if not fbLastErrorIs(ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME):
      fThrowLastError("CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...)" % \
          (repr(sBinaryPath), repr(sCommandLine), uFlags, repr(sWorkingDirectory)));
    return (None, None, None, None);
  return (
    oProcessInformation.hProcess,
    oProcessInformation.dwProcessId.value,
    oProcessInformation.hThread,
    oProcessInformation.dwThreadId.value
  );
