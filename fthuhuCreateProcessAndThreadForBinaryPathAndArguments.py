from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fthuhuCreateProcessAndThreadForBinaryPathAndArguments(sBinaryPath, asArguments, sWorkingDirectory = None, bSuspended = False):
  sCommandLine = " ".join([
    (s and (s[0] == '"' or s.find(" ") == -1)) and s or '"%s"' % s.replace('"', '\\"')
    for s in [sBinaryPath] + asArguments
  ]);
  uFlags = (bSuspended and CREATE_SUSPENDED or 0);
  oStartupInfo = STARTUPINFOW();
  oStartupInfo.cb = fuSizeOf(oStartupInfo);
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
    if not fbLastErrorIs(ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME):
      fThrowLastError("CreateProcessW(%s, %s, NULL, NULL, FALSE, 0x%08X, NULL, %s, ..., ...)" % \
          (repr(sBinaryPath), repr(sCommandLine), uFlags, repr(sWorkingDirectory)));
    return (None, None, None, None);
  return (oProcessInformation.hProcess, oProcessInformation.dwProcessId.value, oProcessInformation.hThread, oProcessInformation.dwThreadId.value);
