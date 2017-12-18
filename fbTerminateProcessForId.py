from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;
from fThrowError import fThrowError;

def fbTerminateProcessForId(uProcessId, nTimeout = None):
  if nTimeout is None:
    uTimeout = INFINITE;
  else:
    uTimeout = long(nTimeout * 1000);
  # Try to open the process so we can terminate it...
  uFlags = PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
  hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
  try:
    if hProcess:
      # We can open the process: try to terminate it.
      bTerminated = KERNEL32.TerminateProcess(hProcess, 0);
      uTerminateProcessError = KERNEL32.GetLastError();
      (bTerminated or HRESULT_FROM_WIN32(uTerminateProcessError) == ERROR_ACCESS_DENIED) \
          or fThrowError("TerminateProcess(0x%08X, 0)" % (hProcess,), uError = uTerminateProcessError);
      sTerminateProcessResult = "TerminateProcess(0x%08X, 0) %s" % \
          (hProcess, bTerminated and " = TRUE" or " => ERROR_ACCESS_DENIED");
    else:
      # We cannot open the process for termination, it may have been terminated already: try to open the process
      # again with just enough privileges to see if it's still running.
      sTerminateProcessResult = None;
      uFlags = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
      hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
      if not hProcess:
        # The process may have terminated so long ago that it's process id is no longer valid:
        uOpenProcessError = KERNEL32.GetLastError();
        (HRESULT_FROM_WIN32(uOpenProcessError) == ERROR_INVALID_PARAMETER) \
            or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId), uOpenProcessError);
        (uProcessId not in fdsProcessesExecutableName_by_uId()) \
            or fThrowError("OpenProcess(0x%08X, FALSE, %d/0x%X)" % (uFlags, uProcessId, uProcessId), uOpenProcessError);
        # The process does not exist anymore.
        return True;
    # The process exists: wait for it to die.
    uWaitForSingleObjectResult = KERNEL32.WaitForSingleObject(hProcess, uTimeout);
    if uWaitForSingleObjectResult == WAIT_TIMEOUT:
      return False; # Could not wait for it to die.
    if uWaitForSingleObjectResult == WAIT_OBJECT_0:
      return True; # Proces was terminated.
    uWaitForSingleObjectError = KERNEL32.GetLastError();
    fThrowError(
      (sTerminateProcessResult and sTerminateProcessResult + ", " or "") +
      "WaitForSingleObject(0x%08X, %d) = 0x%08X" % (hProcess, guTimeout, uWaitForSingleObjectResult)
    );
  finally:
    if hProcess:
      KERNEL32.CloseHandle(hProcess) \
          or fThrowError("CloseHandle(0x%X)" % (hProcess,));
