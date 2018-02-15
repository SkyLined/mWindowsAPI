from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fbTerminateProcessForHandle(hProcess, nTimeout = None):
  # We can open the process: try to terminate it.
  bTerminated = KERNEL32.TerminateProcess(hProcess, 0);
  uTerminateProcessError = KERNEL32.GetLastError();
  (bTerminated or HRESULT_FROM_WIN32(uTerminateProcessError) == ERROR_ACCESS_DENIED) \
      or fThrowError("TerminateProcess(0x%08X, 0)" % (hProcess,), uError = uTerminateProcessError);
  sTerminateProcessResult = "TerminateProcess(0x%08X, 0) %s" % \
      (hProcess, bTerminated and " = TRUE" or " => ERROR_ACCESS_DENIED");
  # Wait for the process to die.
  if nTimeout is None:
    uTimeout = INFINITE;
  else:
    uTimeout = long(nTimeout * 1000);
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
