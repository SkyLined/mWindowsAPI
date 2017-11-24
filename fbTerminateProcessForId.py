from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;
from fsGetErrorMessage import fsGetErrorMessage;

guTimeout = 5000; # Give an application 5 seconds to terminate.

def fbTerminateProcessForId(uProcessId, uTimeout = None):
  if uTimeout is None:
    uTimeout = guTimeout;
  # Try to open the process so we can terminate it...
  uFlags = PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
  hProcess = HANDLE(KERNEL32.OpenProcess(uFlags, FALSE, uProcessId));
  try:
    if hProcess:
      # We can open it, try to terminate it.
      bTerminated = KERNEL32.TerminateProcess(hProcess, 0);
      uTerminateProcessError = KERNEL32.GetLastError();
      sTerminateProcessCall = "TerminateProcess(0x%08X, 0)" % (hProcess.value,);
      sTerminateProcessResult = bTerminated and (sTerminateProcessCall + " = TRUE") \
          or fsGetErrorMessage(sTerminateProcessCall, uTerminateProcessError);
      assert bTerminated or HRESULT_FROM_WIN32(uTerminateProcessError) == ERROR_ACCESS_DENIED, \
          sTerminateProcessResult;
    else:
      # Failed to open the process for termination.
      bTerminated = False;
      sTerminateProcessResult = None;
      # The process may have been terminated already: try to open the process again with just enough privileges to see
      # if it's still running:
      uFlags = SYNCHRONIZE;
      hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
      if not hProcess:
        uOpenProcessError = KERNEL32.GetLastError();
        # We cannot open the process: see if there even is a process running with the given id:
        auExistingProcessIds = fdsProcessesExecutableName_by_uId();
        assert uProcessId not in auExistingProcessIds, \
            fsGetErrorMessage("OpenProcess(0x%08X, FALSE, %d/0x%X)" % \
            (uFlags, uProcessId, uProcessId, uTryIndex + 1), uOpenProcessError);
        # The process does not exist, assume it was already terminated.
        return False; # Terminated, but not by this function.
    # The process exists: wait for it to die. If we did not terminate it, do not wait forever:
    uWaitForSingleObjectResult = KERNEL32.WaitForSingleObject(hProcess, bTerminated and INFINITE or guTimeout);
    if uWaitForSingleObjectResult != WAIT_OBJECT_0:
      uWaitForSingleObjectError = KERNEL32.GetLastError();
      sWaitForSingleObjectCall = "WaitForSingleObject(0x%08X, %d) = 0x%08X" % \
          (hProcess.value, guTimeout, uWaitForSingleObjectResult);
      sCalls = (sTerminateProcessResult and sTerminateProcessResult + ", " or "") + sWaitForSingleObjectCall;
      assert uWaitForSingleObjectResult != WAIT_TIMEOUT, \
          "Could not wait for process to die: %s" % sCalls;
      assert uWaitForSingleObjectResult != WAIT_FAILED, \
          fsGetErrorMessage(sCalls, uWaitForSingleObjectError);
      raise AssertionError("%s => Unhandled result value" % sCalls)
    return bTerminated;
  finally:
    if hProcess:
      assert KERNEL32.CloseHandle(hProcess), \
          fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess.value,));
