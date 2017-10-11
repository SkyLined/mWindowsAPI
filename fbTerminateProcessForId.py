from mWindowsAPI import *;
from fdsProcessesExecutableName_by_uId import fdsProcessesExecutableName_by_uId;

def fbTerminateProcessForId(uProcessId):
  # Try to open the process so we can terminate it...
  hProcess = KERNEL32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, uProcessId);
  if hProcess:
    # We can open it, try to terminate it.
    bTerminated = KERNEL32.TerminateProcess(hProcess, 0);
    uTerminateProcessError = KERNEL32.GetLastError();
    assert bTerminated or uTerminateProcessError == WIN32_FROM_HRESULT(ERROR_ACCESS_DENIED), \
        "TerminateProcess(0x%08X, 0) => Error 0x%08X" % (hProcess, uTerminateProcessError)
  else:
    bTerminated = False;
    uTerminateProcessError = None;
    # Failed to open the process for termination. Try to open the process with
    # less privileges; just enough see if it's still running...
    hProcess = KERNEL32.OpenProcess(SYNCHRONIZE, FALSE, uProcessId);
    if not hProcess:
      # We cannot open the process. This means it must not exist, or something
      # is wrong:
      assert uProcessId not in fdsProcessesExecutableName_by_uId(), \
          "OpenProcess(0x%08X, FALSE, %d/0x%X) => Error 0x%08X (after %d tries)" % \
          (PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, \
          uProcessId, uProcessId, KERNEL32.GetLastError(), uTryIndex + 1);
      # The process does not exist, assume it was terminated long ago, but not
      # by this function.
      return False;
  # The process exists: give it up to five seconds to die:
  uWaitForSingleObjectResult = KERNEL32.WaitForSingleObject(hProcess, 5000);
  uWaitForSingleObjectError = KERNEL32.GetLastError();
  if uWaitForSingleObjectResult == WIN32_FROM_HRESULT(ERROR_ACCESS_DENIED):
    # We do not have access to the process to terminate it.
    assert not bTerminated, \
        "WaitForSingleObject(0x%08X, 1000) = 0x%08X => Error 0x%08X" % \
        (hProcess, uWaitForSingleObjectResult, uWaitForSingleObjectError);
  else:
    # It should be terminated now, either by us, or it already was.
    assert uWaitForSingleObjectResult == WAIT_OBJECT_0, \
        ", ".join([
          "TerminateProcess(0x%08X, 0) => %s" % \
              (hProcess, uTerminateProcessError is not None and "Error 0x%08X" % uTerminateProcessError or "OK"),
          "WaitForSingleObject(0x%08X, 1000) = 0x%08X => Error 0x%08X" % \
              (hProcess, uWaitForSingleObjectResult, uWaitForSingleObjectError),
        ]);
  KERNEL32.CloseHandle(hProcess);
  return bTerminated;