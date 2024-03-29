from mWindowsSDK import \
  ERROR_COMMITMENT_LIMIT, ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY, \
  fsGetWin32ErrorCodeDescription;

def fThrowWin32Error(sFailedOperation, uWin32ErrorCode):
  mDebugOutput_HideInCallStack = True; # Hide this helper function in the call stack.
  sErrorMessage = "%s => %s." % (sFailedOperation, fsGetWin32ErrorCodeDescription(uWin32ErrorCode));
  if uWin32ErrorCode in [ERROR_COMMITMENT_LIMIT, ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY]:
    raise MemoryError(sErrorMessage);
  raise WindowsError(uWin32ErrorCode, sErrorMessage);

