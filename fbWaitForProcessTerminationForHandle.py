from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

def fbWaitForProcessTerminationForHandle(hProcess, nTimeout = None):
  if nTimeout is None:
    uTimeout = INFINITE;
  else:
    uTimeout = long(nTimeout * 1000);
  uWaitForSingleObjectResult = KERNEL32.WaitForSingleObject(hProcess, uTimeout);
  if uWaitForSingleObjectResult == WAIT_TIMEOUT:
    return False; # Could not wait for it to die.
  if uWaitForSingleObjectResult == WAIT_OBJECT_0:
    return True; # Proces was terminated.
  fThrowError(
    "WaitForSingleObject(0x%08X, %d) = 0x%08X" % (hProcess, guTimeout, uWaitForSingleObjectResult)
  );
