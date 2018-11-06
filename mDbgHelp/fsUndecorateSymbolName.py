from ..fbLastErrorIs import fbLastErrorIs;
from ..fThrowLastError import fThrowLastError;
from ..mDefines import *;
from ..mDLLs import DBGHELP, KERNEL32;
from ..mFunctions import *;
from ..mTypes import *;

def fsUndecorateSymbolName(sDecoratedSymbolName, bNameOnly = False):
  if sDecoratedSymbolName.startswith(".?AV"):
    # This is a prefix for class names that for some reason does not get handled well, so we'll fix that here:
    sDecoratedSymbolName = "?" + sDecoratedSymbolName[4:]; # Replace ".?AV" with "?"
  # Notes on https://msdn.microsoft.com/en-us/library/windows/desktop/ms681400(v=vs.85).aspx:
  # Calls to "UnDecorateSymbolName" will officially succeed if the return value > 0. However, it turns out that if the
  # buffer is too small to contain the entire undecorated symbol, UnDecorateSymbolName will write as many chars as
  # possible to the buffer and return the number of chars it was able to write. This would leave us with a truncated
  # symbol, so we work around this by repeatedly increasing the size of the buffer until we get the same return value
  # twice as this indicates the symbol was not truncated in both calls.
  uSymbolNameBufferLengthInChars = len(sDecoratedSymbolName) * 2; # Let's start with twice the length of the input.
  uLastError = None;
  uLastReturnValue = 0;
  uFlags = bNameOnly and UNDNAME_NAME_ONLY or UNDNAME_COMPLETE;
  while uSymbolNameBufferLengthInChars < 0x10000: # Just a random sane upper limit.
    sBuffer = STR(uSymbolNameBufferLengthInChars);
    dwSymbolNameLengthInCharsExcludingNullTerminator = DBGHELP.UnDecorateSymbolName(
      sDecoratedSymbolName,
      sBuffer,
      uSymbolNameBufferLengthInChars,
      uFlags,
    );
    if dwSymbolNameLengthInCharsExcludingNullTerminator.value > 0:
      if uLastReturnValue == dwSymbolNameLengthInCharsExcludingNullTerminator.value:
        sSymbolName = sBuffer[:dwSymbolNameLengthInCharsExcludingNullTerminator.value];
        # Only return a value if the function returned something different; it can return its input unaltered if it does
        # not know how to demangle it.
        return sSymbolName != sDecoratedSymbolName and sSymbolName or None;
      uLastError = None;
    elif not fbLastErrorIs(ERROR_INVALID_PARAMETER):
      fThrowLastError("UnDecorateSymbolNameW(\"%s\", ..., 0x%X, 0x%X)" % \
          (sDecoratedSymbolName, uSymbolNameBufferLengthInChars, uFlags,));
      # This error is returned if the buffer is too small; try again with a buffer twice the size:
    uSymbolNameBufferLengthInChars *= 2;
    uLastReturnValue = dwSymbolNameLengthInCharsExcludingNullTerminator.value;
  return None; # The symbol name was too large to start with, or the undecorated symbol name would be too large.


