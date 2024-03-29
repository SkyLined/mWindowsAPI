from mWindowsSDK import *;
from ..fbLastErrorIs import fbLastErrorIs;
from ..fThrowLastError import fThrowLastError;

def fs0UndecorateSymbolName(sDecoratedSymbolName, bNameOnly = False):
  oDbgHelp = foLoadDbgHelpDLL();
  if sDecoratedSymbolName.startswith(".?AV"):
    # This is a prefix for class names that for some reason does not get handled well, so we'll fix that here:
    sDecoratedSymbolName = "?" + sDecoratedSymbolName[4:]; # Replace ".?AV" with "?"
  # Notes on https://msdn.microsoft.com/en-us/library/windows/desktop/ms681400(v=vs.85).aspx:
  # Calls to "UnDecorateSymbolName" will officially succeed if the return value > 0. However, it turns out that if the
  # buffer is too small to contain the entire undecorated symbol, UnDecorateSymbolName will write as many chars as
  # possible to the buffer and return the number of chars it was able to write. This would leave us with a truncated
  # symbol, so we work around this by repeatedly increasing the size of the buffer until we get a string that is
  # smaller than the buffer, because that means it is not truncated.
  uSymbolNameBufferLengthInChars = len(sDecoratedSymbolName) * 2; # Let's start with twice the length of the input.
  uLastReturnValue = 0;
  uFlags = UNDNAME_NAME_ONLY if bNameOnly else UNDNAME_COMPLETE;
  osbDecoratedSymbolName = CHAR.foCreateString(sDecoratedSymbolName);
  while uSymbolNameBufferLengthInChars < 0x10000: # Just a random sane upper limit.
    osbUndecoratedSymbolName = CHAR[uSymbolNameBufferLengthInChars]();
    odwSymbolNameLengthInCharsExcludingNullTerminator = oDbgHelp.UnDecorateSymbolName(
      PCSTR(osbDecoratedSymbolName),
      PSTR(osbUndecoratedSymbolName),
      uSymbolNameBufferLengthInChars,
      uFlags,
    );
    uSymbolNameLength = odwSymbolNameLengthInCharsExcludingNullTerminator.fuGetValue();
    if 0 < uSymbolNameLength < uSymbolNameBufferLengthInChars - 1:
      sSymbolName = osbUndecoratedSymbolName.fsGetValue(u0Length = uSymbolNameLength);
      assert len(sSymbolName) == uSymbolNameLength, \
          "There are %d bytes in the symbol name (%s), but there should be %d" % \
          (len(sSymbolName), repr(sSymbolName), uSymbolNameLength);
      # Only return a value if the function returned something different; it can return its input unaltered if it does
      # not know how to demangle it.
      return sSymbolName if sSymbolName != sDecoratedSymbolName else None;
    elif not fbLastErrorIs(ERROR_INVALID_PARAMETER):
      fThrowLastError("UnDecorateSymbolNameW(\"%s\", ..., 0x%X, 0x%X)" % \
          (sDecoratedSymbolName, uSymbolNameBufferLengthInChars, uFlags,));
      # This error is returned if the buffer is too small; try again with a buffer twice the size:
    uSymbolNameBufferLengthInChars *= 2;
    uLastReturnValue = odwSymbolNameLengthInCharsExcludingNullTerminator.value;
  return None; # The symbol name was too large to start with, or the undecorated symbol name would be too large.


