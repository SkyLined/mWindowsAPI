from .fbLastErrorFailed import fbLastErrorFailed;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import ADVAPI32, KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fuGetIntegrityLevelForProcessHandle(hProcess):
  assert isinstance(hProcess, HANDLE), \
      "%s is not a HANDLE" % repr(hProcess);
  dwDesiredAccess = DWORD(TOKEN_QUERY);
  hToken = HANDLE();
  if not KERNEL32.OpenProcessToken(hProcess, dwDesiredAccess, POINTER(hToken)):
    fThrowLastError("OpenProcessToken(0x%08X, 0x%08X, 0x%X)" % \
        (hProcess.value, dwDesiredAccess.value, fuAddressOf(hToken)));
  bSuccess = False;
  try:
    dwTokenMandatoryLabelSize = DWORD();
    uFlags = TokenIntegrityLevel;
    # Find out how large a TOKEN_MANDATORY_LABEL struct is:
    if (
      ADVAPI32.GetTokenInformation(hToken, uFlags, NULL, 0, PDWORD(dwTokenMandatoryLabelSize))
      or not fbLastErrorIs(ERROR_INSUFFICIENT_BUFFER)
    ):
      # The call should fail because the buffer is too small, if it does not that is an error:
      fThrowLastError("GetTokenInformation(0x%08X, 0x%08X, NULL, 0, 0x%X)" % \
          (hToken.value, uFlags, fuAddresOf(dwTokenMandatoryLabelSize)));
    # Allocate memory to store a TOKEN_MANDATORY_LABEL struct:
    poTokenMandatoryLabel = fxCast(POINTER(TOKEN_MANDATORY_LABEL), BUFFER(dwTokenMandatoryLabelSize.value));
    # Get the TOKEN_MANDATORY_LABEL struct:
    xTokenInformationClass = TokenIntegrityLevel
    if not ADVAPI32.GetTokenInformation(
      hToken,
      xTokenInformationClass,
      poTokenMandatoryLabel,
      dwTokenMandatoryLabelSize,
      POINTER(dwTokenMandatoryLabelSize)
    ):
      fThrowLastError("GetTokenInformation(0x%08X, 0x%08X, 0x%X, 0x%X, 0x%X)" % \
          hToken.value, xTokenInformationClass, fuPointerValue(poTokenMandatoryLabel), \
          dwTokenMandatoryLabelSize.value, fuAddressOf(dwTokenMandatoryLabelSize));
    oTokenMandatoryLabel = fxPointerTarget(poTokenMandatoryLabel);
    # Find out the index of the last Sid Sub Authority
    puSidSubAuthorityCount = ADVAPI32.GetSidSubAuthorityCount(oTokenMandatoryLabel.Label.Sid);
    # Annoyingly the return value of GetSidSubAuthorityCount is "undefined" in case of an error. So we will need to
    # check the return value of GetlastError to make sure it succeeded.
    if fbLastErrorFailed():
      fThrowLastError("GetSidSubAuthorityCount(0x%X)" % fuPointerValue(oTokenMandatoryLabel.Label.Sid));
    
    # Get the last Sid Sub Authority
    uLastSidSubAuthorityIndex = fxPointerTarget(puSidSubAuthorityCount).value - 1;
    pdwLastSidSubAuthority= ADVAPI32.GetSidSubAuthority(oTokenMandatoryLabel.Label.Sid, uLastSidSubAuthorityIndex);
    # Again, the return value of GetSidSubAuthority is "undefined" in case of an error. So we will check the return
    # value of GetlastError to make sure it succeeded.
    if fbLastErrorFailed():
      fThrowLastError("GetSidSubAuthority(0x%X, %d)" % \
          (fuPointerValue(oTokenMandatoryLabel.Label.Sid), uLastSidSubAuthorityIndex));
    dwIntegrityLevel = fxPointerTarget(pdwLastSidSubAuthority);
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hToken) and bSuccess:
      fThrowError("CloseHandle(0x%X,)" % (hToken.value,));
  return dwIntegrityLevel.value;
