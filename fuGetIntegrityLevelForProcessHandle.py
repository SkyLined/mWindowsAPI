from mWindowsSDK import *;
from .fbLastErrorFailed import fbLastErrorFailed;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;

def fuGetIntegrityLevelForProcessHandle(ohProcess):
  oKernel32 = foLoadKernel32DLL();
  oAdvAPI32 = foLoadAdvAPI32DLL();
  assert isinstance(ohProcess, HANDLE), \
      "%s is not a HANDLE" % repr(ohProcess);
  odwDesiredAccess = DWORD(TOKEN_QUERY);
  ohToken = HANDLE();
  if not oKernel32.OpenProcessToken(ohProcess, odwDesiredAccess, ohToken.foCreatePointer()):
    fThrowLastError("OpenProcessToken(0x%08X, 0x%08X, 0x%X)" % \
        (ohProcess.value, odwDesiredAccess.value, ohToken.fuGetAddress()));
  bSuccess = False;
  try:
    odwTokenMandatoryLabelSize = DWORD();
    uFlags = TokenIntegrityLevel;
    # Find out how large a TOKEN_MANDATORY_LABEL struct is:
    if (
      oAdvAPI32.GetTokenInformation(ohToken, uFlags, NULL, 0, odwTokenMandatoryLabelSize.foCreatePointer())
      or not fbLastErrorIs(ERROR_INSUFFICIENT_BUFFER)
    ):
      # The call should fail because the buffer is too small, if it does not that is an error:
      fThrowLastError("GetTokenInformation(0x%08X, 0x%08X, NULL, 0, 0x%X)" % \
          (ohToken.value, uFlags, fuAddresOf(odwTokenMandatoryLabelSize)));
    # Allocate memory to store a TOKEN_MANDATORY_LABEL struct:
    opoTokenMandatoryLabel = foCreateBuffer(odwTokenMandatoryLabelSize.value).foCreatePointer(PTOKEN_MANDATORY_LABEL);
    # Get the TOKEN_MANDATORY_LABEL struct:
    xTokenInformationClass = TokenIntegrityLevel
    if not oAdvAPI32.GetTokenInformation(
      ohToken,
      xTokenInformationClass,
      opoTokenMandatoryLabel,
      odwTokenMandatoryLabelSize,
      odwTokenMandatoryLabelSize.foCreatePointer()
    ):
      fThrowLastError("GetTokenInformation(0x%08X, 0x%08X, 0x%X, 0x%X, 0x%X)" % (
        ohToken.value, xTokenInformationClass, opoTokenMandatoryLabel.value, \
        odwTokenMandatoryLabelSize.value, odwTokenMandatoryLabelSize.fuGetAddress()
      ));
    oTokenMandatoryLabel = opoTokenMandatoryLabel.foGetTarget();
    # Find out the index of the last Sid Sub Authority
    opuSidSubAuthorityCount = oAdvAPI32.GetSidSubAuthorityCount(oTokenMandatoryLabel.Label.Sid);
    # Annoyingly the return value of GetSidSubAuthorityCount is "undefined" in case of an error. So we will need to
    # check the return value of GetlastError to make sure it succeeded.
    if fbLastErrorFailed():
      fThrowLastError("GetSidSubAuthorityCount(0x%X)" % oTokenMandatoryLabel.Label.Sid.value);
    
    # Get the last Sid Sub Authority
    uLastSidSubAuthorityIndex = opuSidSubAuthorityCount.foGetTarget().value - 1;
    opdwLastSidSubAuthority= oAdvAPI32.GetSidSubAuthority(oTokenMandatoryLabel.Label.Sid, uLastSidSubAuthorityIndex);
    # Again, the return value of GetSidSubAuthority is "undefined" in case of an error. So we will check the return
    # value of GetlastError to make sure it succeeded.
    if fbLastErrorFailed():
      fThrowLastError("GetSidSubAuthority(0x%X, %d)" % \
          (oTokenMandatoryLabel.Label.Sid.value, uLastSidSubAuthorityIndex));
    odwIntegrityLevel = opdwLastSidSubAuthority.foGetTarget();
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohToken) and bSuccess:
      fThrowError("CloseHandle(0x%X,)" % (ohToken.value,));
  return odwIntegrityLevel.value;
