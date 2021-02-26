from mWindowsSDK import *;
from .fbLastErrorFailed import fbLastErrorFailed;
from .fbLastErrorIs import fbLastErrorIs;
from .fThrowLastError import fThrowLastError;

def fuGetIntegrityLevelForProcessHandle(ohProcess):
  oKernel32 = foLoadKernel32DLL();
  oAdvAPI32 = foLoadAdvAPI32DLL();
  assert isinstance(ohProcess, HANDLE), \
      "%s is not a HANDLE" % repr(ohProcess);
  odwDesiredAccess = DWORD(TOKEN_QUERY);
  ohToken = HANDLE();
  if not oKernel32.OpenProcessToken(ohProcess, odwDesiredAccess, ohToken.foCreatePointer()):
    fThrowLastError("OpenProcessToken(%s, %s, 0x%X)" % \
        (repr(ohProcess), repr(odwDesiredAccess), ohToken.fuGetAddress()));
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
      fThrowLastError("GetTokenInformation(%s, 0x%08X, NULL, 0, 0x%X)" % \
          (repr(ohToken), uFlags, odwTokenMandatoryLabelSize.fiGetAddress()));
    # Allocate memory to store a TOKEN_MANDATORY_LABEL struct. This may be more than what we know, but not less.
    assert TOKEN_MANDATORY_LABEL.fuGetSize() <= odwTokenMandatoryLabelSize.fuGetValue(), \
        "The OS is reporting that a TOKEN_MANDATORY_LABEL requires %d bytes, but at least %d bytes are expected!" %\
        (odwTokenMandatoryLabelSize.fuGetValue(), TOKEN_MANDATORY_LABEL.fuGetSize());
    oTokenMandatoryLabelBuffer = BYTE[odwTokenMandatoryLabelSize.fuGetValue()]();
    poTokenMandatoryLabel = oTokenMandatoryLabelBuffer.foCreatePointer(PTOKEN_MANDATORY_LABEL);
    # Get the TOKEN_MANDATORY_LABEL struct:
    xTokenInformationClass = TokenIntegrityLevel
    if not oAdvAPI32.GetTokenInformation(
      ohToken,
      xTokenInformationClass,
      poTokenMandatoryLabel,
      odwTokenMandatoryLabelSize,
      odwTokenMandatoryLabelSize.foCreatePointer()
    ):
      fThrowLastError("GetTokenInformation(%s, 0x%08X, 0x%X, 0x%X, 0x%X)" % (
        repr(ohToken), xTokenInformationClass, oTokenMandatoryLabel.fuGetAddress(), \
        repr(odwTokenMandatoryLabelSize), odwTokenMandatoryLabelSize.fuGetAddress()
      ));
    # Now extract the struct we know from the buffer.
    oTokenMandatoryLabel = poTokenMandatoryLabel.fo0GetTarget();
    # Find out the index of the last Sid Sub Authority
    opuSidSubAuthorityCount = oAdvAPI32.GetSidSubAuthorityCount(oTokenMandatoryLabel.Label.Sid);
    # Annoyingly the return value of GetSidSubAuthorityCount is "undefined" in case of an error. So we will need to
    # check the return value of GetlastError to make sure it succeeded.
    if fbLastErrorFailed():
      fThrowLastError("GetSidSubAuthorityCount(%s)" % (repr(oTokenMandatoryLabel.Label.Sid),));
    
    # Get the last Sid Sub Authority
    uLastSidSubAuthorityIndex = opuSidSubAuthorityCount.fo0GetTarget().fuGetValue() - 1;
    opdwLastSidSubAuthority= oAdvAPI32.GetSidSubAuthority(oTokenMandatoryLabel.Label.Sid, uLastSidSubAuthorityIndex);
    # Again, the return value of GetSidSubAuthority is "undefined" in case of an error. So we will check the return
    # value of GetlastError to make sure it succeeded.
    if fbLastErrorFailed():
      fThrowLastError("GetSidSubAuthority(0x%X, %d)" % \
          (oTokenMandatoryLabel.Label.Sid.fuGetValue(), uLastSidSubAuthorityIndex));
    odwIntegrityLevel = opdwLastSidSubAuthority.fo0GetTarget();
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohToken) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohToken),));
  return odwIntegrityLevel.fuGetValue();
