from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import ADVAPI32, KERNEL32;
from fsGetErrorMessage import fsGetErrorMessage;

def fuGetProcessIntegrityLevelForId(uProcessId):
  hProcess = KERNEL32.OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, uProcessId);
  if hProcess == 0:
    return None;
  try:
    hToken = HANDLE();
    if not KERNEL32.OpenProcessToken(hProcess, DWORD(TOKEN_QUERY), POINTER(hToken)):
      return None;
    try:
      # Find out how large a TOKEN_MANDATORY_LABEL struct is:
      dwTokenMandatoryLabelSize = DWORD();
      uFlags = TokenIntegrityLevel;
      assert not ADVAPI32.GetTokenInformation(hToken, uFlags, NULL, 0, PDWORD(dwTokenMandatoryLabelSize)), \
          "GetTokenInformation(0x%08X, 0x%08X, NULL, 0, ...) => No error" % (hToken.value, uFlags,);
      uGetTokenInformationError = KERNEL32.GetLastError();
      assert HRESULT_FROM_WIN32(uGetTokenInformationError) == ERROR_INSUFFICIENT_BUFFER, \
          fsGetErrorMessage("GetTokenInformation(0x%08X, 0x%08X, NULL, 0, ...)" % (hToken.value, uFlags,), \
          uGetTokenInformationError);
      # Allocate memory to store a TOKEN_MANDATORY_LABEL struct:
      poTokenMandatoryLabel = CAST(POINTER(TOKEN_MANDATORY_LABEL), BUFFER(dwTokenMandatoryLabelSize.value));
      # Get the TOKEN_MANDATORY_LABEL struct:
      if not ADVAPI32.GetTokenInformation(
        hToken,
        TokenIntegrityLevel,
        poTokenMandatoryLabel,
        dwTokenMandatoryLabelSize,
        POINTER(dwTokenMandatoryLabelSize)
      ):
        return None;
      oTokenMandatoryLabel = poTokenMandatoryLabel.contents;
      # Find out the index of the last Sid Sub Authority
      puSidSubAuthorityCount = ADVAPI32.GetSidSubAuthorityCount(oTokenMandatoryLabel.Label.Sid);
      uLastSidSubAuthorityIndex = puSidSubAuthorityCount.contents.value - 1;
      # Get the last Sid Sub Authority
      pdwLastSidSubAuthority= ADVAPI32.GetSidSubAuthority(oTokenMandatoryLabel.Label.Sid, uLastSidSubAuthorityIndex);
      dwIntegrityLevel = pdwLastSidSubAuthority.contents.value;
      return dwIntegrityLevel;
    finally:
      KERNEL32.CloseHandle(hToken);
  finally:
    KERNEL32.CloseHandle(hProcess);
