from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import ADVAPI32, KERNEL32;

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
      assert not ADVAPI32.GetTokenInformation(hToken, TokenIntegrityLevel, None, 0, PDWORD(dwTokenMandatoryLabelSize)), \
          "GetTokenInformation(...) succeeded unexpectedly";
      assert KERNEL32.GetLastError() == WIN32_FROM_HRESULT(ERROR_INSUFFICIENT_BUFFER), \
          "GetTokenInformation(...) => Error 0x%08X" % KERNEL32.GetLastError();
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
      # Found out the index of the last Sid Sub Authority
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
