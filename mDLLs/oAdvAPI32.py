from mWindowsSDK import *;

oAdvAPI32 = cDLL(
  "Advapi32.dll", 
  {
    "GetTokenInformation": {
      "xReturnType": BOOL, 
      "txArgumentTypes": (HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD),
    },
    "GetSidSubAuthorityCount": {
      "xReturnType": PUCHAR, 
      "txArgumentTypes": (PSID),
    },
    "GetSidSubAuthority": {
      "xReturnType": PDWORD, 
      "txArgumentTypes": (PSID, DWORD),
    },
  },
);