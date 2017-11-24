from cDLL import cDLL;
from ..mTypes import *;

ADVAPI32 = cDLL("Advapi32.dll");
ADVAPI32.fDefineFunction(BOOL, "GetTokenInformation", HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
ADVAPI32.fDefineFunction(PUCHAR, "GetSidSubAuthorityCount", PSID);
ADVAPI32.fDefineFunction(PDWORD, "GetSidSubAuthority", PSID, DWORD);
