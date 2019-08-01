from mWindowsSDK import *;

# All functions in DbgHelp are single threaded!
oDbgHelp = cDLL(
  "DbgHelp.dll",
  {
    "UnDecorateSymbolName": {
      "xReturnType": DWORD,
      "txArgumentTypes": (PCSTR, PSTR, DWORD, DWORD),
      "bSingleThreaded": True,
    },
    "UnDecorateSymbolNameW": {
      "xReturnType": DWORD,
      "txArgumentTypes": (PCWSTR, PWSTR, DWORD, DWORD),
      "bSingleThreaded": True,
    },
  },
);
