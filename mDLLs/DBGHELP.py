from cDLL import cDLL;
from ..mTypes import *;

DBGHELP = cDLL("DbgHelp.dll");
# All functions in DbgHelp are single threaded!

DBGHELP.fDefineFunction(DWORD,   "UnDecorateSymbolName", PCSTR, PSTR, DWORD, DWORD, bSingleThreaded = True);
DBGHELP.fDefineFunction(DWORD,   "UnDecorateSymbolNameW", PCWSTR, PWSTR, DWORD, DWORD, bSingleThreaded = True);
