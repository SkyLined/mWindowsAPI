from mWindowsAPI import *;
from oConsole import oConsole;

def fTestDbgHelp():
  # mDbgHelp.fsUndecorateSymbolName
  oConsole.fOutput("* Testing mDbgHelp...");
  oConsole.fOutput("  * fsUndecorateSymbolName...");
  for (sDecoratedSymbolName, tsExpectedResults) in {
    "?function@@YAHD@Z":                    ["int __cdecl function(char)", "function"],
    "?function@namespace@@AAGXM@Z":         ["private: void __stdcall namespace::function(float)", "namespace::function"],
    "?method@class@namespace@@AAEXH@Z":     ["private: void __thiscall namespace::class::method(int)", "namespace::class::method"],
    ".?AVSafeIntException@utilities@msl@@": [" ?? msl::utilities::SafeIntException", "msl::utilities::SafeIntException"],
    "Not a decorated name":                 [None, None],
  }.items():
    sExpectedFullSymbolName, sExpectedSymbolName = tsExpectedResults;
    sUndecoratedFullSymbolName = mDbgHelp.fsUndecorateSymbolName(sDecoratedSymbolName);
    assert sUndecoratedFullSymbolName == sExpectedFullSymbolName, \
        "mDbgHelp.fsUndecorateSymbolName(%s) => %s instead of %s" % \
        (repr(sDecoratedSymbolName), repr(sUndecoratedFullSymbolName), repr(sExpectedFullSymbolName));
    sUndecoratedSymbolName = mDbgHelp.fsUndecorateSymbolName(sDecoratedSymbolName, bNameOnly = True);
    assert sUndecoratedSymbolName == sExpectedSymbolName, \
        "mDbgHelp.fsUndecorateSymbolName(%s) => %s instead of %s" % \
        (repr(sDecoratedSymbolName), repr(sUndecoratedSymbolName), repr(sExpectedSymbolName));
    oConsole.fOutput("    + %s => %s / %s" % (sDecoratedSymbolName, sUndecoratedSymbolName, sUndecoratedFullSymbolName));
  oConsole.fOutput("* Texting cUWPApplication...");
  oCalc = cUWPApplication("Microsoft.WindowsCalculator");
  assert oCalc.bPackageExists, \
      "UWP application package %s does not exist!?" % oCalc.sPackageName;
  assert oCalc.sApplicationId is not None, \
      "UWP application package %s does not have a single application id!?" % oCalc.sPackageName;
  oInvalid = cUWPApplication("XXXXXXXXXXXXX");
  assert not oInvalid.bPackageExists, \
      "UWP application package %s exist!?" % oInvalid.sPackageName;
  oInvalid = cUWPApplication("Microsoft.WindowsCalculator!XXXXXXXXXXXXX");
  assert not oInvalid.bIdExists, \
      "UWP application package %s has an application with id %s!?" % (oInvalid.sPackageName, oInvalid.sApplicationId);
