import json, os, sys;

# Augment the search path to make the test subject a package and have access to its modules folder.
sTestsFolderPath = os.path.dirname(os.path.abspath(__file__));
sMainFolderPath = os.path.dirname(sTestsFolderPath);
sParentFolderPath = os.path.dirname(sMainFolderPath);
sModulesFolderPath = os.path.join(sMainFolderPath, "modules");
asOriginalSysPath = sys.path[:];
sys.path = [sParentFolderPath, sModulesFolderPath] + asOriginalSysPath;
# Load product details
oProductDetailsFile = open(os.path.join(sMainFolderPath, "dxProductDetails.json"), "rb");
try:
  dxProductDetails = json.load(oProductDetailsFile);
finally:
  oProductDetailsFile.close();
# Save the list of names of loaded modules:
asOriginalModuleNames = sys.modules.keys();

__import__(dxProductDetails["sProductName"], globals(), locals(), [], -1);

# Sub-packages should load all modules relative, or they will end up in the global namespace, which means they may get
# loaded by the script importing it if it tries to load a differnt module with the same name. Obviously, that script
# will probably not function when the wrong module is loaded, so we need to check that we did this correctly.
asUnexpectedModules = list(set([
  sModuleName.lstrip("_").split(".", 1)[0] for sModuleName in sys.modules.keys()
  if not (
    sModuleName in asOriginalModuleNames # This was loaded before
    or sModuleName.lstrip("_").split(".", 1)[0] in (
      [dxProductDetails["sProductName"]] +
      dxProductDetails["asDependentOnProductNames"] +
      [
        # These built-in modules are expected:
        "collections", "ctypes", "gc", "heapq", "itertools", "keyword",
        "msvcrt", "platform", "string", "strop", "subprocess", "thread",
        "threading", "time", "winreg"
      ]
    )
  )
]));
assert len(asUnexpectedModules) == 0, \
      "Module(s) %s was/were unexpectedly loaded!" % ", ".join(sorted(asUnexpectedModules));

#Import the test subject
from mWindowsAPI import *;
from mWindowsSDK import *;
oKernel32 = foLoadKernel32DLL();
from mWindowsAPI import mDbgHelp;
from mWindowsAPI.fThrowLastError import fThrowLastError;

# Restore the search path
sys.path = asOriginalSysPath;

from fTestProcess import fTestProcess;

if __name__ == "__main__":
  # Test system info
  print "* Testing system info...";sys.stdout.flush();
  print "  * fsGetPythonISA() = %s" % fsGetPythonISA();sys.stdout.flush();
  print "  * oSystemInfo...";sys.stdout.flush();
  print "    | OS:                      %s" %  oSystemInfo.sOSFullDetails;sys.stdout.flush();
  print "    | Processors:              %d" % oSystemInfo.uNumberOfProcessors;sys.stdout.flush();
  print "    | Address range:           0x%08X - 0x%08X" % (oSystemInfo.uMinimumApplicationAddress, oSystemInfo.uMaximumApplicationAddress);sys.stdout.flush();
  print "    | Page size:               0x%X" % oSystemInfo.uPageSize;sys.stdout.flush();
  print "    | Allocation granularity:  0x%X" % oSystemInfo.uAllocationAddressGranularity;sys.stdout.flush();
  print "    | System name:             %s" % oSystemInfo.sSystemName;sys.stdout.flush();
  print "    | System id:               %s" % oSystemInfo.sUniqueSystemId;sys.stdout.flush();
  
  # Test console functions
  print "* Testing oKernel32 console functions...";sys.stdout.flush();
  ohStdOut = oKernel32.GetStdHandle(STD_OUTPUT_HANDLE);
  oConsoleScreenBufferInfo = CONSOLE_SCREEN_BUFFER_INFO();
  if not oKernel32.GetConsoleScreenBufferInfo(ohStdOut, oConsoleScreenBufferInfo.foCreatePointer()):
    fThrowLastError("GetConsoleScreenBufferInfo(0x%08X, 0x%X)" % (ohStdOut.value, oConsoleScreenBufferInfo.fuGetAddress()));
  print "  Console buffer size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwSize.X, oConsoleScreenBufferInfo.dwSize.Y);sys.stdout.flush();
  print "  Console window size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwMaximumWindowSize.X, oConsoleScreenBufferInfo.dwMaximumWindowSize.Y);sys.stdout.flush();
  uOriginalColor = oConsoleScreenBufferInfo.wAttributes & 0xFF;
  uTestColor = (uOriginalColor & 0xF0) | 0x0A; # Bright green foreground, keep same background.
  if not oKernel32.SetConsoleTextAttribute(ohStdOut, uTestColor):
    fThrowLastError("SetConsoleTextAttribute(0x%08X, 0x%02X)" % (ohStdOut.value, uTestColor));
  print "  * This should be green.";sys.stdout.flush();
  if not oKernel32.SetConsoleTextAttribute(ohStdOut, uOriginalColor):
    fThrowLastError("SetConsoleTextAttribute(0x%08X, 0x%02X)" % (ohStdOut.value, uOriginalColor));
  
  print "* Testing process functions...";sys.stdout.flush();
  
  # cPipe
  print "* Testing cPipe...";sys.stdout.flush();
  def fTestPipe(oPipe):
    sWrittenBytes = "test\0test\x7f\x80\xff";
    oPipe.fWriteBytes(sWrittenBytes + "\n");
    sReadBytes = oPipe.fsReadLine();
    assert sReadBytes == sWrittenBytes, \
        "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
    oPipe.fWriteBytes(sWrittenBytes + "\r\n");
    sReadBytes = oPipe.fsReadLine();
    assert sReadBytes == sWrittenBytes, \
        "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
    oPipe.fWriteBytes(sWrittenBytes);
    oPipe.fClose(bInput = True);
    sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
    assert sReadBytes == sWrittenBytes, \
        "Expected %s, got %s" % (repr(sWrittenBytes), repr(sReadBytes));
    sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
    assert sReadBytes == "", \
        "Read %s after closing pipe for write" % repr(sReadBytes);
    oPipe.fClose();
    sReadBytes = oPipe.fsReadBytes(len(sWrittenBytes));
    assert sReadBytes == "", \
        "Read %s from a completely closed pipe" % repr(sReadBytes);
    try:
      oPipe.fWriteBytes("test");
    except IOError:
      pass;
    else:
      raise AssertionError("Should not be able to write to a closed pipe!");
  fTestPipe(cPipe.foCreate());
  print "  * Testing cPipe with non-inheritable handles...";sys.stdout.flush();
  fTestPipe(cPipe.foCreate(bInheritableInput = False, bInheritableOutput = False));
  
  # Test process functions
  sComSpec = os.environ.get("ComSpec");
  
  sComSpec_x86 = sComSpec.replace("\\system32\\", "\\SysWOW64\\");
  if sComSpec != sComSpec_x86 and os.path.isfile(sComSpec_x86):
    fTestProcess(sComSpec_x86, "x86");
    fTestProcess(sComSpec, "x64");
  else:
    fTestProcess(sComSpec, fsGetPythonISA());
  
  # mDbgHelp.fsUndecorateSymbolName
  print "* Testing mDbgHelp...";sys.stdout.flush();
  print "  * fsUndecorateSymbolName...";sys.stdout.flush();
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
    print "    + %s => %s / %s" % (sDecoratedSymbolName, sUndecoratedSymbolName, sUndecoratedFullSymbolName);sys.stdout.flush();
  print "* Texting cUWPApplication...";sys.stdout.flush();
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
