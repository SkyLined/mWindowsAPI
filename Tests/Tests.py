from fTestDependencies import fTestDependencies;
fTestDependencies();

try:
  import mDebugOutput;
except:
  mDebugOutput = None;
try:
  try:
    from oConsole import oConsole;
  except:
    import sys, threading;
    oConsoleLock = threading.Lock();
    class oConsole(object):
      @staticmethod
      def fOutput(*txArguments, **dxArguments):
        sOutput = "";
        for x in txArguments:
          if isinstance(x, (str, unicode)):
            sOutput += x;
        sPadding = dxArguments.get("sPadding");
        if sPadding:
          sOutput.ljust(120, sPadding);
        oConsoleLock.acquire();
        print sOutput;
        sys.stdout.flush();
        oConsoleLock.release();
      fPrint = fOutput;
      @staticmethod
      def fStatus(*txArguments, **dxArguments):
        pass;
  
  import os;
  
  #Import the test subject
  from mWindowsAPI import *;
  from mWindowsSDK import *;
  oKernel32 = foLoadKernel32DLL();
  from mWindowsAPI import mDbgHelp;
  from mWindowsAPI.fThrowLastError import fThrowLastError;
  from fTestProcess import fTestProcess;
  
  # Test system info
  oConsole.fOutput("* Testing system info...");
  oConsole.fOutput("  * fsGetPythonISA() = %s" % fsGetPythonISA());
  oConsole.fOutput("  * oSystemInfo...");
  oConsole.fOutput("    | OS:                      %s" %  oSystemInfo.sOSFullDetails);
  oConsole.fOutput("    | Processors:              %d" % oSystemInfo.uNumberOfProcessors);
  oConsole.fOutput("    | Address range:           0x%08X - 0x%08X" % (oSystemInfo.uMinimumApplicationAddress, oSystemInfo.uMaximumApplicationAddress));
  oConsole.fOutput("    | Page size:               0x%X" % oSystemInfo.uPageSize);
  oConsole.fOutput("    | Allocation granularity:  0x%X" % oSystemInfo.uAllocationAddressGranularity);
  oConsole.fOutput("    | System name:             %s" % oSystemInfo.sSystemName);
  oConsole.fOutput("    | System id:               %s" % oSystemInfo.sUniqueSystemId);
  
  # Test console functions
  oConsole.fOutput("* Testing oKernel32 console functions...");
  ohStdOut = oKernel32.GetStdHandle(STD_OUTPUT_HANDLE);
  oConsoleScreenBufferInfo = CONSOLE_SCREEN_BUFFER_INFO();
  if not oKernel32.GetConsoleScreenBufferInfo(ohStdOut, oConsoleScreenBufferInfo.foCreatePointer()):
    fThrowLastError("GetConsoleScreenBufferInfo(0x%08X, 0x%X)" % (ohStdOut.value, oConsoleScreenBufferInfo.fuGetAddress()));
  oConsole.fOutput("  Console buffer size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwSize.X, oConsoleScreenBufferInfo.dwSize.Y));
  oConsole.fOutput("  Console window size (WxH): %d x %d" % (oConsoleScreenBufferInfo.dwMaximumWindowSize.X, oConsoleScreenBufferInfo.dwMaximumWindowSize.Y));
  uOriginalColor = oConsoleScreenBufferInfo.wAttributes & 0xFF;
  uTestColor = (uOriginalColor & 0xF0) | 0x0A; # Bright green foreground, keep same background.
  if not oKernel32.SetConsoleTextAttribute(ohStdOut, uTestColor):
    fThrowLastError("SetConsoleTextAttribute(0x%08X, 0x%02X)" % (ohStdOut.value, uTestColor));
  oConsole.fOutput("  * This should be green.");
  if not oKernel32.SetConsoleTextAttribute(ohStdOut, uOriginalColor):
    fThrowLastError("SetConsoleTextAttribute(0x%08X, 0x%02X)" % (ohStdOut.value, uOriginalColor));
  
  oConsole.fOutput("* Testing process functions...");
  
  # cPipe
  oConsole.fOutput("* Testing cPipe...");
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
  oConsole.fOutput("  * Testing cPipe with non-inheritable handles...");
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
  
  oConsole.fOutput("+ Done.");
  
except Exception as oException:
  if mDebugOutput:
    mDebugOutput.fTerminateWithException(oException, bShowStacksForAllThread = True);
  raise;
