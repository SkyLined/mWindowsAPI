from fTestDependencies import fTestDependencies;
fTestDependencies();

try: # mDebugOutput use is Optional
  import mDebugOutput as m0DebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  m0DebugOutput = None;

try:
  try:
    from mConsole import oConsole;
  except:
    import sys, threading;
    oConsoleLock = threading.Lock();
    class oConsole(object):
      @staticmethod
      def fOutput(*txArguments, **dxArguments):
        sOutput = "";
        for x in txArguments:
          if isinstance(x, str):
            sOutput += x;
        sPadding = dxArguments.get("sPadding");
        if sPadding:
          sOutput.ljust(120, sPadding);
        oConsoleLock.acquire();
        print(sOutput);
        sys.stdout.flush();
        oConsoleLock.release();
      fPrint = fOutput;
      @staticmethod
      def fStatus(*txArguments, **dxArguments):
        pass;
  
  import os, sys;
  
  bTestEverything = True; # Set to false if individual components are to be tested.
  bTestSystemInfo = False;
  bTestConsole = False;
  bTestPipe = False;
  bTestProcess = False;
  bTestConsoleProcess = False;
  bTestThread = False;
  bTestDbgHelp = False;
  bQuick = False;
  bFull = False;
  
  for sArgument in sys.argv[1:]:
    if sArgument == "--quick":
      bQuick = True;
    elif sArgument == "--full":
      bFull = True;
    elif sArgument == "--debug":
      assert m0DebugOutput, \
          "mDebugOutput is not available!";
      m0DebugOutput.fEnableAllDebugOutput();
    elif sArgument == "--system-info":
      bTestSystemInfo = True;
      bTestEverything = False;
    elif sArgument == "--console":
      bTestConsole = True;
      bTestEverything = False;
    elif sArgument == "--pipe":
      bTestPipe = True;
      bTestEverything = False;
    elif sArgument == "--process":
      bTestProcess = True;
      bTestEverything = False;
    elif sArgument == "--console-process":
      bTestConsoleProcess = True;
      bTestEverything = False;
    elif sArgument == "--thread":
      bTestThread = True;
      bTestEverything = False;
    elif sArgument == "--dbg-help":
      bTestDbgHelp = True;
      bTestEverything = False;
    else:
      raise AssertionError("Unknown argument: %s" % repr(sArgument));
  assert not bQuick or not bFull, \
      "Cannot test both quick and full!";
  
  #Import the test subject
  from mWindowsAPI import *;
  from mWindowsAPI.fThrowLastError import fThrowLastError;
  
  from fTestConsole import fTestConsole;
  from fTestDbgHelp import fTestDbgHelp;
  from fTestPipe import fTestPipe;
  from fTestProcess import fTestProcess;
  from fTestConsoleProcess import fTestConsoleProcess;
  from fTestSystemInfo import fTestSystemInfo;
  from fTestThread import fTestThread;
  
  sPythonISA = fsGetPythonISA();
  if sPythonISA == "x64":
    s0ComSpec_x64 = os.environ.get("ComSpec");
    s0ComSpec_x86 = s0ComSpec_x64.replace("\\system32\\", "\\SysWOW64\\");
  else:
    s0ComSpec_x64 = None;
    s0ComSpec_x86 = os.environ.get("ComSpec");
  
  # Test system info API
  if bTestSystemInfo or bTestEverything:
    fTestSystemInfo();
  
  # Test console API
  if bTestConsole or bTestEverything:
    fTestConsole();
  
  # Test Pipe API
  if bTestPipe or bTestEverything:
    fTestPipe();
  
  # Test process API
  if bTestProcess or bTestEverything:
    if s0ComSpec_x86: fTestProcess(s0ComSpec_x86, sPythonISA, "x86");
    if s0ComSpec_x64: fTestProcess(s0ComSpec_x64, sPythonISA, "x64");
  
  # Test console process API
  if bTestConsoleProcess or bTestEverything:
    if s0ComSpec_x86: fTestConsoleProcess(s0ComSpec_x86, sPythonISA, "x86");
    if s0ComSpec_x64: fTestConsoleProcess(s0ComSpec_x64, sPythonISA, "x64");
  
  # Test thread API
  if bTestThread or bTestEverything:
    if s0ComSpec_x86: fTestThread(s0ComSpec_x86, sPythonISA, "x86");
    if s0ComSpec_x64: fTestThread(s0ComSpec_x64, sPythonISA, "x64");
  
  # Test DbgHelp API
  if bTestDbgHelp or bTestEverything:
    fTestDbgHelp();
  
  oConsole.fOutput("+ Done.");
  
except Exception as oException:
  if m0DebugOutput:
    m0DebugOutput.fTerminateWithException(oException, bShowStacksForAllThread = True);
  raise;
