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
  
  bTestSystemInfo = True;
  bTestConsole = True;
  bTestPipe = True;
  bTestProcess = True;
  bTestThread = True;
  bTestDbgHelp = True;
  
  # Test system info
  if bTestSystemInfo:
    fTestSystemInfo();
  
  if bTestConsole:
    fTestConsole();
  
  # Test Pipe functions
  if bTestPipe:
    fTestPipe();
  
  if bTestProcess:
    # Test process functions
    if s0ComSpec_x86: fTestProcess(s0ComSpec_x86, sPythonISA, "x86");
    if s0ComSpec_x64: fTestProcess(s0ComSpec_x64, sPythonISA, "x64");
    if s0ComSpec_x86: fTestConsoleProcess(s0ComSpec_x86, sPythonISA, "x86");
    if s0ComSpec_x64: fTestConsoleProcess(s0ComSpec_x64, sPythonISA, "x64");
  
  if bTestThread:
    if s0ComSpec_x86: fTestThread(s0ComSpec_x86, sPythonISA, "x86");
    if s0ComSpec_x64: fTestThread(s0ComSpec_x64, sPythonISA, "x64");
  
  if bTestDbgHelp:
    fTestDbgHelp();
  
  oConsole.fOutput("+ Done.");
  
except Exception as oException:
  if mDebugOutput:
    mDebugOutput.fTerminateWithException(oException, bShowStacksForAllThread = True);
  raise;
