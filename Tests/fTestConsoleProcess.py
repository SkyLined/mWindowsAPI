import threading, time;
from mWindowsAPI import *;
from mConsole import oConsole;

def fTestConsoleProcess(sComSpec, sThisProcessISA, sExpectedChildProcessISA):
  oConsole.fOutput("=== Testing console process related functions ", sPadding = "=");
  # cConsoleProcess, fSuspendForProcessId
  oConsole.fOutput("* Testing cConsoleProcess...");
  sExpectedOutput = "Test";
  oConsoleProcess = cConsoleProcess.foCreateForBinaryPathAndArguments(
    sComSpec,
    ["/K", "ECHO %s&ECHO OFF" % sExpectedOutput],
  );
  try:
    oConsole.fOutput("* Console process id: %s, ISA: %s" % (oConsoleProcess.uId, sExpectedChildProcessISA));
    assert oConsoleProcess.sISA == sExpectedChildProcessISA, \
        "oConsoleProcess.sISA == %s instead of %s" % (oConsoleProcess.sISA, sExpectedChildProcessISA);
    sExpectedOutput += "\r\n";
    time.sleep(1); # Allow process to start
    oConsole.fOutput("  * Reading process output...");
    sActualOutput = oConsoleProcess.oStdOutPipe.fsRead(len(sExpectedOutput));
    assert sActualOutput == sExpectedOutput, \
        "Expected %s, got %s" % (repr(sExpectedOutput), repr(sActualOutput));
    # Suspend the process to test for a known issue: attempting to close handles on a
    # suspended process will hang until the process is resumed or killed.
    fSuspendForProcessId(oConsoleProcess.uId);
    asDataRead = [""];
    def fPipeReadingThread():
      oConsole.fOutput("  * Reading end of console process output in thread...");
      asDataRead[0] = oConsoleProcess.oStdOutPipe.fsRead();
    oReadThread = threading.Thread(target = fPipeReadingThread);
    oReadThread.start();
    def fKillProcessThread():
      time.sleep(1);
      oConsole.fOutput("  * Terminating console process...");
      fbTerminateForProcessId(oConsoleProcess.uId);
    oKillProcessThread = threading.Thread(target = fKillProcessThread);
    oKillProcessThread.start();
    oConsole.fOutput("  * Closing pipes...");
    # This will hang until the process is killed...
    oConsoleProcess.fClose();
    oConsole.fOutput("  * Waiting for kill process thread...");
    oKillProcessThread.join();
    oConsole.fOutput("  * Waiting for end of console process output in thread...");
    oReadThread.join();
    assert asDataRead[0] == "", \
        "Expected %s, got %s" % (repr(""), repr(asDataRead[0]));
    oConsole.fOutput("  * Reading end of output...");
    sReadBytes = oConsoleProcess.oStdOutPipe.fsbReadBytes(1);
    assert sReadBytes == b"", \
        "Read %s from a completely closed pipe" % repr(sReadBytes);
  finally:
    if oConsoleProcess.bIsRunning:
      oConsoleProcess.fbTerminate();