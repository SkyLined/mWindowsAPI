import threading, time;
from mWindowsAPI import *;
from oConsole import oConsole;

def fTestConsoleProcess(sComSpec, sThisProcessISA, sExpectedChildProcessISA):
  oConsole.fPrint("=== Testing console process related functions ", sPadding = "=");
  # cConsoleProcess, fSuspendForProcessId
  oConsole.fPrint("* Testing cConsoleProcess...");
  oConsole.fOutput("* This process ISA: %s, child console process ISA: %s" % (sThisProcessISA, sExpectedChildProcessISA));
  sExpectedOutput = "Test";
  oConsoleProcess = cConsoleProcess.foCreateForBinaryPathAndArguments(
    sComSpec,
    ["/K", "ECHO %s&ECHO OFF" % sExpectedOutput],
  );
  try:
    sExpectedOutput += "\r\n";
    time.sleep(1); # Allow process to start
    oConsole.fPrint("  * Reading process output...");
    sActualOutput = oConsoleProcess.oStdOutPipe.fsReadBytes(len(sExpectedOutput));
    assert sActualOutput == sExpectedOutput, \
        "Expected %s, got %s" % (repr(sExpectedOutput), repr(sActualOutput));
    # Suspend the process to test for a known issue: attempting to close handles on a
    # suspended process will hang until the process is resumed or killed.
    fSuspendForProcessId(oConsoleProcess.uId);
    asBytesRead = [""];
    def fPipeReadingThread():
      oConsole.fPrint("  * Reading end of console process output in thread...");
      asBytesRead[0] = oConsoleProcess.oStdOutPipe.fsReadBytes();
    oReadThread = threading.Thread(target = fPipeReadingThread);
    oReadThread.start();
    def fKillProcessThread():
      time.sleep(1);
      oConsole.fPrint("  * Terminating console process...");
      fbTerminateForProcessId(oConsoleProcess.uId);
    oKillProcessThread = threading.Thread(target = fKillProcessThread);
    oKillProcessThread.start();
    oConsole.fPrint("  * Closing pipes...");
    # This will hang until the process is killed...
    oConsoleProcess.fClose();
    oConsole.fPrint("  * Waiting for kill process thread...");
    oKillProcessThread.join();
    oConsole.fPrint("  * Waiting for end of console process output in thread...");
    oReadThread.join();
    assert asBytesRead[0] == "", \
        "Expected %s, got %s" % (repr(""), repr(asBytesRead[0]));
    oConsole.fPrint("  * Reading end of output...");
    sReadBytes = oConsoleProcess.oStdOutPipe.fsReadBytes(1);
    assert sReadBytes == "", \
        "Read %s from a completely closed pipe" % repr(sReadBytes);
  finally:
    if oConsoleProcess.bIsRunning:
      oConsoleProcess.fbTerminate();