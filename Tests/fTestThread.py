import re, sys, time;
from mWindowsAPI import *;
from mWindowsSDK import *;
from oConsole import oConsole;

def fDumpThreadInfo(oThread, sISA, bDumpContext):
  oConsole.fPrint("  * Thread: %s" % (repr(oThread),));
  o0TEB = oThread.fo0GetTEB();
  if o0TEB:
    oConsole.fPrint("    * TEB:");
    for sLine in oThread.o0TEB.fasDump("Thread %d/0x%X TEB" % (oThread.uId, oThread.uId)):
      oConsole.fPrint("    | " + sLine);
  if bDumpContext:
    d0uRegisterValue_by_sName = oThread.fd0uGetRegisterValueByName();
    if d0uRegisterValue_by_sName:
      oConsole.fPrint("    * Registers:");
      # Filter out partial register names such as ah, al, ax, ... (and optionally eax, ... on x64 ISAs)
      rFilterRegisterNames = re.compile({
        "x64": r"^r([a-z]+|\d+)$",
        "x86": r"^e[a-z]+$",
      }[sISA]);
      asFilteredRegisterNames = [
        sRegisterName for sRegisterName in d0uRegisterValue_by_sName.keys()
        if rFilterRegisterNames.match(sRegisterName)
      ];
      # Show them in a table:
      sRegisterOutputFormat = {
        "x64": "%-3s = %16s",
        "x86": "%-3s = %8s",
      }[sISA];
      aasRegisterOrder = [
        ["ax", "bx", "cx", "dx"],
        ["si", "di", "sp", "bp"],
        ["r8", "r9", "r10", "r11"],
        ["r12", "r13", "r14", "r15"],
        ["ip"],
      ];
      for asRegisterOrder in aasRegisterOrder:
        asRegistersOutput = [];
        for sRegisterOrder in asRegisterOrder:
          for sRegisterName in asFilteredRegisterNames:
            if sRegisterName.endswith(sRegisterOrder):
              asRegistersOutput.append(sRegisterOutputFormat % (sRegisterName, "%X" % d0uRegisterValue_by_sName[sRegisterName]));
        if asRegistersOutput:
          oConsole.fPrint("    | ", "   ".join(asRegistersOutput));
      asFlagNames = ["zf", "cf", "if", "af", "rf", "pf", "tf", "df", "of", "sf"];
      oConsole.fPrint("    | flags = ", " ".join([
        "%s:%d" % (sFlagName, d0uRegisterValue_by_sName[sFlagName])
        for sFlagName in asFlagNames
      ]));

def faoGetAndDumpProcessThreads(oTestProcess):
  oConsole.fStatus("  * Calling <cProcess #%X>.faoGetThreads()..." % (oTestProcess.uId,));
  aoThreads = oTestProcess.faoGetThreads();
  oConsole.fPrint("  + <cProcess #%X>.faoGetThreads() => [%s]" % (oTestProcess.uId, ", ".join(["0x%X" % (oThread.uId,) for oThread in aoThreads]),));
  return aoThreads;

def fTestThread(sComSpec, sThisProcessISA, sExpectedChildProcessISA):
  oConsole.fPrint("=== Testing thread related functions ", sPadding = "=");
  oConsole.fOutput("* This process ISA: %s, test thread ISA: %s" % (sThisProcessISA, sExpectedChildProcessISA));
  oConsole.fStatus("  * Calling cProcess.foCreateForBinaryPath(%s, bSuspended = True)..." % (repr(sComSpec),));
  oTestProcess = cConsoleProcess.foCreateForBinaryPath(sComSpec, bSuspended = True);
  try:
    oConsole.fPrint("  + cProcess.foCreateForBinaryPath(%s, bSuspended = True) = <cProcess #%X>" % (repr(sComSpec), oTestProcess.uId));
    time.sleep(1); # Allow process to start
    # cProcess
    assert oTestProcess.sISA == sExpectedChildProcessISA, \
        "cProcess.sISA == %s instead of %s" % (oTestProcess.sISA, sExpectedChildProcessISA);
    
    # List all threads in process
    aoThreads = faoGetAndDumpProcessThreads(oTestProcess);
    fDumpThreadInfo(aoThreads[0], oTestProcess.sISA, bDumpContext = True);
    
    # Create an additional test thread
    oConsole.fStatus("  * Calling <cProcess #%X>.fuCreateThreadForAddress(0, bSuspended = True)..." % (oTestProcess.uId,));
    uTestThreadId = oTestProcess.fuCreateThreadForAddress(0, bSuspended = True);
    oConsole.fPrint("  + <cProcess #%X>.fuCreateThreadForAddress(0, bSuspended = True) = 0x%X" % (oTestProcess.uId, uTestThreadId));
    
    aoThreads = faoGetAndDumpProcessThreads(oTestProcess);
    assert uTestThreadId in [oThread.uId for oThread in aoThreads], \
        "Thread 0x%X not found in list of threads!?" % uTestThreadId;
    
    oConsole.fStatus("  * Calling <cProcess #%X>.foGetThreadForId(0x%X)..." % (oTestProcess.uId, uTestThreadId));
    oTestThread = oTestProcess.foGetThreadForId(uTestThreadId);
    oConsole.fPrint("  + <cProcess #%X>.foGetThreadForId(0x%X) = <cThread #%0X>" % (oTestProcess.uId, uTestThreadId, oTestThread.uId));
    oConsole.fPrint("    ", repr(oTestThread));
    fDumpThreadInfo(oThread, oTestProcess.sISA, bDumpContext = True);
    
    oConsole.fStatus("  * Calling <cThread #%0X>.fbTerminate()..." % uTestThreadId);
    assert oTestThread.fbTerminate(), \
        "Expected to be able to terminate the thread";
    oConsole.fPrint("  + <cThread #%X>.fbTerminate() = True" % uTestThreadId);
    oConsole.fPrint("    ", repr(oTestThread));
    
    oConsole.fStatus("  * Calling <cThread #%X>.fbWait(1)..." % uTestThreadId);
    assert oTestThread.fbWait(1), \
        "Expected to be able to wait for the thread to terminate in 1 second!";
    oConsole.fPrint("  + <cThread #%X>.fbWait(1) = True" % uTestThreadId);
    oConsole.fPrint("    ", repr(oTestThread));
    fDumpThreadInfo(oThread, oTestProcess.sISA, bDumpContext = True);
    
    # We will have to wait a bit for the terminated thread to be removed from the process.
    aoThreads = faoGetAndDumpProcessThreads(oTestProcess);
    assert uTestThreadId not in [oThread.uId for oThread in aoThreads], \
        "Thread 0x%X found in list of threads after it was terminated!?" % uTestThreadId;
    
    for oThread in aoThreads:
      assert not oThread.bIsTerminated, \
          "Thread 0x%X is already terminated!?" % (oThread.uId,);
      oConsole.fStatus("  * Calling <cThread #%X>.fbTerminate()..." % (oThread.uId,));
      assert oThread.fbTerminate(), \
          "Cannot terminated thread #%X!" % (oThread.uId,);
      oConsole.fPrint("  + <cThread #%X>.fbTerminate() = True" % (oThread.uId,));
      oConsole.fStatus("  * Calling <cThread #%X>.fbWait(1)..." % (oThread.uId,));
      assert oThread.fbWait(1), \
          "Cannot terminated thread #%X!" % (oThread.uId,);
      oConsole.fPrint("  + <cThread #%X>.fbWait(1) = True" % (oThread.uId,));
      assert oThread.bIsTerminated, \
          "Thread was not terminated #%X!" % (oThread.uId,);
    oConsole.fStatus("  * Calling <cProcess>.faoGetThreads()...");
    aoThreads = faoGetAndDumpProcessThreads(oTestProcess);
    assert len(aoThreads) == 0, \
        "Threads exist after they were terminated!?";
    assert oTestProcess.bIsTerminated, \
        "Test process was not terminated!";
    try:
      fohOpenForThreadIdAndDesiredAccess(0, THREAD_ALL_ACCESS);
    except:
      pass;
    else:
      raise AssertionError("Opening a non-existing thread somehow worked!?");
    ohThread = foh0OpenForThreadIdAndDesiredAccess(0, THREAD_ALL_ACCESS, bMustExist = False);
    assert ohThread is None, \
        "Opening a non-existing thread somehow worked!?";
  finally:
    if oTestProcess and oTestProcess.bIsRunning:
      oTestProcess.fbTerminate();