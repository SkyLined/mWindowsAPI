import re, sys, time;
from mWindowsAPI import *;
from mWindowsSDK import *;
from mConsole import oConsole;

def fDumpThreadInfo(oThread, sISA, bDumpContext):
  oConsole.fOutput("  * Thread: %s" % (repr(oThread),));
  o0TEB = oThread.fo0GetTEB();
  if o0TEB:
    oConsole.fOutput("    * TEB:");
    for sLine in oThread.o0TEB.fasDump("Thread %d/0x%X TEB" % (oThread.uId, oThread.uId)):
      oConsole.fOutput("    | " + sLine);
  if bDumpContext:
    d0uRegisterValue_by_sbName = oThread.fd0uGetRegisterValueByName();
    if d0uRegisterValue_by_sbName:
      oConsole.fOutput("    * Registers:");
      # Filter out partial register names such as ah, al, ax, ... (and optionally eax, ... on x64 ISAs)
      rFilterRegisterNames = re.compile({
        "x64": rb"^r([a-z]+|\d+)$",
        "x86": rb"^e[a-z]+$",
      }[sISA]);
      asbFilteredRegisterNames = [
        str(sbRegisterName, 'latin1') for sbRegisterName in d0uRegisterValue_by_sbName.keys()
        if rFilterRegisterNames.match(sbRegisterName)
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
          for sRegisterName in asbFilteredRegisterNames:
            if sRegisterName.endswith(sRegisterOrder):
              uRegisterValue = d0uRegisterValue_by_sbName[bytes(sRegisterName, 'latin1')]
              asRegistersOutput.append(sRegisterOutputFormat % (sRegisterName, "%X" % uRegisterValue));
        if asRegistersOutput:
          oConsole.fOutput("    | ", "   ".join(asRegistersOutput));
      asFlagNames = ["zf", "cf", "if", "af", "rf", "pf", "tf", "df", "of", "sf"];
      oConsole.fOutput("    | flags = ", " ".join([
        "%s:%d" % (sFlagName, d0uRegisterValue_by_sbName[bytes(sFlagName, 'latin1')])
        for sFlagName in asFlagNames
      ]));

def faoGetAndDumpProcessThreads(oTestProcess):
  oConsole.fStatus("  * Calling <cProcess #%X>.faoGetThreads()..." % (oTestProcess.uId,));
  aoThreads = oTestProcess.faoGetThreads();
  oConsole.fOutput("  + <cProcess #%X>.faoGetThreads() => [%s]" % (oTestProcess.uId, ", ".join(["0x%X" % (oThread.uId,) for oThread in aoThreads]),));
  return aoThreads;

def fTestThread(sComSpec, sThisProcessISA, sExpectedChildProcessISA):
  oConsole.fOutput("=== Testing thread related functions ", sPadding = "=");
  oConsole.fOutput("* This process ISA: %s, test thread ISA: %s" % (sThisProcessISA, sExpectedChildProcessISA));
  oConsole.fStatus("  * Calling cProcess.foCreateForBinaryPath(%s, bSuspended = True)..." % (repr(sComSpec),));
  oTestProcess = cConsoleProcess.foCreateForBinaryPath(sComSpec, bSuspended = True);
  try:
    oConsole.fOutput("  + cProcess.foCreateForBinaryPath(%s, bSuspended = True) = <cProcess #%X>" % (repr(sComSpec), oTestProcess.uId));
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
    oConsole.fOutput("  + <cProcess #%X>.fuCreateThreadForAddress(0, bSuspended = True) = 0x%X" % (oTestProcess.uId, uTestThreadId));
    
    aoThreads = faoGetAndDumpProcessThreads(oTestProcess);
    assert uTestThreadId in [oThread.uId for oThread in aoThreads], \
        "Thread 0x%X not found in list of threads!?" % uTestThreadId;
    
    oConsole.fStatus("  * Calling <cProcess #%X>.foGetThreadForId(0x%X)..." % (oTestProcess.uId, uTestThreadId));
    oTestThread = oTestProcess.foGetThreadForId(uTestThreadId);
    oConsole.fOutput("  + <cProcess #%X>.foGetThreadForId(0x%X) = <cThread #%0X>" % (oTestProcess.uId, uTestThreadId, oTestThread.uId));
    oConsole.fOutput("    ", repr(oTestThread));
    fDumpThreadInfo(oTestThread, oTestProcess.sISA, bDumpContext = True);
    
    oConsole.fStatus("  * Calling <cThread #%0X>.fbTerminate()..." % uTestThreadId);
    assert oTestThread.fbTerminate(), \
        "Expected to be able to terminate the thread";
    oConsole.fOutput("  + <cThread #%X>.fbTerminate() = True" % uTestThreadId);
    oConsole.fOutput("    ", repr(oTestThread));
    
    oConsole.fStatus("  * Calling <cThread #%X>.fbWait(1)..." % uTestThreadId);
    assert oTestThread.fbWait(1), \
        "Expected to be able to wait for the thread to terminate in 1 second!";
    oConsole.fOutput("  + <cThread #%X>.fbWait(1) = True" % uTestThreadId);
    oConsole.fOutput("    ", repr(oTestThread));
    fDumpThreadInfo(oTestThread, oTestProcess.sISA, bDumpContext = True);
    
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
      oConsole.fOutput("  + <cThread #%X>.fbTerminate() = True" % (oThread.uId,));
      oConsole.fStatus("  * Calling <cThread #%X>.fbWait(1)..." % (oThread.uId,));
      assert oThread.fbWait(1), \
          "Cannot terminated thread #%X!" % (oThread.uId,);
      oConsole.fOutput("  + <cThread #%X>.fbWait(1) = True" % (oThread.uId,));
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