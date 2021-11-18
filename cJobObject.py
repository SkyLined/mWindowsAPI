from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fsGetPythonISA import fsGetPythonISA;
from .fThrowLastError import fThrowLastError;
from .oSystemInfo import oSystemInfo;

JOBOBJECT_EXTENDED_LIMIT_INFORMATION = {
  "x86": JOBOBJECT_EXTENDED_LIMIT_INFORMATION32,
  "x64": JOBOBJECT_EXTENDED_LIMIT_INFORMATION64,
}[fsGetPythonISA()];

class cJobObject(object):
  def __init__(oSelf, *auProcessIds):
    from mWindowsSDK.mKernel32 import oKernel32DLL;
    oSelf.__ohJob = oKernel32DLL.CreateJobObjectW(NULL, NULL);
    if not fbIsValidHandle(oSelf.__ohJob):
      fThrowLastError("CreateJobObject(NULL, NULL)");
    for uProcessId in auProcessIds:
      assert oSelf.fbAddProcessForId(uProcessId, bThrowAllErrors = True), \
          "Yeah, well, you know, that's just like ehh.. your opinion, man.";
  
  def fbAddProcessForId(oSelf, uProcessId, bThrowAllErrors = False):
    from mWindowsSDK.mKernel32 import oKernel32DLL;
    ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_SET_QUOTA | PROCESS_TERMINATE);
    try:
      if oKernel32DLL.AssignProcessToJobObject(oSelf.__ohJob, ohProcess):
        return True;
      if bThrowAllErrors or not fbLastErrorIs(ERROR_ACCESS_DENIED):
        fThrowLastError("AssignProcessToJobObject(%s, %s)" % (repr(oSelf.__ohJob), repr(ohProcess)));
    finally:
      if not oKernel32DLL.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
    # We cannot add the process to the job, but maybe it is already added?
    ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    try:
      obProcessInJob = BOOLEAN();
      if not oKernel32DLL.IsProcessInJob(ohProcess, oSelf.__ohJob, obProcessInJob.foCreatePointer()):
        fThrowLastError("IsProcessInJob(0x%X, ..., ...)" % (ohProcess,));
      return obProcessInJob != 0;
    finally:
      if not oKernel32DLL.CloseHandle(ohProcess):
        fThrowLastError("CloseHandle(0x%X)" % (ohProcess,));
  
  def __foQueryExtendedLimitInformation(oSelf):
    from mWindowsSDK.mKernel32 import oKernel32DLL;
    oExtendedLimitInformation = JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
    odwReturnLength = DWORD();
    if not oKernel32DLL.QueryInformationJobObject(
      oSelf.__ohJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      LPVOID(oExtendedLimitInformation, bCast = True), # lpJobObjectInfo
      oExtendedLimitInformation.fuGetSize(), # cbJobObjectInfoLength,
      odwReturnLength.foCreatePointer(), # lpReturnLength
    ):
      fThrowLastError("QueryInformationJobObject(hJob=%s, JobObjectInfoClass=0x%X, lpJobObjectInfo=0x%X, cbJobObjectInfoLength=0x%X, lpReturnLength=0x%X)" % (
        repr(oSelf.__ohJob),
        JobObjectExtendedLimitInformation,
        oExtendedLimitInformation.fuGetAddress(),
        oExtendedLimitInformation.fuGetSize(),
        odwReturnLength.fuGetAddress()
      ));
    assert odwReturnLength == oExtendedLimitInformation.fuGetSize(), \
        "QueryInformationJobObject(hJob=%s, JobObjectInfoClass=0x%X, lpJobObjectInfo=0x%X, cbJobObjectInfoLength=0x%X, lpReturnLength=0x%X) => wrote 0x%X bytes" % (
          repr(oSelf.__ohJob),
          JobObjectExtendedLimitInformation,
          oExtendedLimitInformation.fuGetAddress(),
          oExtendedLimitInformation.fuGetSize(),
          odwReturnLength.fuGetAddress(),
          odwReturnLength.fuGetValue()
        );
    return oExtendedLimitInformation;
  
  def __fSetExtendedLimitInformation(oSelf, oExtendedLimitInformation):
    from mWindowsSDK.mKernel32 import oKernel32DLL;
    if not oKernel32DLL.SetInformationJobObject(
      oSelf.__ohJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      LPVOID(oExtendedLimitInformation, bCast = True), # lpJobObjectInfo
      oExtendedLimitInformation.fuGetSize(), # cbJobObjectInfoLength,
    ):
      fThrowLastError("SetInformationJobObject(hJob=0x%X, JobObjectInfoClass=0x%X, lpJobObjectInfo=0x%X, cbJobObjectInfoLength=0x%X)" % \
          (oSelf.__ohJob, JobObjectExtendedLimitInformation, oExtendedLimitInformation.fuGetAddress(),
          oExtendedLimitInformation.fuGetSize()));
  
  def fSetMaxProcessMemoryUse(oSelf, uMemoryUseInBytes):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    oExtendedLimitInformation.ProcessMemoryLimit = int(uMemoryUseInBytes);
    oExtendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    oSelf.__fSetExtendedLimitInformation(oExtendedLimitInformation);

  def fSetMaxTotalMemoryUse(oSelf, uMemoryUseInBytes):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    oExtendedLimitInformation.JobMemoryLimit = int(uMemoryUseInBytes);
    oExtendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    oSelf.__fSetExtendedLimitInformation(oExtendedLimitInformation);
  
  def fuGetMaxProcessMemoryUse(oSelf):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    return int(oExtendedLimitInformation.PeakProcessMemoryUsed);
  
  def fuGetMaxTotalMemoryUse(oSelf):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    return int(oExtendedLimitInformation.PeakJobMemoryUsed);

