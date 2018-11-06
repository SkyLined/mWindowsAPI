from .fbLastErrorIs import fbLastErrorIs;
from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fsGetPythonISA import fsGetPythonISA;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;
from .oSystemInfo import oSystemInfo;

JOBOBJECT_EXTENDED_LIMIT_INFORMATION = {
  "x86": JOBOBJECT_EXTENDED_LIMIT_INFORMATION_32,
  "x64": JOBOBJECT_EXTENDED_LIMIT_INFORMATION_64,
}[fsGetPythonISA()];

class cJobObject(object):
  def __init__(oSelf, *auProcessIds):
    oSelf.__hJob = KERNEL32.CreateJobObjectW(NULL, NULL);
    if not fbIsValidHandle(oSelf.__hJob):
      fThrowLastError("CreateJobObject(NULL, NULL)");
    for uProcessId in auProcessIds:
      assert oSelf.fbAddProcessForId(uProcessId, bThrowAllErrors = True), \
          "Yeah, well, you know, that's just like ehh.. your opinion, man.";
  
  def fbAddProcessForId(oSelf, uProcessId, bThrowAllErrors = False):
    hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_SET_QUOTA | PROCESS_TERMINATE);
    try:
      if KERNEL32.AssignProcessToJobObject(oSelf.__hJob, hProcess):
        return True;
      if bThrowAllErrors or not fbLastErrorIs(ERROR_ACCESS_DENIED):
        fThrowLastError("AssignProcessToJobObject(0x%08X, 0x%08X)" % (oSelf.__hJob.value, hProcess.value,));
    finally:
      if not KERNEL32.CloseHandle(hProcess):
        fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
    # We cannot add the process to the job, but maybe it is already added?
    hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_QUERY_LIMITED_INFORMATION);
    try:
      bProcessInJob = BOOL();
      if not KERNEL32.IsProcessInJob(hProcess, oSelf.__hJob, POINTER(bProcessInJob)):
        fThrowLastError("IsProcessInJob(0x%X, ..., ...)" % (hProcess,));
      return bProcessInJob.value == TRUE;
    finally:
      if not KERNEL32.CloseHandle(hProcess):
        fThrowLastError("CloseHandle(0x%X)" % (hProcess,));
  
  def __foQueryExtendedLimitInformation(oSelf):
    oExtendedLimitInformation = JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
    dwReturnLength = DWORD();
    if not KERNEL32.QueryInformationJobObject(
      oSelf.__hJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      fxCast(LPVOID, POINTER(oExtendedLimitInformation)), # lpJobObjectInfo
      fuSizeOf(oExtendedLimitInformation), # cbJobObjectInfoLength,
      POINTER(dwReturnLength), # lpReturnLength
    ):
      fThrowLastError("QueryInformationJobObject(..., 0x%08X, ..., 0x%X, *dwReturnLength=0x%X)" % \
          (JobObjectExtendedLimitInformation, fuSizeOf(oExtendedLimitInformation), dwReturnLength.value));
    assert dwReturnLength.value == fuSizeOf(oExtendedLimitInformation), \
        "QueryInformationJobObject(..., 0x%08X, ..., 0x%X, ...) => wrote 0x%X bytes" % \
        (JobObjectExtendedLimitInformation, fuSizeOf(oExtendedLimitInformation), dwReturnLength.value);
    return oExtendedLimitInformation;
  
  def __fSetExtendedLimitInformation(oSelf, oExtendedLimitInformation):
    if not KERNEL32.SetInformationJobObject(
      oSelf.__hJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      fxCast(LPVOID, POINTER(oExtendedLimitInformation)), # lpJobObjectInfo
      fuSizeOf(oExtendedLimitInformation), # cbJobObjectInfoLength,
    ):
      fThrowLastError("SetInformationJobObject(..., JobObjectExtendedLimitInformation, ..., 0x%X)" % \
          (fuSizeOf(oExtendedLimitInformation),));
  
  def fSetMaxProcessMemoryUse(oSelf, uMemoryUseInBytes):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    oExtendedLimitInformation.ProcessMemoryLimit = long(uMemoryUseInBytes);
    oExtendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    oSelf.__fSetExtendedLimitInformation(oExtendedLimitInformation);

  def fSetMaxTotalMemoryUse(oSelf, uMemoryUseInBytes):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    oExtendedLimitInformation.JobMemoryLimit = long(uMemoryUseInBytes);
    oExtendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    oSelf.__fSetExtendedLimitInformation(oExtendedLimitInformation);
  
  def fuGetMaxProcessMemoryUse(oSelf):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    return long(oExtendedLimitInformation.PeakProcessMemoryUsed);
  
  def fuGetMaxTotalMemoryUse(oSelf):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    return long(oExtendedLimitInformation.PeakJobMemoryUsed);

