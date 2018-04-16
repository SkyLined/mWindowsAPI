from .mDefines import *;
from .mFunctions import *;
from .mTypes import *;
from .mDLLs import KERNEL32;
from .fThrowError import fThrowError;

from .fsGetPythonISA import fsGetPythonISA;
from .oSystemInfo import oSystemInfo;

JOBOBJECT_EXTENDED_LIMIT_INFORMATION = {
  "x86": JOBOBJECT_EXTENDED_LIMIT_INFORMATION_32,
  "x64": JOBOBJECT_EXTENDED_LIMIT_INFORMATION_64,
}[fsGetPythonISA()];

class cJobObject(object):
  def __init__(oSelf, *auProcessIds):
    oSelf.__hJob = KERNEL32.CreateJobObjectW(NULL, NULL);
    oSelf.__hJob \
        or fThrowError("CreateJobObject(NULL, NULL)");
    for uProcessId in auProcessIds:
      # The following method call can only return False when there is an ERROR_ACCESS_DENIED, so report that:
      oSelf.fbAddProcessForId(uProcessId) \
          or fThrowError("AssignProcessToJobObject(..., 0x%08X)" % uProcessId, ERROR_ACCESS_DENIED);
  
  def fbAddProcessForId(oSelf, uProcessId):
    uFlags = PROCESS_SET_QUOTA | PROCESS_TERMINATE;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, 0x%08X)" % (uFlags, uProcessId,));
    try:
      if KERNEL32.AssignProcessToJobObject(oSelf.__hJob, hProcess):
        return True;
      uAssignProcessToJobObjectError = KERNEL32.GetLastError();
      (HRESULT_FROM_WIN32(uAssignProcessToJobObjectError) == ERROR_ACCESS_DENIED) \
          or fThrowError("AssignProcessToJobObject(..., 0x%08X)" % (hProcess.value,), \
          uAssignProcessToJobObjectError);
    finally:
      KERNEL32.CloseHandle(hProcess) \
          or fThrowError("CloseHandle(0x%X)" % (hProcess.value,));
    # We cannot add the process to the job, but maybe it is already added?
    uFlags = PROCESS_QUERY_LIMITED_INFORMATION;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
    hProcess \
        or fThrowError("OpenProcess(0x%08X, FALSE, 0x%08X)" % (uFlags, uProcessId,));
    try:
      bProcessInJob = BOOL();
      KERNEL32.IsProcessInJob(hProcess, oSelf.__hJob, POINTER(bProcessInJob)) \
          or fThrowError("IsProcessInJob(0x%X, ..., ...)" % (hProcess,));
      return bProcessInJob.value == TRUE;
    finally:
      KERNEL32.CloseHandle(hProcess) \
          or fThrowError("CloseHandle(0x%X)" % (hProcess,));
  
  def __foQueryExtendedLimitInformation(oSelf):
    oExtendedLimitInformation = JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
    dwReturnLength = DWORD();
    KERNEL32.QueryInformationJobObject(
      oSelf.__hJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      CAST(LPVOID, POINTER(oExtendedLimitInformation)), # lpJobObjectInfo
      SIZEOF(oExtendedLimitInformation), # cbJobObjectInfoLength,
      POINTER(dwReturnLength), # lpReturnLength
    ) or fThrowError("QueryInformationJobObject(..., 0x%08X, ..., 0x%X, *dwReturnLength=0x%X)" % \
        (JobObjectExtendedLimitInformation, SIZEOF(oExtendedLimitInformation), dwReturnLength.value));
    assert dwReturnLength.value == SIZEOF(oExtendedLimitInformation), \
        "QueryInformationJobObject(..., 0x%08X, ..., 0x%X, ...) => wrote 0x%X bytes" % \
        (JobObjectExtendedLimitInformation, SIZEOF(oExtendedLimitInformation), dwReturnLength.value);
    return oExtendedLimitInformation;
  
  def __fSetExtendedLimitInformation(oSelf, oExtendedLimitInformation):
    KERNEL32.SetInformationJobObject(
      oSelf.__hJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      CAST(LPVOID, POINTER(oExtendedLimitInformation)), # lpJobObjectInfo
      SIZEOF(oExtendedLimitInformation), # cbJobObjectInfoLength,
    ) or fThrowError("SetInformationJobObject(..., JobObjectExtendedLimitInformation, ..., 0x%X)" % \
        (SIZEOF(oExtendedLimitInformation),));
  
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

