from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;
from fsGetErrorMessage import fsGetErrorMessage;

class cJobObject(object):
  def __init__(oSelf, *auProcessIds):
    oSelf.__hJob = KERNEL32.CreateJobObjectW(NULL, NULL);
    assert oSelf.__hJob, \
        fsGetErrorMessage("CreateJobObject(NULL, NULL)");
    for uProcessId in auProcessIds:
      # The following method call can only return False when there is an ERROR_ACCESS_DENIED, so report that:
      assert oSelf.fbAddProcessForId(uProcessId), \
          fsGetErrorMessage("AssignProcessToJobObject(..., 0x%08X)" % uProcessId, ERROR_ACCESS_DENIED);
  
  def fbAddProcessForId(oSelf, uProcessId):
    uFlags = PROCESS_SET_QUOTA | PROCESS_TERMINATE;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
    assert hProcess, \
        fsGetErrorMessage("OpenProcess(0x%08X, FALSE, 0x%08X)" % (uFlags, uProcessId,));
    try:
      if KERNEL32.AssignProcessToJobObject(oSelf.__hJob, hProcess):
        return True;
      uAssignProcessToJobObjectError = KERNEL32.GetLastError();
      assert HRESULT_FROM_WIN32(uAssignProcessToJobObjectError) == ERROR_ACCESS_DENIED, \
          fsGetErrorMessage("AssignProcessToJobObject(..., 0x%08X)" % (hProcess.value,), \
          uAssignProcessToJobObjectError);
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess.value,));
    # We cannot add the process to the job, but maybe it is already added?
    uFlags = PROCESS_QUERY_LIMITED_INFORMATION;
    hProcess = KERNEL32.OpenProcess(uFlags, FALSE, uProcessId);
    assert hProcess, \
        fsGetErrorMessage("OpenProcess(0x%08X, FALSE, 0x%08X)" % (uFlags, uProcessId,));
    try:
      bProcessInJob = BOOL();
      assert KERNEL32.IsProcessInJob(hProcess, oSelf.__hJob, POINTER(bProcessInJob)), \
          fsGetErrorMessage("IsProcessInJob(0x%X, ..., ...)" % (hProcess,));
      return bProcessInJob.value == TRUE;
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          fsGetErrorMessage("CloseHandle(0x%X)" % (hProcess,));
  
  def __foQueryExtendedLimitInformation(oSelf):
    oExtendedLimitInformation = JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
    dwReturnLength = DWORD();
    assert KERNEL32.QueryInformationJobObject(
      oSelf.__hJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      CAST(LPVOID, POINTER(oExtendedLimitInformation)), # lpJobObjectInfo
      SIZEOF(oExtendedLimitInformation), # cbJobObjectInfoLength,
      POINTER(dwReturnLength), # lpReturnLength
    ), fsGetErrorMessage("QueryInformationJobObject(..., 0x%08X, ..., 0x%X, ...)" % \
        (JobObjectExtendedLimitInformation, SIZEOF(oExtendedLimitInformation),));
    assert dwReturnLength.value == SIZEOF(oExtendedLimitInformation), \
        "QueryInformationJobObject(..., 0x%08X, ..., 0x%X, ...) => wrote 0x%X bytes" % \
        (JobObjectExtendedLimitInformation, SIZEOF(oExtendedLimitInformation), dwReturnLength.value);
    return oExtendedLimitInformation;
  
  def __fSetExtendedLimitInformation(oSelf, oExtendedLimitInformation):
    assert KERNEL32.SetInformationJobObject(
      oSelf.__hJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      CAST(LPVOID, POINTER(oExtendedLimitInformation)), # lpJobObjectInfo
      SIZEOF(oExtendedLimitInformation), # cbJobObjectInfoLength,
    ), fsGetErrorMessage("SetInformationJobObject(..., JobObjectExtendedLimitInformation, ..., 0x%X)" % \
        (SIZEOF(oExtendedLimitInformation),));
  
  def fSetMaxProcessMemoryUse(oSelf, uMemoryUseInBytes):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    oExtendedLimitInformation.ProcessMemoryLimit = uMemoryUseInBytes;
    oExtendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    oSelf.__fSetExtendedLimitInformation(oExtendedLimitInformation);

  def fSetMaxTotalMemoryUse(oSelf, uMemoryUseInBytes):
    oExtendedLimitInformation = oSelf.__foQueryExtendedLimitInformation();
    oExtendedLimitInformation.JobMemoryLimit = uMemoryUseInBytes;
    oExtendedLimitInformation.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    oSelf.__fSetExtendedLimitInformation(oExtendedLimitInformation);

