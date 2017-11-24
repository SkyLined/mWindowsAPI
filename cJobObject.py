from mDefines import *;
from mFunctions import *;
from mTypes import *;
from mDLLs import KERNEL32;

class cJobObject(object):
  def __init__(oSelf, *auProcessIds):
    oSelf.__hJob = KERNEL32.CreateJobObjectA(NULL, NULL);
    assert oSelf.__hJob, \
        "CreateJobObject(NULL, NULL) => 0x%08X" % KERNEL32.GetLastError();
    for uProcessId in auProcessIds:
      # This method can only return false when there is only one error, so report that:
      assert oSelf.fbAddProcessForId(uProcessId), \
          "AssignProcessToJobObject(..., 0x%08X) => ERROR_ACCESS_DENIED" % uProcessId;
  
  def fbAddProcessForId(oSelf, uProcessId):
    hProcess = KERNEL32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, uProcessId);
    assert hProcess, \
        "OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, 0x%08X) => Error 0x%08X" % (uProcessId, KERNEL32.GetLastError());
    try:
      if KERNEL32.AssignProcessToJobObject(oSelf.__hJob, hProcess):
        return True;
      assert KERNEL32.GetLastError() == WIN32_FROM_HRESULT(ERROR_ACCESS_DENIED), \
        "AssignProcessToJobObject(..., 0x%08X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
    # We cannot add the process to the job, but maybe it is already added?
    hProcess = KERNEL32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, uProcessId);
    assert hProcess, \
        "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0x%08X) => Error 0x%08X" % (uProcessId, KERNEL32.GetLastError());
    try:
      bProcessInJob = BOOL();
      assert KERNEL32.IsProcessInJob(hProcess, oSelf.__hJob, POINTER(bProcessInJob)), \
          "IsProcessInJob(0x%X, ..., ...) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
      return bProcessInJob.value == TRUE;
    finally:
      assert KERNEL32.CloseHandle(hProcess), \
          "CloseHandle(0x%X) => Error 0x%08X" % (hProcess, KERNEL32.GetLastError());
  
  def __foQueryExtendedLimitInformation(oSelf):
    oExtendedLimitInformation = JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
    dwReturnLength = DWORD();
    assert KERNEL32.QueryInformationJobObject(
      oSelf.__hJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      CAST(LPVOID, POINTER(oExtendedLimitInformation)), # lpJobObjectInfo
      SIZEOF(oExtendedLimitInformation), # cbJobObjectInfoLength,
      POINTER(dwReturnLength), # lpReturnLength
    ), "QueryInformationJobObject(..., JobObjectExtendedLimitInformation, ..., 0x%X, ...) => 0x%08X" % \
        (SIZEOF(oExtendedLimitInformation), KERNEL32.GetLastError());
    assert dwReturnLength.value == SIZEOF(oExtendedLimitInformation), \
        "QueryInformationJobObject(..., JobObjectExtendedLimitInformation, ..., 0x%X, ...) set 0x%X bytes in structure" % \
        (SIZEOF(oExtendedLimitInformation), dwReturnLength.value);
    return oExtendedLimitInformation;
  
  def __fSetExtendedLimitInformation(oSelf, oExtendedLimitInformation):
    assert KERNEL32.SetInformationJobObject(
      oSelf.__hJob, # hJob
      JobObjectExtendedLimitInformation, # JobObjectInfoClass
      CAST(LPVOID, POINTER(oExtendedLimitInformation)), # lpJobObjectInfo
      SIZEOF(oExtendedLimitInformation), # cbJobObjectInfoLength,
    ), "SetInformationJobObject(..., JobObjectExtendedLimitInformation, ..., 0x%X) => 0x%08X" % \
        (SIZEOF(oExtendedLimitInformation), KERNEL32.GetLastError().value);
  
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

