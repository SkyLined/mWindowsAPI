from .fhOpenForProcessIdAndDesiredAccess import fhOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;
from .mDefines import *;
from .mDLLs import KERNEL32;
from .mFunctions import *;
from .mTypes import *;

def fthuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, uParameterAddress = None, bSuspended = False):
  hProcess = fhOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
  bSuccess = False;
  try:
    uThreadId = DWORD();
    dwCreationFlags = DWORD(CREATE_SUSPENDED if bSuspended else 0);
    hThread = KERNEL32.CreateRemoteThread(
      hProcess,
      NULL, # lpThreadAttributes
      0,  # dwStackSize
      fxCast(LPTHREAD_START_ROUTINE, uAddress), # lpStartAddress
      fxCast(LPVOID, uParameterAddress), # lpParameter
      dwCreationFlags, # dwCreationFlags
      POINTER(uThreadId), # lpThreadId
    );
    if not fbIsValidHandle(hThread):
      fThrowLastError("CreateRemoteThread(0x%08X, NULL, 0, 0x%08X, 0x%08X, 0x%08X, 0x%X)" % \
          (hProcess.value, uAddress, uParameterAddress or 0, dwCreationFlags.value, fuAddressOf(uThreadId)));
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not KERNEL32.CloseHandle(hProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (hProcess.value,));
  return (hThread, uThreadId.value);
