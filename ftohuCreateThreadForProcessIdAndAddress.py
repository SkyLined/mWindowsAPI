from mWindowsSDK import *;
from mWindowsSDK.mKernel32 import oKernel32DLL;
from .fbIsValidHandle import fbIsValidHandle;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def ftohuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, uParameterAddress = 0, bSuspended = False):
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
  bSuccess = False;
  try:
    odwThreadId = DWORD();
    odwCreationFlags = DWORD(CREATE_SUSPENDED if bSuspended else 0);
    ohThread = oKernel32DLL.CreateRemoteThread(
      ohProcess,
      NULL, # lpThreadAttributes
      0,  # dwStackSize
      LPTHREAD_START_ROUTINE(uAddress), # lpStartAddress
      LPVOID(uParameterAddress), # lpParameter
      odwCreationFlags, # dwCreationFlags
      odwThreadId.foCreatePointer(), # lpThreadId
    );
    if not fbIsValidHandle(ohThread):
      fThrowLastError("CreateRemoteThread(%s, NULL, 0, 0x%08X, 0x%08X, %s, 0x%X)" % \
          (repr(ohProcess), uAddress, uParameterAddress or 0, repr(odwCreationFlags), odwThreadId.fuGetAddress()));
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32DLL.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(%s)" % (repr(ohProcess),));
  return (ohThread, odwThreadId.fuGetValue());
