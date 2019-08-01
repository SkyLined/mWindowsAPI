from mWindowsSDK import *;
from .fbIsValidHandle import fbIsValidHandle;
from .fohOpenForProcessIdAndDesiredAccess import fohOpenForProcessIdAndDesiredAccess;
from .fThrowLastError import fThrowLastError;

def ftohuCreateThreadForProcessIdAndAddress(uProcessId, uAddress, uParameterAddress = 0, bSuspended = False):
  ohProcess = fohOpenForProcessIdAndDesiredAccess(uProcessId, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
  bSuccess = False;
  oKernel32 = foLoadKernel32DLL();
  try:
    odwThreadId = DWORD();
    odwCreationFlags = DWORD(CREATE_SUSPENDED if bSuspended else 0);
    ohThread = oKernel32.CreateRemoteThread(
      ohProcess,
      NULL, # lpThreadAttributes
      0,  # dwStackSize
      LPTHREAD_START_ROUTINE(uAddress), # lpStartAddress
      LPVOID(uParameterAddress), # lpParameter
      odwCreationFlags, # dwCreationFlags
      odwThreadId.foCreatePointer(), # lpThreadId
    );
    if not fbIsValidHandle(ohThread):
      fThrowLastError("CreateRemoteThread(0x%08X, NULL, 0, 0x%08X, 0x%08X, 0x%08X, 0x%X)" % \
          (ohProcess.value, uAddress, uParameterAddress or 0, odwCreationFlags.value, odwThreadId.fuGetAddress()));
    bSuccess = True;
  finally:
    # Only throw an exception if one isn't already being thrown:
    if not oKernel32.CloseHandle(ohProcess) and bSuccess:
      fThrowLastError("CloseHandle(0x%X)" % (ohProcess.value,));
  return (ohThread, odwThreadId.value);
