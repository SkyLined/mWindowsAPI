from .cVirtualAllocation import cVirtualAllocation;
from .mDefines import *;
from .mFunctions import SUCCEEDED;
from .mTypes import *;
from .mDLLs import KERNEL32, NTDLL;
from .fbIsThreadRunningForHandle import fbIsThreadRunningForHandle;
from .fbResumeThreadForHandle import fbResumeThreadForHandle;
from .fTerminateThreadForHandle import fTerminateThreadForHandle;
from .fbWaitForThreadTerminationForHandle import fbWaitForThreadTerminationForHandle;
from .fsGetPythonISA import fsGetPythonISA;
from .fSuspendThreadForHandle import fSuspendThreadForHandle;
from .fThrowError import fThrowError;
from .fuGetThreadExitCodeForHandle import fuGetThreadExitCodeForHandle;

gddtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName_by_sISA = {
  "x86": {
    # 8 bit
    "ah":   ("Eax", 8, 8),
    "al":   ("Eax", 8, 0),
    "bh":   ("Ebx", 8, 8),
    "bl":   ("Ebx", 8, 0),
    "ch":   ("Ecx", 8, 8),
    "cl":   ("Ecx", 8, 0),
    "dh":   ("Edx", 8, 8),
    "dl":   ("Edx", 8, 0),
    # 16 bit
    "ax":   ("Eax", 16, 0),
    "bx":   ("Ebx", 16, 0),
    "cx":   ("Ecx", 16, 0),
    "dx":   ("Edx", 16, 0),
    "si":   ("Esi", 16, 0),
    "di":   ("Edi", 16, 0),
    "bp":   ("Ebp", 16, 0),
    "sp":   ("Esp", 16, 0),
    "ip":   ("Eip", 16, 0),
    # 32 bit
    "eax":  ("Eax", 32, 0),
    "ebx":  ("Ebx", 32, 0),
    "ecx":  ("Ecx", 32, 0),
    "edx":  ("Edx", 32, 0),
    "esi":  ("Esi", 32, 0),
    "edi":  ("Edi", 32, 0),
    "ebp":  ("Ebp", 32, 0),
    "esp":  ("Esp", 32, 0),
    "eip":  ("Eip", 32, 0),
  },
  "x64": {
    # 8 bit
    "ah":   ("Rax", 8, 8),
    "al":   ("Rax", 8, 0),
    "bh":   ("Rbx", 8, 8),
    "bl":   ("Rbx", 8, 0),
    "ch":   ("Rcx", 8, 8),
    "cl":   ("Rcx", 8, 0),
    "dh":   ("Rdx", 8, 8),
    "dl":   ("Rdx", 8, 0),
    "sih":  ("Rsi", 8, 8),
    "sil":  ("Rsi", 8, 0),
    "dih":  ("Rdi", 8, 8),
    "dil":  ("Rdi", 8, 0),
    "bph":  ("Rbp", 8, 8),
    "bpl":  ("Rbp", 8, 0),
    "sph":  ("Rsp", 8, 8),
    "spl":  ("Rsp", 8, 0),
    "iph":  ("Rip", 8, 8),
    "ipl":  ("Rip", 8, 0),
    "r8b":  ("R8",  8, 0),
    "r9b":  ("R9",  8, 0),
    "r10b": ("R10", 8, 0),
    "r11b": ("R11", 8, 0),
    "r12b": ("R12", 8, 0),
    "r13b": ("R13", 8, 0),
    "r14b": ("R14", 8, 0),
    "r15b": ("R15", 8, 0),
    # 16 bit
    "ax":   ("Rax", 16, 0),
    "bx":   ("Rbx", 16, 0),
    "cx":   ("Rcx", 16, 0),
    "dx":   ("Rdx", 16, 0),
    "si":   ("Rsi", 16, 0),
    "di":   ("Rdi", 16, 0),
    "bp":   ("Rbp", 16, 0),
    "sp":   ("Rsp", 16, 0),
    "ip":   ("Rip", 16, 0),
    "r8w":  ("R8",  16, 0),
    "r9w":  ("R9",  16, 0),
    "r10w": ("R10", 16, 0),
    "r11w": ("R11", 16, 0),
    "r12w": ("R12", 16, 0),
    "r13w": ("R13", 16, 0),
    "r14w": ("R14", 16, 0),
    "r15w": ("R15", 16, 0),
    # 32 bit
    "eax":  ("Rax", 32, 0),
    "ebx":  ("Rbx", 32, 0),
    "ecx":  ("Rcx", 32, 0),
    "edx":  ("Rdx", 32, 0),
    "esi":  ("Rsi", 32, 0),
    "edi":  ("Rdi", 32, 0),
    "ebp":  ("Rbp", 32, 0),
    "esp":  ("Rsp", 32, 0),
    "eip":  ("Rip", 32, 0),
    "r8d":  ("R8",  32, 0),
    "r9d":  ("R9",  32, 0),
    "r10d": ("R10", 32, 0),
    "r11d": ("R11", 32, 0),
    "r12d": ("R12", 32, 0),
    "r13d": ("R13", 32, 0),
    "r14d": ("R14", 32, 0),
    "r15d": ("R15", 32, 0),
    # 64 bit
    "rax":  ("Rax", 64, 0),
    "rbx":  ("Rbx", 64, 0),
    "rcx":  ("Rcx", 64, 0),
    "rdx":  ("Rdx", 64, 0),
    "rsi":  ("Rsi", 64, 0),
    "rdi":  ("Rdi", 64, 0),
    "rbp":  ("Rbp", 64, 0),
    "rsp":  ("Rsp", 64, 0),
    "rip":  ("Rip", 64, 0),
    "r8":   ("R8",  64, 0),
    "r9":   ("R9",  64, 0),
    "r10":  ("R10", 64, 0),
    "r11":  ("R11", 64, 0),
    "r12":  ("R12", 64, 0),
    "r13":  ("R13", 64, 0),
    "r14":  ("R14", 64, 0),
    "r15":  ("R15", 64, 0),
  },
};

class cThread(object):
  def __init__(oSelf, oProcess, uId):
    oSelf.oProcess = oProcess;
    oSelf.uId = uId;
    oSelf.__dhThread_by_uFlags = {};
    oSelf.__oTEB = None;
    oSelf.__oStackVirtualAllocation = None;
    oSelf.__oThreadContext = None;
  
  def fhOpenWithFlags(oSelf, uRequiredFlags):
    # See if we have an open handle with the required flags, and keep track of all the flags we've used before.
    uExistingFlags = 0;
    for (uFlags, hThread) in oSelf.__dhThread_by_uFlags.items():
      uExistingFlags |= uFlags;
      if uFlags & uRequiredFlags == uRequiredFlags:
        break;
    else:
      # We have no open handle with the required flags, create one with the required flags and all other flags we've
      # used before. This makes sense because we already have that access and by combining the flags we increase the
      # change of having a handle that matches the required flags during the next call to this function.
      oSelf.__dhThread_by_uFlags = {};
      uFlags = uExistingFlags | uRequiredFlags;
      hThread = KERNEL32.OpenThread(uFlags, FALSE, oSelf.uId);
      hThread \
          or fThrowError("OpenThread(0x%X, FALSE, 0x%X)" % (uRequiredFlags, oSelf.uId,));
      oSelf.__dhThread_by_uFlags[uFlags] = hThread;
    return hThread;
  
  @property
  def oTEB(oSelf):
    if oSelf.__oTEB is None:
      # The type of THREAD_BASIC_INFORMATION returned by NtQueryInformationThread depends on the ISA of the calling
      # process (the Python process we're running in):
      cThreadBasicInformation = {"x86": THREAD_BASIC_INFORMATION_32, "x64": THREAD_BASIC_INFORMATION_64}[fsGetPythonISA()];
      oThreadBasicInformation = cThreadBasicInformation();
      uReturnLength = ULONG();
      hThread = oSelf.fhOpenWithFlags(THREAD_QUERY_INFORMATION);
      uNTStatus = NTDLL.NtQueryInformationThread(
        hThread,# ThreadHandle
        ThreadBasicInformation, # ThreadInformationClass
        CAST(PVOID, POINTER(oThreadBasicInformation)), # ThreadInformation
        SIZEOF(oThreadBasicInformation), # ThreadInformationLength
        POINTER(uReturnLength), # ReturnLength
      );
      SUCCEEDED(uNTStatus) \
          or fThrowError("NtQueryInformationThread(0x%X, 0x%X, ..., 0x%X, ...)" % \
              (hThread, ThreadBasicInformation, SIZEOF(oThreadBasicInformation)), uNTStatus);
      assert uReturnLength.value == SIZEOF(oThreadBasicInformation), \
          "NtQueryInformationThread(0x%X, 0x%08X, ..., 0x%X, ...) wrote 0x%X bytes" % \
          (hThread, ThreadBasicInformation, SIZEOF(oThreadBasicInformation), uReturnLength.value);
      # Read TEB
      uTEBAddress = oThreadBasicInformation.TebBaseAddress;
      # The type of TEB (32- or 64-bit) depends on the type of THREAD_BASIC_INFORMATION (see above)
      cTEB = {"x86": TEB_32, "x64": TEB_64}[fsGetPythonISA()];
      oVirtualAllocation = oSelf.oProcess.foGetAllocatedVirtualAllocationWithSizeCheck(uTEBAddress, SIZEOF(cTEB), "TEB");
      oSelf.__oTEB = oVirtualAllocation.foReadStructureForOffset(
        cStructure = cTEB,
        uOffset = uTEBAddress - oVirtualAllocation.uStartAddress,
      );
    return oSelf.__oTEB;
  
  def __del__(oSelf):
    try:
      oSelf.__dhThread_by_uFlags;
    except AttributeError:
      return;
    for hThread in oSelf.__dhThread_by_uFlags.values():
      KERNEL32.CloseHandle(hThread) \
          or fThrowError("CloseHandle(0x%X)" % (hThread,));
  
  @property
  def bIsRunning(oSelf):
    return fbIsThreadRunningForHandle(oSelf.fhOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION));
  
  def fTerminate(oSelf, uTimeout = None):
    return fTerminateThreadForHandle(oSelf.fhOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION), uTimeout);
  
  def fSuspend(oSelf):
    return fSuspendThreadForHandle(oSelf.fhOpenWithFlags(THREAD_SUSPEND_RESUME));
  
  def fbResume(oSelf):
    return fbResumeThreadForHandle(oSelf.fhOpenWithFlags(THREAD_SUSPEND_RESUME));
  
  def fbWait(oSelf, uTimeout = None):
    return fbWaitForThreadTerminationForHandle(oSelf.fhOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION), uTimeout);
  
  @property
  def uExitCode(oSelf):
    return fuGetThreadExitCodeForHandle(oSelf.fhOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION));
  
  @property
  def uStackBottomAddress(oSelf):
    return oSelf.oTEB.NtTib.StackBase;
  
  @property
  def uStackTopAddress(oSelf):
    return oSelf.oTEB.NtTib.StackLimit;
  
  @property
  def oStackVirtualAllocation(oSelf):
    if oSelf.__oStackVirtualAllocation is None:
      oSelf.__oStackVirtualAllocation = cVirtualAllocation(oSelf.oProcess.uId, oSelf.uStackBottomAddress);
    return oSelf.__oStackVirtualAllocation;
  
  def __foGetThreadContext(oSelf):
    # The type of CONTEXT returned by GetThreadContext depends on the ISA of the calling process (the Python process
    # we're running in):
    cThreadContext = {"x86": CONTEXT_32, "x64": CONTEXT_64}[fsGetPythonISA()];
    oThreadContext = cThreadContext();
    hThread = oSelf.fhOpenWithFlags(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION);
    oThreadContext.ContextFlags = CONTEXT_ALL;
    KERNEL32.GetThreadContext(
      hThread, # hThread
      POINTER(oThreadContext), # lpContext
    ) \
        or fThrowError("GetThreadContext(0x%08X, ...)" % (hThread,));
    return oThreadContext;
  
  def fduGetRegisterValueByName(oSelf):
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName = \
        gddtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName_by_sISA[oSelf.oProcess.sISA];
    duRegisterValues_by_sName = {};
    oThreadContext = oSelf.__foGetThreadContext();
    for (sRegisterName, (sThreadContextStructMemberName, uBitSize, uBitOffset)) in \
        dtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName.items():
      uRegisterValue = (getattr(oThreadContext, sThreadContextStructMemberName) >> uBitOffset) & ((1 << uBitSize) - 1);
      duRegisterValues_by_sName[sRegisterName] = uRegisterValue;
    return duRegisterValues_by_sName;
  
  def fuGetRegister(oSelf, sRegisterName):
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName = \
        gddtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName_by_sISA[oSelf.oProcess.sISA];
    assert sRegisterName in dtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName, \
        "Register %s is not available in the context of %s process %d" % (sRegisterName, oSelf.oProcess.sISA, oSelf.oProcess.uId);
    (sThreadContextStructMemberName, uBitSize, uBitOffset) = \
        dtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName[sRegisterName];
    return (getattr(oSelf.__foGetThreadContext(), sThreadContextStructMemberName) >> uBitOffset) & ((1 << uBitSize) - 1);
  
  def fSetRegister(oSelf, sRegisterName, uRegisterValue):
    return oSelf.fSetRegisters({sRegisterName: uRegisterValue});
  
  def fSetRegisters(oSelf, duRegisterValue_by_sName):
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName = \
        gddtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName_by_sISA[oSelf.oProcess.sISA];
    oThreadContext = oSelf.__foGetThreadContext();
    for (sRegisterName, uRegisterValue) in duRegisterValue_by_sName.items():
      assert sRegisterName in dtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName, \
          "Register %s is not available in the context of %s process %d" % (sRegisterName, oSelf.oProcess.sISA, oSelf.oProcess.uId);
      (sThreadContextStructMemberName, uBitSize, uBitOffset) = \
          dtxThreadContextStructMemberNameBitSizeAndOffset_by_sRegisterName[sRegisterName];
      assert uRegisterValue & ((1 << uBitSize) - 1) == uRegisterValue, \
          "value 0x%X cannot be stored in %d bit" % (uRegisterValue, uBitSize);
      uContextStructMemberValue = getattr(oThreadContext, sThreadContextStructMemberName);
      uCurrentValueInStructMember = uContextStructMemberValue & (((1 << uBitSize) - 1) << uBitOffset);
      uNewValueInStructMember = uRegisterValue << uBitOffset;
      # Subtract the current value and add the new value:
      uContextStructMemberValue = uContextStructMemberValue - uCurrentValueInStructMember + uNewValueInStructMember;
      setattr(oThreadContext, sThreadContextStructMemberName, uContextStructMemberValue);
    hThread = oSelf.fhOpenWithFlags(THREAD_SET_CONTEXT);
    KERNEL32.SetThreadContext(
        hThread,# hThread
        POINTER(oThreadContext), # lpContext
    ) \
        or fThrowError("SetThreadContext(0x%08X, ...)" % (hThread,));
   