import re;
from mWindowsSDK import \
  CONTEXT_ALL, CONTEXT32, CONTEXT64, \
  ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE, ERROR_INVALID_HANDLE, \
  foLoadNTDLL, \
  HANDLE, \
  iIntegerBaseType, INVALID_HANDLE_VALUE, \
  M128A, \
  NT_SUCCESS, \
  PVOID, \
  SYNCHRONIZE, \
  TEB32, TEB64, \
  ThreadBasicInformation, THREAD_BASIC_INFORMATION32, THREAD_BASIC_INFORMATION64, \
  THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, \
  THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, THREAD_TERMINATE, \
  ULONG;
from mWindowsSDK.mKernel32 import oKernel32DLL;

from .cVirtualAllocation import cVirtualAllocation;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fbResumeForThreadHandle import fbResumeForThreadHandle;
from .fbTerminateForThreadHandle import fbTerminateForThreadHandle;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .foh0OpenForThreadIdAndDesiredAccess import foh0OpenForThreadIdAndDesiredAccess;
from .fsGetDescriptionForThreadHandle import fsGetDescriptionForThreadHandle;
from .fsGetPythonISA import fsGetPythonISA;
from .fsGetThreadAccessRightsFlagsDescription import fsGetThreadAccessRightsFlagsDescription;
from .fbIsValidHandle import fbIsValidHandle;
from .fbLastErrorIs import fbLastErrorIs;
from .fbSuspendForThreadHandle import fbSuspendForThreadHandle;
from .fThrowLastError import fThrowLastError;
from .fThrowNTStatusError import fThrowNTStatusError;
from .fuGetExitCodeForThreadHandle import fuGetExitCodeForThreadHandle;

gsbInstructionPointerRegisterName_by_sISA = {
  "x86": b"eip",
  "x64": b"rip",
}
gsbStackPointerRegisterName_by_sISA = {
  "x86": b"esp",
  "x64": b"rsp",
}

gddtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName_by_sISA = {
  "x86": {
    # 8 bit
    b"ah":   ("Eax", 8, 8),
    b"al":   ("Eax", 8, 0),
    b"bh":   ("Ebx", 8, 8),
    b"bl":   ("Ebx", 8, 0),
    b"ch":   ("Ecx", 8, 8),
    b"cl":   ("Ecx", 8, 0),
    b"dh":   ("Edx", 8, 8),
    b"dl":   ("Edx", 8, 0),
    # 16 bit
    b"ax":   ("Eax", 16, 0),
    b"bx":   ("Ebx", 16, 0),
    b"cx":   ("Ecx", 16, 0),
    b"dx":   ("Edx", 16, 0),
    b"si":   ("Esi", 16, 0),
    b"di":   ("Edi", 16, 0),
    b"bp":   ("Ebp", 16, 0),
    b"sp":   ("Esp", 16, 0),
    b"ip":   ("Eip", 16, 0),
    # 32 bit
    b"eax":  ("Eax", 32, 0),
    b"ebx":  ("Ebx", 32, 0),
    b"ecx":  ("Ecx", 32, 0),
    b"edx":  ("Edx", 32, 0),
    b"esi":  ("Esi", 32, 0),
    b"edi":  ("Edi", 32, 0),
    b"ebp":  ("Ebp", 32, 0),
    b"esp":  ("Esp", 32, 0),
    b"eip":  ("Eip", 32, 0),
    b"*sp":  ("Esp", 32, 0),
    b"*ip":  ("Eip", 32, 0),
    # 64 bit
    b"mm0":  ("FloatSave.RegisterArea", 80, 0*80),
    b"mm1":  ("FloatSave.RegisterArea", 80, 1*80),
    b"mm2":  ("FloatSave.RegisterArea", 80, 2*80),
    b"mm3":  ("FloatSave.RegisterArea", 80, 3*80),
    b"mm4":  ("FloatSave.RegisterArea", 80, 4*80),
    b"mm5":  ("FloatSave.RegisterArea", 80, 5*80),
    b"mm6":  ("FloatSave.RegisterArea", 80, 6*80),
    b"mm7":  ("FloatSave.RegisterArea", 80, 7*80),
    # 80 bit floats
# Python has no support for 80 bit floats, so implementing this is going to be quite a lot of work.
#    "st0":  ("FloatSave.RegisterArea", 80, 0*80),
#    "st1":  ("FloatSave.RegisterArea", 80, 1*80),
#    "st2":  ("FloatSave.RegisterArea", 80, 2*80),
#    "st3":  ("FloatSave.RegisterArea", 80, 3*80),
#    "st4":  ("FloatSave.RegisterArea", 80, 4*80),
#    "st5":  ("FloatSave.RegisterArea", 80, 5*80),
#    "st6":  ("FloatSave.RegisterArea", 80, 6*80),
#    "st7":  ("FloatSave.RegisterArea", 80, 7*80),
    # 128 bit
    b"xmm0": ("ExtendedRegisters", 128, 0*128 + 0x500),
    b"xmm1": ("ExtendedRegisters", 128, 1*128 + 0x500),
    b"xmm2": ("ExtendedRegisters", 128, 2*128 + 0x500),
    b"xmm3": ("ExtendedRegisters", 128, 3*128 + 0x500),
    b"xmm4": ("ExtendedRegisters", 128, 4*128 + 0x500),
    b"xmm5": ("ExtendedRegisters", 128, 5*128 + 0x500),
    b"xmm6": ("ExtendedRegisters", 128, 6*128 + 0x500),
    b"xmm7": ("ExtendedRegisters", 128, 7*128 + 0x500),
    # Flags
    b"cf":   ("Eflags", 1, 0),
    b"pf":   ("Eflags", 1, 2),
    b"af":   ("Eflags", 1, 4),
    b"zf":   ("Eflags", 1, 6),
    b"sf":   ("Eflags", 1, 7),
    b"tf":   ("Eflags", 1, 8),
    b"if":   ("Eflags", 1, 9),
    b"df":   ("Eflags", 1, 10),
    b"of":   ("Eflags", 1, 11),
    b"iopl": ("Eflags", 2, 12),
    b"nt":   ("Eflags", 1, 14),
    b"rf":   ("Eflags", 1, 16),
    b"vm":   ("Eflags", 1, 17),
    b"ac":   ("Eflags", 1, 18),
    b"vif":  ("Eflags", 1, 19),
    b"vip":  ("Eflags", 1, 20),
    b"id":   ("Eflags", 1, 21),
  },
  "x64": {
    # 8 bit
    b"ah":   ("Rax", 8, 8),
    b"al":   ("Rax", 8, 0),
    b"bh":   ("Rbx", 8, 8),
    b"bl":   ("Rbx", 8, 0),
    b"ch":   ("Rcx", 8, 8),
    b"cl":   ("Rcx", 8, 0),
    b"dh":   ("Rdx", 8, 8),
    b"dl":   ("Rdx", 8, 0),
    b"sih":  ("Rsi", 8, 8),
    b"sil":  ("Rsi", 8, 0),
    b"dih":  ("Rdi", 8, 8),
    b"dil":  ("Rdi", 8, 0),
    b"bph":  ("Rbp", 8, 8),
    b"bpl":  ("Rbp", 8, 0),
    b"sph":  ("Rsp", 8, 8),
    b"spl":  ("Rsp", 8, 0),
    b"iph":  ("Rip", 8, 8),
    b"ipl":  ("Rip", 8, 0),
    b"r8b":  ("R8",  8, 0),
    b"r9b":  ("R9",  8, 0),
    b"r10b": ("R10", 8, 0),
    b"r11b": ("R11", 8, 0),
    b"r12b": ("R12", 8, 0),
    b"r13b": ("R13", 8, 0),
    b"r14b": ("R14", 8, 0),
    b"r15b": ("R15", 8, 0),
    # 16 bit
    b"ax":   ("Rax", 16, 0),
    b"bx":   ("Rbx", 16, 0),
    b"cx":   ("Rcx", 16, 0),
    b"dx":   ("Rdx", 16, 0),
    b"si":   ("Rsi", 16, 0),
    b"di":   ("Rdi", 16, 0),
    b"bp":   ("Rbp", 16, 0),
    b"sp":   ("Rsp", 16, 0),
    b"ip":   ("Rip", 16, 0),
    b"r8w":  ("R8",  16, 0),
    b"r9w":  ("R9",  16, 0),
    b"r10w": ("R10", 16, 0),
    b"r11w": ("R11", 16, 0),
    b"r12w": ("R12", 16, 0),
    b"r13w": ("R13", 16, 0),
    b"r14w": ("R14", 16, 0),
    b"r15w": ("R15", 16, 0),
    # 32 bit
    b"eax":  ("Rax", 32, 0),
    b"ebx":  ("Rbx", 32, 0),
    b"ecx":  ("Rcx", 32, 0),
    b"edx":  ("Rdx", 32, 0),
    b"esi":  ("Rsi", 32, 0),
    b"edi":  ("Rdi", 32, 0),
    b"ebp":  ("Rbp", 32, 0),
    b"esp":  ("Rsp", 32, 0),
    b"eip":  ("Rip", 32, 0),
    b"r8d":  ("R8",  32, 0),
    b"r9d":  ("R9",  32, 0),
    b"r10d": ("R10", 32, 0),
    b"r11d": ("R11", 32, 0),
    b"r12d": ("R12", 32, 0),
    b"r13d": ("R13", 32, 0),
    b"r14d": ("R14", 32, 0),
    b"r15d": ("R15", 32, 0),
    # 64 bit
    b"rax":  ("Rax", 64, 0),
    b"rbx":  ("Rbx", 64, 0),
    b"rcx":  ("Rcx", 64, 0),
    b"rdx":  ("Rdx", 64, 0),
    b"rsi":  ("Rsi", 64, 0),
    b"rdi":  ("Rdi", 64, 0),
    b"rbp":  ("Rbp", 64, 0),
    b"rsp":  ("Rsp", 64, 0),
    b"rip":  ("Rip", 64, 0),
    b"*sp":  ("Rsp", 64, 0),
    b"*ip":  ("Rip", 64, 0),
    b"r8":   ("R8",  64, 0),
    b"r9":   ("R9",  64, 0),
    b"r10":  ("R10", 64, 0),
    b"r11":  ("R11", 64, 0),
    b"r12":  ("R12", 64, 0),
    b"r13":  ("R13", 64, 0),
    b"r14":  ("R14", 64, 0),
    b"r15":  ("R15", 64, 0),
    b"mm0":  ("FltSave.FloatRegisters[0]", 64, 0),
    b"mm1":  ("FltSave.FloatRegisters[1]", 64, 0),
    b"mm2":  ("FltSave.FloatRegisters[2]", 64, 0),
    b"mm3":  ("FltSave.FloatRegisters[3]", 64, 0),
    b"mm4":  ("FltSave.FloatRegisters[4]", 64, 0),
    b"mm5":  ("FltSave.FloatRegisters[5]", 64, 0),
    b"mm6":  ("FltSave.FloatRegisters[6]", 64, 0),
    b"mm7":  ("FltSave.FloatRegisters[7]", 64, 0),
    # 80 bit
# Pybthon has no support for 80 bit floats, so implementing this is going to be quite a lot of work.
#    "st0":  ("FltSave.FloatRegisters[0]", 80, 0),
#    "st1":  ("FltSave.FloatRegisters[1]", 80, 0),
#    "st2":  ("FltSave.FloatRegisters[2]", 80, 0),
#    "st3":  ("FltSave.FloatRegisters[3]", 80, 0),
#    "st4":  ("FltSave.FloatRegisters[4]", 80, 0),
#    "st5":  ("FltSave.FloatRegisters[5]", 80, 0),
#    "st6":  ("FltSave.FloatRegisters[6]", 80, 0),
#    "st7":  ("FltSave.FloatRegisters[7]", 80, 0),
    # 128 bit
    b"xmm0": ("Xmm0", 128, 0),
    b"xmm1": ("Xmm1", 128, 0),
    b"xmm2": ("Xmm2", 128, 0),
    b"xmm3": ("Xmm3", 128, 0),
    b"xmm4": ("Xmm4", 128, 0),
    b"xmm5": ("Xmm5", 128, 0),
    b"xmm6": ("Xmm6", 128, 0),
    b"xmm7": ("Xmm7", 128, 0),
    b"xmm8": ("Xmm8", 128, 0),
    b"xmm9": ("Xmm9", 128, 0),
    b"xmm10": ("Xmm10", 128, 0),
    b"xmm11": ("Xmm11", 128, 0),
    b"xmm12": ("Xmm12", 128, 0),
    b"xmm13": ("Xmm13", 128, 0),
    b"xmm14": ("Xmm14", 128, 0),
    b"xmm15": ("Xmm15", 128, 0),
    # Flags
    b"cf":   ("EFlags", 1, 0),
    b"pf":   ("EFlags", 1, 2),
    b"af":   ("EFlags", 1, 4),
    b"zf":   ("EFlags", 1, 6),
    b"sf":   ("EFlags", 1, 7),
    b"tf":   ("EFlags", 1, 8),
    b"if":   ("EFlags", 1, 9),
    b"df":   ("EFlags", 1, 10),
    b"of":   ("EFlags", 1, 11),
    b"iopl": ("EFlags", 2, 12),
    b"nt":   ("EFlags", 1, 14),
    b"rf":   ("EFlags", 1, 16),
    b"vm":   ("EFlags", 1, 17),
    b"ac":   ("EFlags", 1, 18),
    b"vif":  ("EFlags", 1, 19),
    b"vip":  ("EFlags", 1, 20),
    b"id":   ("EFlags", 1, 21),
  },
};

class cThread(object):
  def __init__(oSelf, oProcess, uId, oh0Thread = None, u0ThreadHandleFlags = None):
    oSelf.oProcess = oProcess;
    assert isinstance(uId, int), \
        "uId must be an integer not %s" % repr(uId);
    oSelf.uId = uId;
    if oh0Thread is not None:
      assert isinstance(oh0Thread, HANDLE) and oh0Thread != INVALID_HANDLE_VALUE, \
          "oh0Thread (%s) is not a valid handle" % repr(oh0Thread);
      assert u0ThreadHandleFlags is not None, \
          "You must provide u0ThreadHandleFlags when you provide oh0Thread";
      assert isinstance(u0ThreadHandleFlags, int), \
          "u0ThreadHandleFlags (%s) is not a valid integer" % repr(u0ThreadHandleFlags);
      uThreadHandleFlags = u0ThreadHandleFlags;
    else:
      assert not u0ThreadHandleFlags, \
          "oh0Thread is None but u0ThreadHandleFlags (%s) is not None" % repr(u0ThreadHandleFlags);
      uThreadHandleFlags = 0;
    oSelf.__oh0Thread = oh0Thread;
    oSelf.__uThreadHandleFlags = uThreadHandleFlags;
    oSelf.__o0TEB = None;
    oSelf.__u0TEBAddress = None;
    oSelf.__o0StackVirtualAllocation = None;
  
  def fohOpenWithFlagsOrThrowError(oSelf, uRequiredFlags):
    return oSelf.foh0OpenWithFlags(uRequiredFlags, bMustExist = True, bMustGetAccess = True);
  def foh0OpenWithFlags(oSelf, uRequiredFlags, bMustExist = True, bMustGetAccess = True):
    assert uRequiredFlags, \
        "Cannot open without any flags!";
    # See if we have an open handle
    if oSelf.__oh0Thread:
      # if it already has the required flags, return it:
      if oSelf.__uThreadHandleFlags & uRequiredFlags == uRequiredFlags:
        return oSelf.__oh0Thread;
    # Open a new handle with the required flags and all other flags we've used before.
    # This allows the new handle to be used for anything it was used for before as well
    # as anything new the caller wants to do:
    uFlags = oSelf.__uThreadHandleFlags | uRequiredFlags;
    oh0Thread = foh0OpenForThreadIdAndDesiredAccess(oSelf.uId, uFlags, bMustExist = bMustExist, bMustGetAccess = bMustGetAccess);
    if oh0Thread is None or not fbIsValidHandle(oh0Thread):
      return oh0Thread;
    ohThread = oh0Thread;
    # We have a new HANDLE with more access rights; close the old one if we have it and replace
    # it with the new handle.
    if oSelf.__oh0Thread:
      if not oKernel32DLL.CloseHandle(oSelf.__oh0Thread):
        fThrowLastError("CloseHandle(%s)" % (repr(oSelf.__oh0Thread),));
    oSelf.__oh0Thread = ohThread;
    oSelf.__uThreadHandleFlags = uFlags;
    return oSelf.__oh0Thread;
  
  def fs0GetAccessRightsFlagsDescription(oSelf):
    return fsGetThreadAccessRightsFlagsDescription(oSelf.__uThreadHandleFlags) \
        if oSelf.__oh0Thread is not None else None;
  
  def __del__(oSelf):
    try:
      oh0Thread = oSelf.__oh0Thread;
    except AttributeError:
      return;
    if oh0Thread:
      if not oKernel32DLL.CloseHandle(oh0Thread) and not fbLastErrorIs(ERROR_INVALID_HANDLE):
        fThrowLastError("CloseHandle(%s)" % (repr(oh0Thread),));
  
  @property
  def bIsRunning(oSelf):
    # If the thread does not exist, opening it will return None => return False
    oh0Thread = oSelf.foh0OpenWithFlags(SYNCHRONIZE, bMustExist = False, bMustGetAccess = True);
    if oh0Thread is None:
      return False;
    return fbIsRunningForThreadHandle(oh0Thread);
  
  @property
  def bIsTerminated(oSelf):
    return not oSelf.bIsRunning;
  
  def fbTerminate(oSelf, uTimeout = None):
    # Try to terminate the thread. Return True if the thread is terminated.
    # Return False if the thread is still running.
    # If the thread does not exist, opening it will return None => return False
    oh0Thread = oSelf.foh0OpenWithFlags(SYNCHRONIZE | THREAD_TERMINATE, bMustExist = False, bMustGetAccess = True);
    if oh0Thread is None:
      return False;
    return fbTerminateForThreadHandle(oh0Thread, uTimeout);
  
  def fbSuspend(oSelf): # Returns true if the thread was running but is now suspended.
    return fbSuspendForThreadHandle(oSelf.fohOpenWithFlagsOrThrowError(THREAD_SUSPEND_RESUME));
  
  def fbResume(oSelf): # Returns true if the thread was suspended but is now running.
    return fbResumeForThreadHandle(oSelf.fohOpenWithFlagsOrThrowError(THREAD_SUSPEND_RESUME));
  
  def fbWait(oSelf, uTimeout = None):
    # Wait for thread to terminate if it is runnning. Return True if the thread is terminated.
    oh0Thread = oSelf.foh0OpenWithFlags(SYNCHRONIZE, bMustExist = False, bMustGetAccess = True);
    if oh0Thread is None:
      return False;
    return fbWaitForTerminationForThreadHandle(oh0Thread, uTimeout);
  
  @property
  def uExitCode(oSelf):
    return fuGetExitCodeForThreadHandle(oSelf.fohOpenWithFlagsOrThrowError(THREAD_QUERY_LIMITED_INFORMATION));
  
  @property
  def sDescription(oSelf):
    return fsGetDescriptionForThreadHandle(oSelf.fohOpenWithFlagsOrThrowError(THREAD_QUERY_LIMITED_INFORMATION));
  
  def fo0GetTEB(oSelf):
    # Get TEB without caching
    oSelf.__o0TEB = None;
    oSelf.__u0TEBAddress = None;
    return oSelf.o0TEB;
  @property
  def o0TEB(oSelf):
    # Get TEB with caching
    if oSelf.__o0TEB is None:
      oh0Thread = oSelf.foh0OpenWithFlags(THREAD_QUERY_INFORMATION, bMustExist = False, bMustGetAccess = False);
      if oh0Thread is None or not fbIsValidHandle(oh0Thread):
        return None; # If the thread does not exists or is not accessible, return None
      ohThread = oh0Thread;
      # The type of THREAD_BASIC_INFORMATION returned by NtQueryInformationThread depends on the ISA of the calling
      # process (the Python process we're running in):
      cThreadBasicInformation = {"x86": THREAD_BASIC_INFORMATION32, "x64": THREAD_BASIC_INFORMATION64}[fsGetPythonISA()];
      oThreadBasicInformation = cThreadBasicInformation();
      opThreadBasicInformation = PVOID(oThreadBasicInformation, bCast = True);
      ouReturnLength = ULONG();
      opReturnLength = ouReturnLength.foCreatePointer();
      oNTDLL = foLoadNTDLL();
      oNTStatus = oNTDLL.NtQueryInformationThread(
        ohThread,# ThreadHandle
        ThreadBasicInformation, # ThreadInformationClass
        opThreadBasicInformation, # ThreadInformation
        oThreadBasicInformation.fuGetSize(), # ThreadInformationLength
        opReturnLength, # ReturnLength
      );
      if not NT_SUCCESS(oNTStatus):
        fThrowNTStatusError(
          "NtQueryInformationThread(%s (%s), 0x%X, %s, 0x%X, %s)" % (
            repr(ohThread), oSelf.fs0GetAccessRightsFlagsDescription(),
            ThreadBasicInformation,
            repr(opThreadBasicInformation),
            oThreadBasicInformation.fuGetSize(),
            repr(opReturnLength),
          ),
          oNTStatus.fuGetValue()
        );
      # In practise I found that this function succeeds without providing any
      # data on a newly started, suspended thread. I am not sure why this is
      # but I have to work around it I guess.
      if ouReturnLength != 0:
        assert ouReturnLength == oThreadBasicInformation.fuGetSize(), \
            "NtQueryInformationThread(%s (%s), 0x%X, %s, 0x%X, %s) wrote 0x%X bytes" % (
              repr(ohThread), oSelf.fs0GetAccessRightsFlagsDescription(),
              ThreadBasicInformation,
              repr(opThreadBasicInformation),
              oThreadBasicInformation.fuGetSize(),
              repr(opReturnLength),
              ouReturnLength.fuGetvalue()
            );
        # Terminated threads have TEB address set to 0, indicating no TEB exists.
        uTEBAddress = oThreadBasicInformation.TebBaseAddress.fuGetValue();
        if uTEBAddress != 0:
          # Read TEB. The type of TEB (32- or 64-bit) depends on the type of THREAD_BASIC_INFORMATION (see above)
          cTEB = {"x86": TEB32, "x64": TEB64}[fsGetPythonISA()];
          oSelf.__o0TEB = oSelf.oProcess.fo0ReadStructureForAddress(cTEB, uTEBAddress);
          assert oSelf.__o0TEB, \
              "Cannot read TEB for process %d /0x%X at address 0x%X" % \
              (oSelf.oProcess.uId, oSelf.oProcess.uId, uTEBAddress);
          oSelf.__u0TEBAddress = uTEBAddress;
    return oSelf.__o0TEB;
  
  @property
  def u0StackBottomAddress(oSelf):
    o0TEB = oSelf.o0TEB;
    return o0TEB.NtTib.StackBase.fuGetValue() if o0TEB else None;
  
  @property
  def u0StackTopAddress(oSelf):
    o0TEB = oSelf.o0TEB;
    return o0TEB.NtTib.StackLimit.fuGetValue() if o0TEB else None;
  
  @property
  def o0StackVirtualAllocation(oSelf):
    if oSelf.__o0StackVirtualAllocation is None:
      u0StackBottomAddress = oSelf.u0StackBottomAddress;
      if u0StackBottomAddress is not None:
        oSelf.__o0StackVirtualAllocation = cVirtualAllocation(oSelf.oProcess.uId, u0StackBottomAddress);
    return oSelf.__o0StackVirtualAllocation;
  
  def __fo0GetThreadContext(oSelf):
    # The type of CONTEXT we want to get and the function we need to use to do so depend on the ISA of both the target
    # process and the calling process (the Python process we're running in). We assume Python and the target are both
    # 32-bit, but change these settings if this is not the case:
    cThreadContext = CONTEXT32;
    sGetThreadContextFunctionName = "GetThreadContext";
    uRequiredAccessRightFlags = THREAD_GET_CONTEXT;
    # ERROR_GEN_FAILURE is normal, ERROR_ACCESS_DENIED happens with Wow64
    # on certain OS versions. I haven't figured out which but assume both
    # mean the same thing.
    auErrorsWhenThreadIsTerminated = [ERROR_GEN_FAILURE, ERROR_ACCESS_DENIED];
    if fsGetPythonISA() == "x64":
      if oSelf.oProcess.sISA == "x64":
        cThreadContext = CONTEXT64;
      else:
        sGetThreadContextFunctionName = "Wow64GetThreadContext";
        uRequiredAccessRightFlags |= THREAD_QUERY_INFORMATION;
    oThreadContext = cThreadContext();
    oh0Thread = oSelf.foh0OpenWithFlags(uRequiredAccessRightFlags, bMustExist = False, bMustGetAccess = False);
    if not fbIsValidHandle(oh0Thread):
#      print "oThreadContext = None (oh0Thread = %s)" % (repr(oh0Thread),);
      return None;
    oThreadContext.ContextFlags = CONTEXT_ALL;
    fbGetThreadContext = getattr(oKernel32DLL, sGetThreadContextFunctionName);
    opoThreadContext = oThreadContext.foCreatePointer();
    if not fbGetThreadContext(
      oh0Thread, # hThread
      opoThreadContext, # lpContext
    ):
      if oSelf.bIsTerminated:
        for uErrorWhenThreadIsTerminated in auErrorsWhenThreadIsTerminated:
          if fbLastErrorIs(uErrorWhenThreadIsTerminated): # This happens when a thread is terminated.
#            print "oThreadContext = None (Thread terminated)";
            return None;
      fThrowLastError("%s(%s (%s), 0x%X)" % (
        sGetThreadContextFunctionName,
        repr(oh0Thread), oSelf.fs0GetAccessRightsFlagsDescription(),
        opoThreadContext.fuGetTargetAddress(),
      ));
#    print "oThreadContext = %s" % repr(oThreadContext);
    return oThreadContext;
  
  def __fxGetRegisterFromThreadContext(oSelf, oThreadContext, sThreadContextMemberName, uBitOffset, uBitSize):
    # Walk down the "sThreadContextMemberName" path to get the value from oThreadContext.
    xValue = oThreadContext;
    for sMemberName in re.split(r"[\.\[]", sThreadContextMemberName):
      if sMemberName[-1] == "]":
        xValue = xValue[int(sMemberName[:-1])];
      else:
        xValue = getattr(xValue, sMemberName);
    if isinstance(xValue, M128A):
      uValue = (xValue.High.fuGetValue() * (1 << 64)) ^ xValue.Low.fuGetValue();
      return (uValue >> uBitOffset) & ((1 << uBitSize) - 1);
    elif isinstance(xValue, iIntegerBaseType):
      uValue = xValue.fuGetValue();
      return (uValue >> uBitOffset) & ((1 << uBitSize) - 1);
    else:
      auMemberValueBytes = xValue;
      uValue = 0;
      for uByteIndex in range(uBitOffset >> 3, (uBitOffset + uBitSize) >> 3):
        iStartBitOffsetForMemberValueByte = uBitOffset - uByteIndex * 8;
        iEndBitOffsetForMemberValueByte = iStartBitOffsetForMemberValueByte + uBitSize;
        uValueComponent = auMemberValueBytes[uByteIndex];
        if iStartBitOffsetForMemberValueByte > 0:
          uValueComponent = uValueComponent >> iStartBitOffsetForMemberValueByte;
        else:
          uValueComponent = uValueComponent << -iStartBitOffsetForMemberValueByte;
        if iEndBitOffsetForMemberValueByte < 8:
          uValueComponent = uValueComponent & ((1 << iEndBitOffsetForMemberValueByte) - 1);
        uValue += uValueComponent;
      return uValue;
  
  def __fSetRegisterInThreadContext(oSelf, oThreadContext, sThreadContextMemberName, uBitOffset, uBitSize, uRegisterValue):
    # Walk down the "sThreadContextMemberName" path to find the parent of the value from oThreadContext.
    xValue = oThreadContext;
    xParent = None;
    for sMemberName in re.split(r"[\.\[]", sThreadContextMemberName):
      xParent = xValue;
      if sMemberName[-1] == "]":
        xValue = xValue[int(sMemberName[:-1])];
      else:
        xValue = getattr(xValue, sMemberName);
    if isinstance(xValue, M128A):
      uM128AValue = (xValue.High.fuGetValue() * (1 << 64)) ^ xValue.Low.fuGetValue();
      uCurrentValueInM128A = uValue & (((1 << uBitSize) - 1) << uBitOffset);
      uNewValueInM128A = uRegisterValue << uBitOffset;
      # Subtract the current value and add the new value:
      uM128AValue = uM128AValue - uCurrentValueInM128A + uNewValueInM128A;
      xValue.High = uM128AValue >> 64;
      xValue.Low = uM128AValue & ((1 << 64) - 1);
    elif isinstance(xValue, iIntegerBaseType):
      uValue = xValue.fuGetValue();
      uCurrentValue = uValue & (((1 << uBitSize) - 1) << uBitOffset);
      uNewValue = uRegisterValue << uBitOffset;
      uValue = uValue - uCurrentValue + uNewValue;
      if sMemberName[-1] == "]":
        xParent[int(sMemberName[:-1])] = uValue;
      else:
        setattr(xParent, sMemberName, uValue);
    else:
      raise NotImplementedError("Really not looking forward to this...");
  
  def fsbGetInstructionPointerRegisterName(oSelf):
    return gsbInstructionPointerRegisterName_by_sISA[oSelf.oProcess.sISA];
  def ftxGetInstructionPointerRegisterNameAndValue(oSelf):
    sbRegisterName = oSelf.fsbGetInstructionPointerRegisterName();
    return (sbRegisterName, oSelf.fu0GetRegister(sbRegisterName));
  def fu0GetInstructionPointerRegisterValue(oSelf):
    sbRegisterName = oSelf.fsbGetInstructionPointerRegisterName();
    return oSelf.fu0GetRegister(sbRegisterName);
  
  def fsbGetStackPointerRegisterName(oSelf):
    return gsbStackPointerRegisterName_by_sISA[oSelf.oProcess.sISA];
  def ftxGetStackPointerRegisterNameAndValue(oSelf):
    sbRegisterName = oSelf.fsbGetStackPointerRegisterName();
    return (sbRegisterName, oSelf.fu0GetRegister(sbRegisterName));
  def fu0GetStackPointerRegisterValue(oSelf):
    sbRegisterName = oSelf.fsbGetStackPointerRegisterName();
    return oSelf.fu0GetRegister(sbRegisterName);

  def fd0uGetRegisterValueByName(oSelf):
    o0ThreadContext = oSelf.__fo0GetThreadContext();
    if o0ThreadContext is None: return None;
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName = \
        gddtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName_by_sISA[oSelf.oProcess.sISA];
    duRegisterValues_by_sName = {};
    for (sbRegisterName, (sThreadContextMemberName, uBitSize, uBitOffset)) in \
        dtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName.items():
      uRegisterValue = oSelf.__fxGetRegisterFromThreadContext(o0ThreadContext, sThreadContextMemberName, uBitOffset, uBitSize);
      duRegisterValues_by_sName[sbRegisterName] = uRegisterValue;
    return duRegisterValues_by_sName;
  
  def fu0GetRegister(oSelf, sbRegisterName):
    o0ThreadContext = oSelf.__fo0GetThreadContext();
    if o0ThreadContext is None: return None;
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName = \
        gddtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName_by_sISA[oSelf.oProcess.sISA];
    assert sbRegisterName in dtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName, \
        "Register %s is not available in the context of %s process %d" % (sbRegisterName, oSelf.oProcess.sISA, oSelf.oProcess.uId);
    (sThreadContextMemberName, uBitSize, uBitOffset) = \
        dtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName[sbRegisterName];
    return oSelf.__fxGetRegisterFromThreadContext(o0ThreadContext, sThreadContextMemberName, uBitOffset, uBitSize);
  
  def fbSetRegister(oSelf, sbRegisterName, uRegisterValue):
    return oSelf.fbSetRegisters({sbRegisterName: uRegisterValue});
  
  def fbSetRegisters(oSelf, duRegisterValue_by_sbName):
    o0ThreadContext = oSelf.__fo0GetThreadContext();
    if o0ThreadContext is None:
#      print "fbSetRegisters(%s) => False (o0ThreadContext == None)" % (repr(duRegisterValue_by_sbName),);
      return False;
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName = \
        gddtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName_by_sISA[oSelf.oProcess.sISA];
    for (sbRegisterName, uRegisterValue) in duRegisterValue_by_sbName.items():
      assert sbRegisterName in dtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName, \
          "Register %s is not available in the context of %s process %d" % (sbRegisterName, oSelf.oProcess.sISA, oSelf.oProcess.uId);
      (sThreadContextMemberName, uBitSize, uBitOffset) = \
          dtxThreadContextMemberNameBitSizeAndOffset_by_sbRegisterName[sbRegisterName];
      assert uRegisterValue & ((1 << uBitSize) - 1) == uRegisterValue, \
          "value 0x%X cannot be stored in %d bit" % (uRegisterValue, uBitSize);
      oSelf.__fSetRegisterInThreadContext(o0ThreadContext, sThreadContextMemberName, uBitOffset, uBitSize, uRegisterValue);
    oh0Thread = oSelf.foh0OpenWithFlags(THREAD_SET_CONTEXT, bMustExist = False, bMustGetAccess = False);
    if not fbIsValidHandle(oh0Thread):
#      print "fbSetRegisters(%s) => False (oh0Thread = %s)" % (repr(duRegisterValue_by_sbName),repr(oh0Thread));
      return False;
    # The function we need to use to set the context depends on the ISA of both the target process and the calling
    # process (the Python process we're running in):
    if fsGetPythonISA() == "x64" and oSelf.oProcess.sISA == "x86":
      sSetThreadContextFunctionName = "Wow64SetThreadContext";
    else:
      sSetThreadContextFunctionName = "SetThreadContext";
    fbSetThreadContext = getattr(oKernel32DLL, sSetThreadContextFunctionName);
    if not fbSetThreadContext(
      oh0Thread,# hThread
      o0ThreadContext.foCreatePointer(), # lpContext
    ):
      fThrowLastError("%s(0x%08X (%s), ...)" % (
        sSetThreadContextFunctionName,
        oSelf.fs0GetAccessRightsFlagsDescription()
      ));
#    print "fbSetRegisters(%s) => True" % (repr(duRegisterValue_by_sbName),);
    return True;
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    bIsTerminated = oSelf.bIsTerminated;
    sDescription = oSelf.sDescription;
    u0TEBAddress = oSelf.__u0TEBAddress if oSelf.__o0TEB and not bIsTerminated else None;
    u0StackBottomAddress = oSelf.u0StackBottomAddress if not bIsTerminated else None;
    u0StackTopAddress = oSelf.u0StackTopAddress if u0StackBottomAddress is not None else None;
    sAccessRightsFlagsDescription = oSelf.fs0GetAccessRightsFlagsDescription() if not bIsTerminated else None;
    return [s for s in [
      "tid = 0x%X" % (oSelf.uId,),
      "pid = 0x%X" % (oSelf.oProcess.uId,),
      "description = %s" % (sDescription,) if sDescription else None,
      "terminated" if bIsTerminated else None,
      ("access = [%s]" % (sAccessRightsFlagsDescription,) if sAccessRightsFlagsDescription else None),
      "TEB @ 0x%X" % (u0TEBAddress,) if u0TEBAddress is not None else None,
      "stack @ 0x%X - 0x%X" % (u0StackBottomAddress, u0StackTopAddress) if u0StackBottomAddress else None,
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));

