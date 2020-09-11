import re;
from mWindowsSDK import *;
from .cVirtualAllocation import cVirtualAllocation;
from .fbIsRunningForThreadHandle import fbIsRunningForThreadHandle;
from .fbResumeForThreadHandle import fbResumeForThreadHandle;
from .fbTerminateForThreadHandle import fbTerminateForThreadHandle;
from .fbWaitForTerminationForThreadHandle import fbWaitForTerminationForThreadHandle;
from .fohOpenForThreadIdAndDesiredAccess import fohOpenForThreadIdAndDesiredAccess;
from .fsGetDescriptionForThreadHandle import fsGetDescriptionForThreadHandle;
from .fsGetPythonISA import fsGetPythonISA;
from .fSuspendForThreadHandle import fSuspendForThreadHandle;
from .fsGetThreadAccessRightsFlagsDescription import fsGetThreadAccessRightsFlagsDescription;
from .fThrowError import fThrowError;
from .fThrowLastError import fThrowLastError;
from .fuGetExitCodeForThreadHandle import fuGetExitCodeForThreadHandle;

gddtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName_by_sISA = {
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
    "*sp":  ("Esp", 32, 0),
    "*ip":  ("Eip", 32, 0),
    # 64 bit
    "mm0":  ("FloatSave.RegisterArea", 80, 0*80),
    "mm1":  ("FloatSave.RegisterArea", 80, 1*80),
    "mm2":  ("FloatSave.RegisterArea", 80, 2*80),
    "mm3":  ("FloatSave.RegisterArea", 80, 3*80),
    "mm4":  ("FloatSave.RegisterArea", 80, 4*80),
    "mm5":  ("FloatSave.RegisterArea", 80, 5*80),
    "mm6":  ("FloatSave.RegisterArea", 80, 6*80),
    "mm7":  ("FloatSave.RegisterArea", 80, 7*80),
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
    "xmm0": ("ExtendedRegisters", 128, 0*128 + 0x500),
    "xmm1": ("ExtendedRegisters", 128, 1*128 + 0x500),
    "xmm2": ("ExtendedRegisters", 128, 2*128 + 0x500),
    "xmm3": ("ExtendedRegisters", 128, 3*128 + 0x500),
    "xmm4": ("ExtendedRegisters", 128, 4*128 + 0x500),
    "xmm5": ("ExtendedRegisters", 128, 5*128 + 0x500),
    "xmm6": ("ExtendedRegisters", 128, 6*128 + 0x500),
    "xmm7": ("ExtendedRegisters", 128, 7*128 + 0x500),
    # Flags
    "cf":   ("Eflags", 1, 0),
    "pf":   ("Eflags", 1, 2),
    "af":   ("Eflags", 1, 4),
    "zf":   ("Eflags", 1, 6),
    "sf":   ("Eflags", 1, 7),
    "tf":   ("Eflags", 1, 8),
    "if":   ("Eflags", 1, 9),
    "df":   ("Eflags", 1, 10),
    "of":   ("Eflags", 1, 11),
    "iopl": ("Eflags", 2, 12),
    "nt":   ("Eflags", 1, 14),
    "rf":   ("Eflags", 1, 16),
    "vm":   ("Eflags", 1, 17),
    "ac":   ("Eflags", 1, 18),
    "vif":  ("Eflags", 1, 19),
    "vip":  ("Eflags", 1, 20),
    "id":   ("Eflags", 1, 21),
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
    "*sp":  ("Rsp", 64, 0),
    "*ip":  ("Rip", 64, 0),
    "r8":   ("R8",  64, 0),
    "r9":   ("R9",  64, 0),
    "r10":  ("R10", 64, 0),
    "r11":  ("R11", 64, 0),
    "r12":  ("R12", 64, 0),
    "r13":  ("R13", 64, 0),
    "r14":  ("R14", 64, 0),
    "r15":  ("R15", 64, 0),
    "mm0":  ("FltSave.FloatRegisters[0]", 64, 0),
    "mm1":  ("FltSave.FloatRegisters[1]", 64, 0),
    "mm2":  ("FltSave.FloatRegisters[2]", 64, 0),
    "mm3":  ("FltSave.FloatRegisters[3]", 64, 0),
    "mm4":  ("FltSave.FloatRegisters[4]", 64, 0),
    "mm5":  ("FltSave.FloatRegisters[5]", 64, 0),
    "mm6":  ("FltSave.FloatRegisters[6]", 64, 0),
    "mm7":  ("FltSave.FloatRegisters[7]", 64, 0),
    # 80 bit
# Python has no support for 80 bit floats, so implementing this is going to be quite a lot of work.
#    "st0":  ("FltSave.FloatRegisters[0]", 80, 0),
#    "st1":  ("FltSave.FloatRegisters[1]", 80, 0),
#    "st2":  ("FltSave.FloatRegisters[2]", 80, 0),
#    "st3":  ("FltSave.FloatRegisters[3]", 80, 0),
#    "st4":  ("FltSave.FloatRegisters[4]", 80, 0),
#    "st5":  ("FltSave.FloatRegisters[5]", 80, 0),
#    "st6":  ("FltSave.FloatRegisters[6]", 80, 0),
#    "st7":  ("FltSave.FloatRegisters[7]", 80, 0),
    # 128 bit
    "xmm0": ("Xmm0", 128, 0),
    "xmm1": ("Xmm1", 128, 0),
    "xmm2": ("Xmm2", 128, 0),
    "xmm3": ("Xmm3", 128, 0),
    "xmm4": ("Xmm4", 128, 0),
    "xmm5": ("Xmm5", 128, 0),
    "xmm6": ("Xmm6", 128, 0),
    "xmm7": ("Xmm7", 128, 0),
    "xmm8": ("Xmm8", 128, 0),
    "xmm9": ("Xmm9", 128, 0),
    "xmm10": ("Xmm10", 128, 0),
    "xmm11": ("Xmm11", 128, 0),
    "xmm12": ("Xmm12", 128, 0),
    "xmm13": ("Xmm13", 128, 0),
    "xmm14": ("Xmm14", 128, 0),
    "xmm15": ("Xmm15", 128, 0),
    # Flags
    "cf":   ("EFlags", 1, 0),
    "pf":   ("EFlags", 1, 2),
    "af":   ("EFlags", 1, 4),
    "zf":   ("EFlags", 1, 6),
    "sf":   ("EFlags", 1, 7),
    "tf":   ("EFlags", 1, 8),
    "if":   ("EFlags", 1, 9),
    "df":   ("EFlags", 1, 10),
    "of":   ("EFlags", 1, 11),
    "iopl": ("EFlags", 2, 12),
    "nt":   ("EFlags", 1, 14),
    "rf":   ("EFlags", 1, 16),
    "vm":   ("EFlags", 1, 17),
    "ac":   ("EFlags", 1, 18),
    "vif":  ("EFlags", 1, 19),
    "vip":  ("EFlags", 1, 20),
    "id":   ("EFlags", 1, 21),
  },
};

class cThread(object):
  def __init__(oSelf, oProcess, uId, ohThread = None, uThreadHandleFlags = None):
    oSelf.oProcess = oProcess;
    assert isinstance(uId, (int, long)), \
        "uId must be an integer not %s" % repr(uId);
    oSelf.uId = uId;
    if ohThread:
      assert isinstance(ohThread, HANDLE), \
          "ohThread (%s) is not a valid handle" % repr(ohThread);
      assert uThreadHandleFlags is not None, \
          "You must provide uThreadHandleFlags when you provide ohThread";
      oSelf.__ohThread = ohThread;
      oSelf.__uThreadHandleFlags = uThreadHandleFlags;
    else:
      oSelf.__ohThread = None;
      oSelf.__uThreadHandleFlags = 0;
    oSelf.__oTEB = None;
    oSelf.__oStackVirtualAllocation = None;
    oSelf.__oThreadContext = None;
  
  def fohOpenWithFlags(oSelf, uRequiredFlags):
    # See if we have an open handle
    if oSelf.__ohThread:
      # if it already has the required flags, return it:
      if oSelf.__uThreadHandleFlags & uRequiredFlags == uRequiredFlags:
        return oSelf.__ohThread;
      # If it does not have the required flags, close it:
      oKernel32 = foLoadKernel32DLL();
      if not oKernel32.CloseHandle(oSelf.__ohThread):
        fThrowLastError("CloseHandle(0x%X)" % (oSelf.__ohThread.value,));
      oSelf.__ohThread = None;
    # Open a new handle with the required flags and all other flags we've used before.
    # This allows the new handle to be used for anything it was used for before as well
    # as anything new the caller wants to do:
    uFlags = oSelf.__uThreadHandleFlags | uRequiredFlags;
    ohThread = fohOpenForThreadIdAndDesiredAccess(oSelf.uId, uFlags);
    oSelf.__ohThread = ohThread;
    oSelf.__uThreadHandleFlags = uFlags;
    return ohThread;
  
  def fs0GetAccessRightsFlagsDescription(oSelf):
    return fsGetThreadAccessRightsFlagsDescription(oSelf.__uThreadHandleFlags) \
        if oSelf.__ohThread is not None else None;
    

  def __del__(oSelf):
    try:
      ohThread = oSelf.__ohThread;
    except AttributeError:
      return;
    if ohThread:
      oKernel32 = foLoadKernel32DLL();
      if not oKernel32.CloseHandle(ohThread) and not fbLastErrorIs(ERROR_INVALID_HANDLE):
        fThrowLastError("CloseHandle(0x%X)" % (ohThread.value,));
  
  @property
  def bIsRunning(oSelf):
    return fbIsRunningForThreadHandle(oSelf.fohOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION));
  
  @property
  def bIsTerminated(oSelf):
    return not oSelf.bIsRunning;
  
  def fbTerminate(oSelf, uTimeout = None):
    return fbTerminateForThreadHandle(oSelf.fohOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION), uTimeout);
  
  def fSuspend(oSelf):
    return fSuspendForThreadHandle(oSelf.fohOpenWithFlags(THREAD_SUSPEND_RESUME));
  
  def fbResume(oSelf):
    return fbResumeForThreadHandle(oSelf.fohOpenWithFlags(THREAD_SUSPEND_RESUME));
  
  def fbWait(oSelf, uTimeout = None):
    return fbWaitForTerminationForThreadHandle(oSelf.fohOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION), uTimeout);
  
  @property
  def uExitCode(oSelf):
    return fuGetExitCodeForThreadHandle(oSelf.fohOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION));
  
  @property
  def sDescription(oSelf):
    return fsGetDescriptionForThreadHandle(oSelf.fohOpenWithFlags(THREAD_QUERY_LIMITED_INFORMATION));
  
  @property
  def oTEB(oSelf):
    if oSelf.__oTEB is None:
      # The type of THREAD_BASIC_INFORMATION returned by NtQueryInformationThread depends on the ISA of the calling
      # process (the Python process we're running in):
      cThreadBasicInformation = {"x86": THREAD_BASIC_INFORMATION32, "x64": THREAD_BASIC_INFORMATION64}[fsGetPythonISA()];
      oThreadBasicInformation = cThreadBasicInformation();
      ouReturnLength = ULONG();
      ohThread = oSelf.fohOpenWithFlags(THREAD_QUERY_INFORMATION);
      oNTDLL = foLoadNTDLL();
      oNTStatus = oNTDLL.NtQueryInformationThread(
        ohThread,# ThreadHandle
        ThreadBasicInformation, # ThreadInformationClass
        oThreadBasicInformation.foCreatePointer(PVOID), # ThreadInformation
        oThreadBasicInformation.fuGetSize(), # ThreadInformationLength
        ouReturnLength.foCreatePointer(), # ReturnLength
      );
      if NT_ERROR(oNTStatus):
        fThrowError("NtQueryInformationThread(0x%X, 0x%X, ..., 0x%X, ...)" % \
              (ohThread.value, ThreadBasicInformation, oThreadBasicInformation.fuGetSize()), oNTStatus.value);
      assert ouReturnLength.value == oThreadBasicInformation.fuGetSize(), \
          "NtQueryInformationThread(0x%X, 0x%08X, ..., 0x%X, ...) wrote 0x%X bytes" % \
          (ohThread, ThreadBasicInformation, oThreadBasicInformation.fuGetSize(), ouReturnLength.value);
      # Read TEB
      uTEBAddress = oThreadBasicInformation.TebBaseAddress.value;
      # The type of TEB (32- or 64-bit) depends on the type of THREAD_BASIC_INFORMATION (see above)
      cTEB = {"x86": TEB32, "x64": TEB64}[fsGetPythonISA()];
      oVirtualAllocation = oSelf.oProcess.foGetAllocatedVirtualAllocationWithSizeCheck(uTEBAddress, cTEB.fuGetSize(), "TEB");
      oSelf.__oTEB = oVirtualAllocation.foReadStructureForOffset(
        cStructure = cTEB,
        uOffset = uTEBAddress - oVirtualAllocation.uStartAddress,
      );
    return oSelf.__oTEB;
  
  @property
  def uStackBottomAddress(oSelf):
    return oSelf.oTEB.NtTib.StackBase.value;
  
  @property
  def uStackTopAddress(oSelf):
    return oSelf.oTEB.NtTib.StackLimit.value;
  
  @property
  def oStackVirtualAllocation(oSelf):
    if oSelf.__oStackVirtualAllocation is None:
      oSelf.__oStackVirtualAllocation = cVirtualAllocation(oSelf.oProcess.uId, oSelf.uStackBottomAddress);
    return oSelf.__oStackVirtualAllocation;
  
  def __foGetThreadContext(oSelf):
    # The type of CONTEXT we want to get and the function we need to use to do so depend on the ISA of both the target
    # process and the calling process (the Python process we're running in):
    if fsGetPythonISA() == "x86":
      cThreadContext = CONTEXT32;
      sGetThreadContextFunctionName = "GetThreadContext";
    elif oSelf.oProcess.sISA == "x86":
      cThreadContext = CONTEXT32;
      sGetThreadContextFunctionName = "Wow64GetThreadContext";
    else:
      cThreadContext = CONTEXT64;
      sGetThreadContextFunctionName = "GetThreadContext";
    oThreadContext = cThreadContext();
    ohThread = oSelf.fohOpenWithFlags(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION);
    oThreadContext.ContextFlags = CONTEXT_ALL;
    oKernel32 = foLoadKernel32DLL();
    fbGetThreadContext = getattr(oKernel32, sGetThreadContextFunctionName);
    if not fbGetThreadContext(
      ohThread, # hThread
      oThreadContext.foCreatePointer(), # lpContext
    ):
      fThrowLastError("%s(0x%X, 0x%X)" % (sGetThreadContextFunctionName, ohThread.value, oThreadContext.fuGetAddress()));
    return oThreadContext;
  
  def __fxGetRegisterFromThreadContext(oSelf, oThreadContext, sThreadContextMemberName, uBitOffset, uBitSize):
    # Walk down the "sThreadContextMemberName" path to get the value from oThreadContext.
    xValue = oThreadContext;
    for sMemberName in re.split("[\.\[]", sThreadContextMemberName):
      if sMemberName[-1] == "]":
        xValue = xValue[long(sMemberName[:-1])];
      else:
        xValue = getattr(xValue, sMemberName);
    if isinstance(xValue, M128A):
      uValue = (xValue.High.value * (1 << 64)) ^ xValue.Low.value;
      return (uValue >> uBitOffset) & ((1 << uBitSize) - 1);
    elif isinstance(xValue, cIntegerType):
      uValue = xValue.value;
      return (uValue >> uBitOffset) & ((1 << uBitSize) - 1);
    else:
      auMemberValueBytes = xValue;
      uValue = 0;
      for uByteIndex in xrange(uBitOffset >> 3, (uBitOffset + uBitSize) >> 3):
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
    for sMemberName in re.split("[\.\[]", sThreadContextMemberName):
      xParent = xValue;
      if sMemberName[-1] == "]":
        xValue = xValue[long(sMemberName[:-1])];
      else:
        xValue = getattr(xValue, sMemberName);
    if isinstance(xValue, M128A):
      uM128AValue = (xValue.High.value * (1 << 64)) ^ xValue.Low.value;
      uCurrentValueInM128A = uValue & (((1 << uBitSize) - 1) << uBitOffset);
      uNewValueInM128A = uRegisterValue << uBitOffset;
      # Subtract the current value and add the new value:
      uM128AValue = uM128AValue - uCurrentValueInM128A + uNewValueInM128A;
      xValue.High = uM128AValue >> 64;
      xValue.Low = uM128AValue & ((1 << 64) - 1);
    elif isinstance(xValue, cIntegerType):
      uValue = xValue.value;
      uCurrentValue = uValue & (((1 << uBitSize) - 1) << uBitOffset);
      uNewValue = uRegisterValue << uBitOffset;
      uValue = uValue - uCurrentValue + uNewValue;
      if sMemberName[-1] == "]":
        xParent[long(sMemberName[:-1])] = uValue;
      else:
        setattr(xParent, sMemberName, uValue);
    else:
      raise NotImplementedError("Really not looking forward to this...");
  
  def fduGetRegisterValueByName(oSelf):
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName = \
        gddtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName_by_sISA[oSelf.oProcess.sISA];
    duRegisterValues_by_sName = {};
    oThreadContext = oSelf.__foGetThreadContext();
    for (sRegisterName, (sThreadContextMemberName, uBitSize, uBitOffset)) in \
        dtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName.items():
      uRegisterValue = oSelf.__fxGetRegisterFromThreadContext(oThreadContext, sThreadContextMemberName, uBitOffset, uBitSize);
      duRegisterValues_by_sName[sRegisterName] = uRegisterValue;
    return duRegisterValues_by_sName;
  
  def fuGetRegister(oSelf, sRegisterName):
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName = \
        gddtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName_by_sISA[oSelf.oProcess.sISA];
    assert sRegisterName in dtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName, \
        "Register %s is not available in the context of %s process %d" % (sRegisterName, oSelf.oProcess.sISA, oSelf.oProcess.uId);
    (sThreadContextMemberName, uBitSize, uBitOffset) = \
        dtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName[sRegisterName];
    oThreadContext = oSelf.__foGetThreadContext();
    return oSelf.__fxGetRegisterFromThreadContext(oThreadContext, sThreadContextMemberName, uBitOffset, uBitSize);
  
  def fSetRegister(oSelf, sRegisterName, uRegisterValue):
    return oSelf.fSetRegisters({sRegisterName: uRegisterValue});
  
  def fSetRegisters(oSelf, duRegisterValue_by_sName):
    # Actual valid registers depend on the ISA of the target process:
    dtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName = \
        gddtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName_by_sISA[oSelf.oProcess.sISA];
    oThreadContext = oSelf.__foGetThreadContext();
    for (sRegisterName, uRegisterValue) in duRegisterValue_by_sName.items():
      assert sRegisterName in dtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName, \
          "Register %s is not available in the context of %s process %d" % (sRegisterName, oSelf.oProcess.sISA, oSelf.oProcess.uId);
      (sThreadContextMemberName, uBitSize, uBitOffset) = \
          dtxThreadContextMemberNameBitSizeAndOffset_by_sRegisterName[sRegisterName];
      assert uRegisterValue & ((1 << uBitSize) - 1) == uRegisterValue, \
          "value 0x%X cannot be stored in %d bit" % (uRegisterValue, uBitSize);
      oSelf.__fSetRegisterInThreadContext(oThreadContext, sThreadContextMemberName, uBitOffset, uBitSize, uRegisterValue);
    ohThread = oSelf.fohOpenWithFlags(THREAD_SET_CONTEXT);
    # The function we need to use to set the context depends on the ISA of both the target process and the calling
    # process (the Python process we're running in):
    if fsGetPythonISA() == "x64" and oSelf.oProcess.sISA == "x86":
      sSetThreadContextFunctionName = "Wow64SetThreadContext";
    else:
      sSetThreadContextFunctionName = "SetThreadContext";
    oKernel32 = foLoadKernel32DLL();
    fbSetThreadContext = getattr(oKernel32, sSetThreadContextFunctionName);
    if not fbSetThreadContext(
      ohThread,# hThread
      oThreadContext.foCreatePointer(), # lpContext
    ):
      fThrowLastError("%s(0x%08X, ...)" % (sSetThreadContextFunctionName, ohThread.value));

