import ctypes, threading, os;

class cDLLFunction(object):
  def __init__(oSelf, oDLL, xReturnType, sName, *axArgumenTypes, **dxOptions):
    oSelf.oDLL = oDLL;
    oSelf.xReturnType = xReturnType;
    oSelf.sName = sName;
    oSelf.axArgumenTypes = axArgumenTypes;
    oSelf.dxOptions = dxOptions;
    oSelf.__fFunctionWrapper = None;
    
  def __call__(oSelf, *axArguments):
    if oSelf.__fFunctionWrapper is None:
      # This code is used as a wrapper for functions in this DLL until they are first called. At that point, this code
      # makes sure the DLL gets loaded and replaces itself as the wrapper with a simpler wrapper that does not make
      # sure the DLL is loaded but simply calls the function. This simpler wrapper is also used to make the actual
      # first call to the function.
      # This complexity is needed so we can have cDLL instances without having to load the DLLs in the Python process.
      # We want this so we can offer functionality in many different DLLs without having to load them if the user does
      # not use them. This way, DLLs are loaded transparently the first time a function needs to be called in them, and
      # subsequent calls do not check if the DLL needs to be loaded any more, making those faster
      ffxFunctionConstructor = ctypes.WINFUNCTYPE(oSelf.xReturnType, *oSelf.axArgumenTypes);
      fxBasicFunctionWrapper = ffxFunctionConstructor(
        (oSelf.sName, oSelf.oDLL.oWinDLL),
        tuple([(1, "p%d" % u, 0) for u in xrange(len(oSelf.axArgumenTypes))])
      );
      if oSelf.dxOptions.get("bSingleThreaded"):
        # This function cannot be called concurrently from multiple threads: wrap it in a function that holds a lock
        # while a call is in progress. This allows only a single thread to call it at the same time.
        oSelf.oCallLock = threading.Lock();
        def fxSingleThreadedFunctionWrapper(*axArguments):
          oSelf.oCallLock.acquire();
          try:
            return fxBasicFunctionWrapper(*axArguments);
          finally:
            oSelf.oCallLock.release();
        oSelf.__fFunctionWrapper = fxSingleThreadedFunctionWrapper;
      else:
        oSelf.__fFunctionWrapper = fxBasicFunctionWrapper;
    try:
      xReturnValue = oSelf.__fFunctionWrapper(*axArguments);
    except ctypes.ArgumentError:
      for uIndex in xrange(len(axArguments)):
        xArgument = axArguments[uIndex];
        xExpectedArgumentType = oSelf.axArgumenTypes[uIndex];
        try:
          xExpectedArgumentType(xArgument);
        except TypeError as oTypeError:
          raise TypeError("Argument %d of call to %s cannot be converted from %s to %s: %s" % \
              (uIndex + 1, oSelf.sName, repr(xArgument), repr(xExpectedArgumentType), oTypeError.args[0]));
    if oSelf.xReturnType is not None:
      return oSelf.xReturnType(xReturnValue);
    assert xReturnValue is None, \
        "%s should return None but got %s" % repr(xReturnValue);
  
  def __str__(oSelf):
    return "<cDLLFunction(%s!%s)>" % (oSelf.oDLL.sName, oSelf.sName);
  
class cDLL(object):
  def __init__(oSelf, sDLLFilePath):
    oSelf.__sDLLFilePath = sDLLFilePath;
    oSelf.sName = os.path.basename(sDLLFilePath);
    oSelf.__oWinDLL = None;
  
  @property
  def oWinDLL(oSelf):
    if oSelf.__oWinDLL is None:
      oSelf.__oWinDLL = ctypes.WinDLL(oSelf.__sDLLFilePath);
    return oSelf.__oWinDLL;
  
  def fDefineFunction(oSelf, xReturnType, sName, *axArgumenTypes, **dxOptions):
    oDLLFunction = cDLLFunction(oSelf, xReturnType, sName, *axArgumenTypes, **dxOptions);
    setattr(oSelf, sName, oDLLFunction);
  
  def __str__(oSelf):
    return "<cDLL(%s)>" % oSelf.sName;
